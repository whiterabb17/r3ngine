#!/bin/bash
ensure_postgres_sslmode() {
    local env_file="${1:-.env}"

    if [[ ! -f "$env_file" ]]; then
        echo "ERROR: File not found: $env_file"
        return 1
    fi

    if grep -q '^POSTGRES_SSLMODE=prefer$' "$env_file"; then
        echo "POSTGRES_SSLMODE=prefer already present."
    else
        echo "" >> "$env_file"
        echo "POSTGRES_SSLMODE=prefer" >> "$env_file"
        echo "Added POSTGRES_SSLMODE=prefer to $env_file"
    fi
}
fix_volumes_permissions() {
  local user_id=$1
  local group_id=$1
  
  log "Fixing permissions for Docker volumes..." $COLOR_CYAN
  
  declare -a volumes=(
    "rengine_gf_patterns"
    "rengine_nuclei_templates"
    "rengine_scan_results"
    "rengine_wordlist"
  )

  for volume in "${volumes[@]}"; do
    if docker volume inspect "$volume" >/dev/null 2>&1; then
      log "Setting permissions for volume: $volume" $COLOR_YELLOW
      if ! docker run --rm -v "$volume:/data" alpine sh -c "chown -R $user_id:$group_id /data"; then
        log "Failed to set permissions for volume: $volume" $COLOR_RED
        return 1
      fi
    else
      log "Volume $volume not found, skipping..." $COLOR_YELLOW
    fi
  done
  
  log "Volume permissions updated successfully" $COLOR_GREEN
  return 0
}
# Define color codes.
COLOR_BLACK=0
COLOR_RED=1 # For errors and important messages
COLOR_GREEN=2 # For succesful output/messages
COLOR_YELLOW=3 # For questions and choices
COLOR_BLUE=4
COLOR_MAGENTA=5
COLOR_CYAN=6 # For actions that are being executed
COLOR_WHITE=7 # Default, we don't really use this explicitly
COLOR_DEFAULT=$COLOR_WHITE # Use white as default for clarity

# Log messages in different colors
log() {
  local color=${2:-$COLOR_DEFAULT}  # Use default color if $2 is not set
  if [ "$color" -ne $COLOR_DEFAULT ]; then
    tput setaf "$color"
  fi
  printf "$1\r\n"
  tput sgr0  # Reset text color
}
fix_project_ownership() {
  local user_id=$1
  local group_id=$1
  
  log "Setting correct ownership of the project directory..." $COLOR_CYAN
  project_dir=$(pwd)
  
  # Set ownership for both hidden and regular files in one command
  if ! find "$project_dir" \( -name ".*" -o -true \) -exec chown ${user_id}:${group_id} {} +; then
      log "Failed to set ownership of project directory to $user_id" $COLOR_RED
      return 1
  fi
  
  log "Project directory ownership set to $user_id" $COLOR_GREEN
  return 0
}

ensure_script_perms() {
  echo "Setting correct execution permissions on entrypoints"
  chmod +x docker/web/entrypoint.sh
  chmod +x docker/temporal-go-executor/entrypoint.sh
  chmod +x docker/temporal-python-orchestrator/entrypoint.sh
}

usageFunction()
{
  echo " "
  tput setaf 2;
  echo "Usage: $0 (-n) (-h)"
  echo -e "\t-n Non-interactive installation (Optional)"
  echo -e "\t-h Show usage"
  exit 1
}

tput setaf 2;
cat web/art/reNgine.txt
ensure_postgres_sslmode
tput setaf 1; echo "Before running this script, please make sure Docker is running and you have made changes to .env file."
tput setaf 2; echo "Changing the postgres username & password from .env is highly recommended."

tput setaf 4;

isNonInteractive=false
while getopts nh opt; do
   case $opt in
      n) isNonInteractive=true ;;
      h) usageFunction ;;
      ?) usageFunction ;;
   esac
done

if [ $isNonInteractive = false ]; then
    read -p "Are you sure, you made changes to .env file (y/n)? " answer
    case ${answer:0:1} in
        y|Y|yes|YES|Yes )
          echo "Continiuing Installation!"
        ;;
        * )
          nano .env
        ;;
    esac
else
  echo "Non-interactive installation parameter set. Installation begins."
fi

echo " "
tput setaf 3;
echo "#########################################################################"
echo "Please note that, this installation script is only intended for Linux"
echo "For Mac and Windows, refer to the official guide https://rengine.wiki"
echo "#########################################################################"

fix_project_ownership

echo " "
tput setaf 4;
echo "Installing reNgine and its dependencies"

echo " "
if [ "$EUID" -ne 0 ]
  then
  tput setaf 1; echo "Error installing reNgine, Please run this script as root!"
  tput setaf 1; echo "Example: sudo ./install.sh"
  exit
fi

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing curl..."
echo "#########################################################################"
if [ -x "$(command -v curl)" ]; then
  tput setaf 2; echo "CURL already installed, skipping."
else
  sudo apt update && sudo apt install curl -y
  tput setaf 2; echo "CURL installed!!!"
fi

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing Docker..."
echo "#########################################################################"
if [ -x "$(command -v docker)" ]; then
  tput setaf 2; echo "Docker already installed, skipping."
else
  curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
  tput setaf 2; echo "Docker installed!!!"
fi

ensure_script_perms

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing Docker Compose"
echo "#########################################################################"
if [ -x "$(command -v docker compose)" ]; then
  tput setaf 2; echo "Docker Compose already installed, skipping."
else
  curl -L "https://github.com/docker/compose/releases/download/v2.5.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
  tput setaf 2; echo "Docker Compose installed!!!"
fi


echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing make"
echo "#########################################################################"
if [ -x "$(command -v make)" ]; then
  tput setaf 2; echo "make already installed, skipping."
else
  apt install make
fi

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Checking Docker status"
echo "#########################################################################"
if docker info >/dev/null 2>&1; then
  tput setaf 4;
  echo "Docker is running."
else
  tput setaf 1;
  echo "Docker is not running. Please run docker and try again."
  echo "You can run docker service using sudo systemctl start docker"
  exit 1
fi



echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing reNgine"
echo "#########################################################################"
# The image build unpacks nuclei templates, browsers and dozens of tools, and
# BuildKit keeps intermediate layers while it runs; a nearly full disk fails
# half an hour in with "no space left on device".
MIN_FREE_GB=${MIN_FREE_GB:-60}
docker_root=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null) || docker_root=""
[ -d "$docker_root" ] || docker_root=/var/lib/docker
[ -d "$docker_root" ] || docker_root=/
free_gb=$(df -BG --output=avail "$docker_root" 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -n "$free_gb" ] && [ "$free_gb" -lt "$MIN_FREE_GB" ] && [ -z "$SKIP_DISK_CHECK" ]; then
  tput setaf 1
  echo "Only ${free_gb} GB free under ${docker_root}; the build needs about ${MIN_FREE_GB} GB."
  echo "Free or add space (on Ubuntu LVM: sudo lvextend -l +100%FREE -r /dev/ubuntu-vg/ubuntu-lv),"
  echo "or set SKIP_DISK_CHECK=1 to try anyway."
  exit 1
fi

failed=0
make certs && make build && make up || failed=1
if [ "${failed}" -eq 0 ]; then
  fix_volumes_permissions $SUDO_UID $SUDO_GID
  tput setaf 2 && echo "reNgine is installed!!!"
fi

if [ "${failed}" -eq 0 ]; then
  sleep 3

  echo " "
  tput setaf 4;
  echo "#########################################################################"
  echo "Creating an account"
  echo "#########################################################################"
  make migrate
  make username isNonInteractive=$isNonInteractive


  tput setaf 2 && printf "\n%s\n" "Thank you for installing reNgine, happy recon!!"
  echo "In case you have unapplied migrations (see above in red), run 'make migrate'"
else
  tput setaf 1 && printf "\n%s\n" "reNgine installation failed!!"
fi
