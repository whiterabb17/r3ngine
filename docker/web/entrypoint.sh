#!/bin/bash
# Install/update frontend dependencies only when package.json is updated or node_modules doesn't exist
echo "Checking frontend dependencies..."
cd /usr/src/app/frontend
if [ ! -d "node_modules" ] || [ package.json -nt node_modules ]; then
    echo "Installing/updating frontend dependencies (changes detected)..."
    npm install
else
    echo "Frontend dependencies are up to date."
fi

if [ "$DEBUG" = "1" ]; then
    echo "Development mode: Starting Vite dev server..."
    npm run dev -- --host 0.0.0.0 &
fi
# Ensure searchsploit RC file is copied to root home directory if available
if [ -f "/usr/src/exploitdb/.searchsploit_rc" ]; then
  cp /usr/src/exploitdb/.searchsploit_rc /root/.searchsploit_rc
fi

cd /usr/src/app

# Collect static files (includes built frontend assets)
echo "Collecting static files..."
python3 manage.py collectstatic --noinput --clear

# Create any pending migrations then apply them
echo "Making migrations..."
python3 manage.py makemigrations --noinput
echo "Running migrations..."
python3 manage.py migrate --noinput

# Sync roles and permissions
echo "Syncing roles..."
python3 manage.py sync_roles

# Check if fixtures are already loaded
#echo "Checking if default fixtures are already loaded..."
#if ! python3 manage.py shell -c "from scanEngine.models import EngineType; import sys; sys.exit(0 if EngineType.objects.exists() else 1)"; then
# Commented out the above check as sometimes 
# engine are updated. This needs to be optimized
# Load all scan_engine fixtures in a single command
# Load all hardware_profile fixtures in a single command

    echo "Loading default fixtures..."
    python3 manage.py loaddata \
        fixtures/external_tools.yaml \
        fixtures/default_keywords.yaml \
        fixtures/scan_engines/*.yaml \
        fixtures/hardware_profiles/*.yaml
# else
#     echo "Default fixtures already exist. Skipping..."
# fi

# Start the server
echo "Starting reNgine server..."
if [ "$DEBUG" = "1" ]; then
    echo "  Mode: development (Django runserver via Channels)"
    python3 manage.py runserver 0.0.0.0:8000
else
    echo "  Mode: production (Gunicorn + UvicornWorker ASGI)"
    exec gunicorn reNgine.routing:application \
        -c /usr/src/app/gunicorn.conf.py
fi
