#!/bin/bash
# Sync GF patterns from bind-mount or staged image into volume
echo "Syncing GF patterns..."
mkdir -p /root/.gf
if [ -d "/usr/src/app/gf-patterns" ]; then
  cp -f /usr/src/app/gf-patterns/*.json /root/.gf/
elif [ -d "/usr/src/gf-patterns" ]; then
  cp -f /usr/src/gf-patterns/*.json /root/.gf/
else
  echo "Warning: no GF patterns directory found!"
fi
echo "GF patterns synced: $(ls /root/.gf/*.json | wc -l) patterns installed"

# Install/update frontend dependencies only when package.json is updated or node_modules doesn't exist
echo "Checking frontend dependencies..."
cd /usr/src/app/frontend
if [ ! -d "node_modules" ] || [ package.json -nt node_modules ]; then
    echo "Installing/updating frontend dependencies (changes detected)..."
    # `npm install` rewrites package-lock.json, and because ../frontend is a
    # bind-mount that dirtied the tracked lockfile in the deploy checkout on
    # every boot, which then blocked git checkout. `npm ci` never writes the
    # lockfile and installs exactly what is committed.
    if [ -f "package-lock.json" ]; then
        npm ci || npm install --no-save
    else
        npm install --no-save
    fi
else
    echo "Frontend dependencies are up to date."
fi

if [ "$DEBUG" = "1" ]; then
    echo "Development mode: Starting Vite dev server..."
    npm run dev -- --host 0.0.0.0 &
fi

cd /usr/src/app

# Collect static files (includes built frontend assets).
# No --clear: it empties the static volume nginx is serving, so every restart
# returned 404 for JS/CSS until collectstatic finished. Storage is plain
# StaticFilesStorage (no hashed manifest), so overwriting in place is correct.
echo "Collecting static files..."
python3 manage.py collectstatic --noinput

# Only autogenerate migrations in development. In production this wrote
# migration files that exist in the container but not in git, so the next
# deploy started from a different migration history than the repository.
if [ "$DEBUG" = "1" ]; then
    echo "Making migrations..."
    python3 manage.py makemigrations --noinput
fi
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
