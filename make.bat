@echo off

:: Credits: https://github.com/ninjhacks

set COMPOSE_ALL_FILES=--env-file .env -f docker/docker-compose.yml
set COMPOSE_DEV_FILES=--env-file .env -f docker/docker-compose.dev.yml
set SERVICES=db web proxy redis neo4j temporal temporal-python-orchestrator temporal-go-executor

:: Check if 'docker compose' command is available
docker compose version >nul 2>&1
if %errorlevel% == 0 (
    set DOCKER_COMPOSE=docker compose
) else (
    set DOCKER_COMPOSE=docker-compose
)


:: Generate certificates.
if "%1" == "certs" %DOCKER_COMPOSE% --env-file .env -f docker/docker-compose.setup.yml run --rm certs
:: Generate certificates.
if "%1" == "setup" %DOCKER_COMPOSE% --env-file .env -f docker/docker-compose.setup.yml run --rm certs
:: Build and start all services in production mode.
if "%1" == "up" set DEBUG=0 && %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% up -d --build %SERVICES%
:: Build and start all services in development mode.
if "%1" == "devup" set DEBUG=1 && %DOCKER_COMPOSE% %COMPOSE_DEV_FILES% up -d --build %SERVICES%
:: Build and start the remote worker.
if "%1" == "up-worker" set DEBUG=0 && %DOCKER_COMPOSE% --env-file .env -f docker/docker-compose.worker.yml up -d --build
:: Stop the remote worker.
if "%1" == "down-worker" %DOCKER_COMPOSE% --env-file .env -f docker/docker-compose.worker.yml down
:: Build all services.
if "%1" == "build" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% build %SERVICES%
:: Build all services no cache.
if "%1" == "rebuild" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% build --no-cache %SERVICES%
:: Generate Username (Use only after make up).
if "%1" == "username" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py createsuperuser
:: Change Password
if "%1" == "changepass" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py changepassword
:: Apply migrations
if "%1" == "makemigrations" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py makemigrations
:: Apply migrations
if "%1" == "migrate" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py migrate
:: Pull Docker images.
if "%1" == "pull" %DOCKER_COMPOSE% docker.pkg.github.com & docker-compose %COMPOSE_ALL_FILES% pull
:: Down all services.
if "%1" == "down" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% down
:: Stop all services.
if "%1" == "stop" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% stop %SERVICES%
:: Restart all services.
if "%1" == "restart" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% restart %SERVICES%
:: Remove all services containers.
if "%1" == "rm" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% rm -f %SERVICES%
:: Load external tools.
if "%1" == "loadtools" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py loaddata external_tools.yaml
:: Load default engines.
if "%1" == "loadengines" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py loaddata default_scan_engines.yaml
:: Tail all logs with -n 1000.
if "%1" == "logs" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% logs --follow --tail=1000 %SERVICES%
:: Show all Docker images.
if "%1" == "images" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% images %SERVICES%
:: Remove containers and delete volume data.
if "%1" == "prune" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% stop %SERVICES% & docker-compose %COMPOSE_ALL_FILES% rm -f %SERVICES% & docker volume prune -f

:: !! DESTRUCTIVE !! Delete ALL containers, images, volumes, build cache, and local artifacts for a clean slate.
if "%1" == "erase" (
    setlocal enabledelayedexpansion
    echo.
    echo ============================================================
    echo   r3ngine ERASE -- COMPLETE RESET
    echo ============================================================
    echo.
    echo   WARNING: This will PERMANENTLY and IRREVERSIBLY delete:
    echo.
    echo   - All r3ngine Docker containers ^(running or stopped^)
    echo   - All r3ngine Docker images
    echo   - ALL Docker volumes ^(scan data, PostgreSQL, Neo4j, wordlists^)
    echo   - Docker build layer cache
    echo   - Local Python artifacts ^(__pycache__, *.pyc, staticfiles/^)
    echo   - Local frontend artifacts ^(dist/, node_modules/^)
    echo.
    echo   ALL SCAN DATA AND DATABASE CONTENT WILL BE LOST.
    echo   There is no undo. Back up first if needed.
    echo.
    echo ============================================================
    echo.
    set /p confirm="  Type 'erase' to confirm full reset: "
    if /i not "!confirm!" == "erase" (
        echo.
        echo   Erase cancelled.
        echo.
        goto :eof
    )
    echo.
    echo [1/5] Stopping services and removing all containers, volumes, and images...
    %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% down --volumes --rmi all --remove-orphans
    echo.
    echo [2/5] Pruning Docker build cache...
    docker builder prune -af
    echo.
    echo [3/5] Removing any remaining dangling Docker volumes...
    docker volume prune -f
    echo.
    echo [4/5] Removing local Python build artifacts...
    for /d /r "web" %%d in (__pycache__) do (
        if exist "%%d" rd /s /q "%%d"
    )
    for /r "web" %%f in (*.pyc *.pyo) do del /f /q "%%f" 2>nul
    if exist "web\staticfiles" rd /s /q "web\staticfiles"
    echo.
    echo [5/5] Removing local frontend build artifacts...
    if exist "frontend\dist" rd /s /q "frontend\dist"
    if exist "frontend\node_modules" rd /s /q "frontend\node_modules"
    echo.
    echo ============================================================
    echo   Erase complete. All data has been wiped.
    echo   Run 'make up' to start fresh.
    echo ============================================================
    echo.
)

:: REQUIRED for v3.2.0+: migrate from Celery to Temporal.
if "%1" == "fullupgrade" (
    echo.
    echo ============================================================
    echo   r3ngine FULL UPGRADE -- v3.2.0 (Celery to Temporal^)
    echo ============================================================
    echo.
    echo   This upgrade makes IRREVERSIBLE changes to your deployment:
    echo.
    echo   1. All Celery and Celery Beat containers will be removed.
    echo   2. Temporal workflow engine containers will be started.
    echo   3. Database migrations will apply new Temporal models
    echo      and remove legacy django_celery_beat tables.
    echo   4. All images will be rebuilt from scratch.
    echo   5. Any in-progress scans WILL be interrupted.
    echo.
    echo   YOUR DATA IS SAFE:
    echo   - All Docker VOLUMES are preserved ^(scan_results, postgres_data,
    echo     nuclei_templates, wordlist, etc.^).
    echo   - Only CONTAINERS and IMAGES are rebuilt -- no volume data is
    echo     deleted or modified by this script.
    echo.
    echo   BEFORE PROCEEDING:
    echo   - Ensure you have pulled the latest code  ^(git pull^)
    echo   - Ensure no critical scans are running
    echo   - Back up your database if required
    echo.
    echo   For full upgrade instructions see README.md or CHANGELOG.md
    echo ============================================================
    echo.
    choice /C YN /M "  Confirm upgrade? Press Y to proceed or N to cancel"
    if errorlevel 2 (
        echo.
        echo   Upgrade cancelled.
        echo.
        goto :eof
    )
    echo.
    echo [1/6] Stopping all running services ^(volumes are NOT removed^)...
    %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% down --remove-orphans
    echo.
    echo [2/6] Pulling latest images and rebuilding containers (no cache^)...
    %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% build --no-cache %SERVICES%
    echo.
    echo [3/6] Starting database service...
    %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% up -d db redis
    echo Waiting for database to be ready...
    timeout /t 8 /nobreak > nul
    echo.
    echo [4/6] Applying database migrations...
    %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% run --rm web python3 manage.py migrate --noinput
    echo.
    echo [5/6] Starting all services...
    set DEBUG=0
    %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% up -d %SERVICES%
    echo.
    echo [6/6] Verifying services are healthy...
    timeout /t 5 /nobreak > nul
    %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% ps
    echo.
    echo ============================================================
    echo   Full upgrade complete.
    echo   Temporal UI: http://localhost:8080
    echo   r3ngine UI:  https://localhost
    echo ============================================================
    echo.
)

:: Show this help.
if "%1" == "help" echo Make application Docker images and manage containers using Docker Compose files only for windows.
