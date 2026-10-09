@echo off

:: Credits: https://github.com/ninjhacks

:: Compose v5 defaults to `docker buildx bake`. On Docker Desktop for Windows
:: that talks to BuildKit over a TLS gRPC session and commonly fails with:
::   failed to compute cache key: failed to copy: local error: tls: bad record MAC
set COMPOSE_BAKE=false

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
:: Clone r3ngine-mcp (if needed) and run its Node setup script.
if "%1" == "install-mcp" node scripts\install-mcp.mjs %2 %3 %4 %5 %6 %7 %8 %9
:: Pull latest r3ngine-mcp and re-run setup (--update).
if "%1" == "update-mcp" node scripts\install-mcp.mjs --update %2 %3 %4 %5 %6 %7 %8 %9
:: Build and start all services in production mode.
if "%1" == "up" set DEBUG=0 && %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% up -d --build %SERVICES%
:: Build and start all services in development mode.
if "%1" == "devup" set DEBUG=1 && %DOCKER_COMPOSE% %COMPOSE_DEV_FILES% up -d --build %SERVICES%
:: Optional services (compose profiles). This script does not read COMPOSE_PROFILES
:: from .env, so start them by name.
:: Build and start the optional Tor service.
if "%1" == "up-tor" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% up -d --build tor
:: Stop the optional Tor service.
if "%1" == "stop-tor" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% stop tor
:: Build and start the optional Ollama service.
if "%1" == "up-ollama" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% up -d --build ollama
:: Stop the optional Ollama service.
if "%1" == "stop-ollama" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% stop ollama
:: Build and start the remote worker.
if "%1" == "up-worker" set DEBUG=0 && %DOCKER_COMPOSE% --env-file .env -f docker/docker-compose.worker.yml up -d --build
:: Stop the remote worker.
if "%1" == "down-worker" %DOCKER_COMPOSE% --env-file .env -f docker/docker-compose.worker.yml down
:: Build all services.
if "%1" == "build" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% build %SERVICES%
:: Build only the web/orchestrator/executor shared image.
if "%1" == "build-web" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% build web
:: Rebuild ALL services from scratch (no cache).
if "%1" == "build-clean" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% build --no-cache %SERVICES%
:: Build all services no cache. (alias of build-clean)
if "%1" == "rebuild" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% build --no-cache %SERVICES%
:: Restart only web, temporal-python-orchestrator, and temporal-go-executor.
if "%1" == "restart-apps" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% restart web temporal-python-orchestrator temporal-go-executor
:: Generate Username (Use only after make up).
if "%1" == "username" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py createsuperuser
:: Change Password
if "%1" == "changepassword" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py changepassword
if "%1" == "changepass" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py changepassword
:: Apply migrations
if "%1" == "makemigrations" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py makemigrations
:: Apply migrations
if "%1" == "migrate" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% exec web python3 manage.py migrate
:: Pull Docker images.
if "%1" == "pull" %DOCKER_COMPOSE% %COMPOSE_ALL_FILES% pull --ignore-buildable
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

:: Full backup: PostgreSQL dump + compressed scan_results -> ./backups/full_<timestamp>/
if "%1" == "backup" (
    call :load_postgres_env
    set "DOCKER_COMPOSE_CMD=%DOCKER_COMPOSE% %COMPOSE_ALL_FILES%"
    set "SCAN_RESULTS_VOLUME=r3ngine_scan_results"
    bash scripts/full_backup.sh
    goto :eof
)

:: Restore a full backup. Usage: make.bat restore BACKUP=./backups/full_YYYYMMDD_HHMMSS
if "%1" == "restore" (
    setlocal enabledelayedexpansion
    set "BACKUP_ARG=%~2"
    if "!BACKUP_ARG!"=="" (
        echo BACKUP is required. Example: make.bat restore BACKUP=./backups/full_20260327_120000
        exit /b 1
    )
    :: Accept BACKUP=path or a bare path
    echo !BACKUP_ARG! | findstr /b /c:"BACKUP=" >nul
    if not errorlevel 1 (
        set "BACKUP=!BACKUP_ARG:~7!"
    ) else (
        set "BACKUP=!BACKUP_ARG!"
    )
    call :load_postgres_env
    if errorlevel 1 exit /b 1
    set "DOCKER_COMPOSE_CMD=%DOCKER_COMPOSE% %COMPOSE_ALL_FILES%"
    set "SCAN_RESULTS_VOLUME=r3ngine_scan_results"
    bash scripts/full_restore.sh
    set "RESTORE_EXIT=!errorlevel!"
    endlocal & exit /b %RESTORE_EXIT%
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

:: Show this help (also default when no target is given).
if "%1" == "" goto :help
if "%1" == "help" goto :help

goto :eof

:: ---------------------------------------------------------------------------
:: Helpers
:: ---------------------------------------------------------------------------

:load_postgres_env
:: Load POSTGRES_USER / POSTGRES_DB from .env for backup/restore scripts.
if not exist ".env" (
    echo ERROR: .env not found. Copy .env.example to .env first.
    exit /b 1
)
for /f "usebackq eol=# tokens=1,* delims==" %%a in (".env") do (
    if /i "%%a"=="POSTGRES_USER" set "POSTGRES_USER=%%b"
    if /i "%%a"=="POSTGRES_DB" set "POSTGRES_DB=%%b"
)
if not defined POSTGRES_USER (
    echo ERROR: POSTGRES_USER not set in .env
    exit /b 1
)
if not defined POSTGRES_DB (
    echo ERROR: POSTGRES_DB not set in .env
    exit /b 1
)
exit /b 0

:help
echo Make application Docker images and manage containers using Docker Compose files.
echo.
echo Usage:
echo   make.bat ^<target^> (default: help)
echo.
echo Targets:
echo   certs            Generate certificates.
echo   setup            Generate certificates.
echo   install-mcp      Clone r3ngine-mcp (if needed) and run its Node setup script.
echo   update-mcp       Pull latest r3ngine-mcp and re-run setup (--update).
echo   up               Build and start all services in production mode.
echo   up-worker        Build and start the remote worker.
echo   down-worker      Stop the remote worker.
echo   devup            Build and start all services in development mode.
echo   build            Build all services.
echo   build-web        Build only the web/orchestrator/executor shared image.
echo   build-clean      Rebuild ALL services from scratch (no cache).
echo   restart-apps     Restart only web, temporal-python-orchestrator, and temporal-go-executor.
echo   username         Generate Username (Use only after make up).
echo   changepassword   Change password for user
echo   migrate          Apply migrations
echo   pull             Pull Docker images.
echo   down             Down all services.
echo   stop             Stop all services.
echo   restart          Restart all services.
echo   rm               Remove all services containers.
echo   loadtools        Load external tools.
echo   loadengines      Load default engines.
echo   logs             Tail all logs with -n 1000.
echo   images           Show all Docker images.
echo   prune            Remove containers and delete volume data.
echo   erase            !! DESTRUCTIVE !! Delete ALL containers, images, volumes, build cache, and local artifacts for a clean slate.
echo   fullupgrade      Upgrade to Django 5.2 + PostgreSQL 16 + Gunicorn (includes automatic PG image upgrade).
echo   backup           Full backup: PostgreSQL dump + compressed scan_results -^> ./backups/full_^<timestamp^>/
echo   restore          Restore a full backup. Usage: make.bat restore BACKUP=./backups/full_YYYYMMDD_HHMMSS
echo   help             Show this help.
exit /b 0
