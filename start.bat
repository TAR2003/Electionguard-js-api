@echo off
echo Starting ElectionGuard Frontend...
echo =================================

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Docker is not running. Please start Docker and try again.
    exit /b 1
)

REM Check if Docker Compose is available
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Docker Compose is not installed.
    exit /b 1
)

echo Building and starting the frontend container...
docker-compose up --build

echo.
echo Frontend should be available at: http://localhost:3000
echo Press Ctrl+C to stop the container.
