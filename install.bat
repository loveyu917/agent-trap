@echo off
REM Agent Trap Lab - one-command install for Windows (cmd.exe)
REM
REM   install.bat                 : Claude only
REM   set DEEPSEEK_API_KEY=sk-xxx  &  install.bat   : also test DeepSeek
REM   install.bat --rebuild       : force rebuild image after code changes
REM
REM (Mac/Linux, or Git Bash/WSL on Windows, use ./install.sh instead.)

setlocal enabledelayedexpansion
set IMAGE=trap-lab:v22
set AUTH_VOLUME=trap-claude-auth
set SCRIPT_DIR=%~dp0
set RESULTS_DIR=%SCRIPT_DIR%results

REM 1. check docker
where docker >nul 2>&1
if errorlevel 1 (
  echo [x] Docker not found. Install Docker Desktop first: https://www.docker.com/products/docker-desktop/
  exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
  echo [x] Docker is not running. Start Docker Desktop, then retry.
  exit /b 1
)

REM 2. build image if missing, or when --rebuild given
set DO_BUILD=0
docker image inspect %IMAGE% >nul 2>&1
if errorlevel 1 set DO_BUILD=1
if "%~1"=="--rebuild" set DO_BUILD=1
if "%DO_BUILD%"=="1" (
  echo ==^> Building image %IMAGE% ^(first time takes a few minutes^) ...
  docker build -t %IMAGE% "%SCRIPT_DIR%."
  if errorlevel 1 (
    echo [x] docker build failed.
    exit /b 1
  )
) else (
  echo ==^> Image %IMAGE% already exists ^(use install.bat --rebuild to rebuild^).
)

REM 3. persistent volume for Claude login (created once; survives container removal)
docker volume inspect %AUTH_VOLUME% >nul 2>&1
if errorlevel 1 docker volume create %AUTH_VOLUME% >nul

REM 4. results folder on host
if not exist "%RESULTS_DIR%" mkdir "%RESULTS_DIR%"

REM 5. optional DeepSeek key
set KEY_ARG=
if not "%DEEPSEEK_API_KEY%"=="" set KEY_ARG=-e DEEPSEEK_API_KEY=%DEEPSEEK_API_KEY%

REM 6. enter container (--rm: removed on exit; login + results are kept via volume/mount)
echo ==^> Entering container. Exit removes the container; login and results are kept.
echo.
docker run -it --rm %KEY_ARG% -v "%RESULTS_DIR%:/lab/results" -v "%AUTH_VOLUME%:/root/.claude" %IMAGE%

endlocal
