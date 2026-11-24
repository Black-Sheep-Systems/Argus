@echo off
rem Starts Argus without a console window. The Electron project is the app folder.
set "ARGUS_APP=D:\Github\Argus\app"
set "ELECTRON=%ARGUS_APP%\node_modules\electron\dist\electron.exe"
if not exist "%ELECTRON%" (
  echo Electron was not found at "%ELECTRON%".
  echo Run "npm install" in %ARGUS_APP% once, then try again.
  pause
  exit /b 1
)
start "" "%ELECTRON%" "%ARGUS_APP%"
