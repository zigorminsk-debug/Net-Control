@echo off
rem ===================================================================
rem  Сборка Net-Control в setup.exe (Windows)
rem  Результат: dist\Net-Control.exe
rem ===================================================================
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    set PY=py -3
) else (
    set PY=python
)

%PY% --version
if errorlevel 1 (
    echo [!] Не найден Python. Установите Python 3.9+ с sites-packages.
    pause
    exit /b 1
)

echo [*] Установка PyInstaller...
%PY% -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo [!] Не удалось установить PyInstaller.
    pause
    exit /b 1
)

echo [*] Сборка setup.exe...
%PY% build_setup.py
if errorlevel 1 (
    echo [!] Сборка завершена с ошибкой.
    pause
    exit /b 1
)

echo.
echo [+] Готово: dist\Net-Control.exe
pause
