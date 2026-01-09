@echo off
echo Automatyczny Skaner Podatności - Uruchamianie
echo =============================================


python --version >nul 2>&1
if errorlevel 1 (
    echo BLAD: Python nie jest zainstalowany lub nie jest w PATH
    echo Zainstaluj Python ze strony: https://python.org
    pause
    exit /b 1
)

echo Python znaleziony
python --version

if not exist "main.py" (
    echo BLAD: Plik main.py nie istnieje
    echo Upewnij sie, ze wszystkie pliki sa w tym samym katalogu
    pause
    exit /b 1
)

if not exist "port_scanner.py" (
    echo BLAD: Plik port_scanner.py nie istnieje
    pause
    exit /b 1
)

if not exist "cms_scanner.py" (
    echo BLAD: Plik cms_scanner.py nie istnieje
    pause
    exit /b 1
)

if not exist "report_generator.py" (
    echo BLAD: Plik report_generator.py nie istnieje
    pause
    exit /b 1
)

echo Wszystkie pliki znalezione

echo Sprawdzanie zależności...
python -c "import tkinter" 2>nul
if errorlevel 1 (
    echo BLAD: tkinter nie jest dostępny
    echo Zainstaluj Python z opcją tkinter
    pause
    exit /b 1
)

python -c "import nmap" 2>nul
if errorlevel 1 (
    echo OSTRZEZENIE: python-nmap nie jest zainstalowany
    echo Instalowanie...
    pip install python-nmap
    if errorlevel 1 (
        echo BLAD: Nie można zainstalować python-nmap
        pause
        exit /b 1
    )
)

python -c "import requests" 2>nul
if errorlevel 1 (
    echo OSTRZEZENIE: requests nie jest zainstalowany
    echo Instalowanie...
    pip install requests
)

python -c "from bs4 import BeautifulSoup" 2>nul
if errorlevel 1 (
    echo OSTRZEZENIE: beautifulsoup4 nie jest zainstalowany
    echo Instalowanie...
    pip install beautifulsoup4
)

python -c "from reportlab.lib.pagesizes import letter" 2>nul
if errorlevel 1 (
    echo OSTRZEZENIE: reportlab nie jest zainstalowany
    echo Instalowanie...
    pip install reportlab
)

echo Zależności sprawdzone
echo Uruchamianie aplikacji...
echo.
python main.py

if errorlevel 1 (
    echo.
    echo BLAD: Aplikacja zakończyła się z błędem
    echo Sprawdź powyższe komunikaty
    pause
) else (
    echo.
    echo Aplikacja zakończona pomyślnie
) 