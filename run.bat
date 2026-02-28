@echo off
cd /d "%~dp0"
chcp 65001 >nul
python baidu_dl.py
pause
