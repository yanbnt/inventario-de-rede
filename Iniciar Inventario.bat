@echo off
title Inventario de Rede - Make Distribuidora
cd /d "%~dp0"
python app.py
if errorlevel 1 (
  echo.
  echo Nao foi possivel iniciar. Verifique se o Python 3 esta instalado.
  pause
)
