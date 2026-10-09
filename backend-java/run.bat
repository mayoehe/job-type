@echo off
REM JobShield Java backend — build + run (JDK 17+, no Maven needed)
setlocal
cd /d %~dp0
if not exist out mkdir out
dir /s /b src\*.java > out\sources.txt
javac -encoding UTF-8 -d out @out\sources.txt
if errorlevel 1 exit /b 1
copy /y data\employers.json out\employers.json >nul
java -cp out com.jobshield.App
