@echo off
rem Cloud Bait presenter: double-click to start, then the browser opens on the slides.
cd /d "%~dp0.."
start "" http://localhost:4000
node presenter\server.js
