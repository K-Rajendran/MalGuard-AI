# Always launch the isolated environment; project.ps1 restores caller variables.
param([int]$Port = 8501)
& "$PSScriptRoot/scripts/project.ps1" -PythonArgs @('-m','streamlit','run','streamlit_app.py','--server.port',"$Port",'--global.developmentMode','false')
exit $LASTEXITCODE
