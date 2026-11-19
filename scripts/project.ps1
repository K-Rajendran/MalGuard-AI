# Keep Python overrides local to this process; do not change user/system settings.
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$PythonArgs)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$projectPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $projectPython)) { throw 'Create .venv with py -3.15 -m venv .venv first.' }
$savedPythonPath = $env:PYTHONPATH
$savedPipTarget = $env:PIP_TARGET
$savedPythonHome = $env:PYTHONHOME
try {
    $env:PYTHONPATH = ''
    $env:PIP_TARGET = ''
    $env:PYTHONHOME = ''
    Push-Location -LiteralPath $projectRoot
    try { & $projectPython @PythonArgs; $projectExitCode = $LASTEXITCODE }
    finally { Pop-Location }
}
finally {
    $env:PYTHONPATH = $savedPythonPath
    $env:PIP_TARGET = $savedPipTarget
    $env:PYTHONHOME = $savedPythonHome
}
exit $projectExitCode
