<#
Create and prepare a local Python virtual environment and install dependencies.
Usage: .\setup_env.ps1
#>

$venvPath = ".\.venv"
$activate = "$venvPath\Scripts\Activate.ps1"

if (-not (Test-Path $venvPath)) {
    Write-Host "Creating virtual environment at $venvPath..."
    python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) { Write-Error "Failed to create virtualenv."; exit 1 }
} else {
    Write-Host "Virtual environment already exists at $venvPath"
}

if (-not (Test-Path $activate)) {
    Write-Error "Activation script not found at $activate"
    exit 1
}

Write-Host "Activating virtual environment..."
& $activate

if (Test-Path "requirements.txt") {
    Write-Host "Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Error "pip install failed."; exit 1 }
} else {
    Write-Host "requirements.txt not found — skipping dependency install."
}

Write-Host "Setup complete. Activate the environment with: & $activate"