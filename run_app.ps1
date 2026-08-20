<#
Run the Flask application using the project virtual environment.
Usage: .\run_app.ps1
#>

$venvActivate = ".\.venv\Scripts\Activate.ps1"
if (-not (Test-Path $venvActivate)) {
    Write-Host "Virtual environment not found at .\.venv. Create one first: .\setup_env.ps1"
    exit 1
}

Write-Host "Activating virtual environment..."
& $venvActivate

Write-Host "Starting the Flask app (development mode)..."
# Use py if available to pick the correct interpreter; fallback to python
if (Get-Command py -ErrorAction SilentlyContinue) {
    py app.py
} else {
    python app.py
}