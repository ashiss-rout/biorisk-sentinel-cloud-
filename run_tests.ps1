<#
Run the full unit and integration test suite using the project virtual environment.
Usage: .\run_tests.ps1
#>

$venvActivate = ".\.venv\Scripts\Activate.ps1"
if (-not (Test-Path $venvActivate)) {
    Write-Host "Virtual environment not found at .\.venv. Create one first: .\setup_env.ps1"
    exit 1
}

Write-Host "Activating virtual environment..."
& $venvActivate

Write-Host "Running tests..."
python -m unittest discover -s tests -v

if ($LASTEXITCODE -ne 0) {
    Write-Error "Some tests failed."; exit $LASTEXITCODE
}

Write-Host "All tests passed."