param(
    [string]$OutputDir = "dist\portable"
)

$ErrorActionPreference = "Stop"

Write-Host "Building NetDocIT portable executable..."

uv run --with pyinstaller python -m PyInstaller `
    --noconfirm --clean --onefile `
    --name "NetDocIT" `
    --distpath $OutputDir `
    --hidden-import pyvis.network `
    --collect-data pyvis `
    --add-data "data;data" `
    --add-data "src\backend\scripts;src\backend\scripts" `
    --add-data "src\presentation\templates;src\presentation\templates" `
    --add-data "src\presentation\web;src\presentation\web" `
    main.py

if (Test-Path "NetDocIT.spec") {
    Remove-Item "NetDocIT.spec" -Force
}

$exe = Join-Path $OutputDir "NetDocIT.exe"
if (Test-Path $exe) {
    $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host "Build complete: $exe ($size MB)"
} else {
    Write-Host "Build failed: $exe not found"
    exit 1
}
