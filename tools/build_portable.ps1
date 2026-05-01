param(
    [string]$OutputDir = "dist\portable"
)

$ErrorActionPreference = "Stop"

python -m pip install --upgrade pip
python -m pip install pyinstaller

$datas = @(
    "data;data",
    "src\backend\scripts;src\backend\scripts",
    "src\presentation\templates;src\presentation\templates"
)

$args = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--name", "NetDocIT",
    "--distpath", $OutputDir,
    "--add-data", $datas[0],
    "--add-data", $datas[1],
    "--add-data", $datas[2],
    "src\main.py"
)

python @args