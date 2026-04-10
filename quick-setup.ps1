param(
    [switch]$WithRun
)

$ErrorActionPreference = 'Stop'

function Step($msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan
}

function Ok($msg) {
    Write-Host "[OK] $msg" -ForegroundColor Green
}

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Step "检查 Python"
python --version | Out-Null
Ok "Python 可用"

Step "安装后端依赖"
python -m pip install -r requirements.txt
Ok "后端依赖安装完成"

$frontendDir = Join-Path $Root 'frontend'
if (Test-Path (Join-Path $frontendDir 'package.json')) {
    Step "检查 Node.js"
    node -v | Out-Null
    npm -v | Out-Null
    Ok "Node.js / npm 可用"

    Step "安装前端依赖"
    Push-Location $frontendDir
    npm install
    Pop-Location
    Ok "前端依赖安装完成"
} else {
    Write-Host "[WARN] 未找到 frontend/package.json，跳过前端依赖安装" -ForegroundColor Yellow
}

Write-Host "`n============================" -ForegroundColor DarkCyan
Write-Host "环境准备完成" -ForegroundColor Green
Write-Host "后端启动: uvicorn app:app --host 0.0.0.0 --port 8000 --reload"
Write-Host "前端启动: cd frontend; npm run dev"
Write-Host "============================`n" -ForegroundColor DarkCyan

if ($WithRun) {
    Step "启动后端（当前窗口）"
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload
}
