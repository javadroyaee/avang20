$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Magenta
Write-Host "   Avang VPN - GitHub Auto Build Tool    " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Magenta

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "خطا: Git روی سیستم نصب نیست!" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path ".git")) {
    git init
    git branch -M main
}

$remoteUrl = git remote get-url origin 2>$null
if (-not $remoteUrl) {
    $repoInput = Read-Host "لینک مخزن GitHub خود را وارد کنید (مثال: https://github.com/username/AvangVPN.git)"
    git remote add origin $repoInput
}

git add .
git commit -m "Build Full AvangVPN with Sing-box Core - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" --allow-empty
git push -u origin main

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "ارسال با موفقیت انجام شد!" -ForegroundColor Green
Write-Host "در تب Actions مخزن GitHub، فایل AvangVPN-Full-Signed را دانلود کنید." -ForegroundColor White
Write-Host "=========================================" -ForegroundColor Green