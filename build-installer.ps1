param(
    [string]$Version,
    [switch]$SelfContained
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

$PackageWxsPath = Join-Path $RepoRoot "installer\Package.wxs"
$wxsContent = Get-Content $PackageWxsPath -Raw -Encoding UTF8

# Package.wxs から現在の ProductVersion を抽出
if ($wxsContent -match '<\?define\s+ProductVersion\s*=\s*"(\d+)\.(\d+)\.(\d+)\.(\d+)"\s*\?>') {
    $major    = $Matches[1]
    $minor    = $Matches[2]
    $patch    = $Matches[3]
    $buildNum = [int]$Matches[4]
    $currentWxsVersion = "$major.$minor.$patch.$buildNum"
} else {
    throw "Package.wxs 内の ProductVersion 定義が見つかりませんでした。"
}

# パラメータ指定がない場合は Package.wxs のバージョンを使用
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version    = $currentWxsVersion
    $MsiVersion = $currentWxsVersion
} else {
    $MsiVersion = if ($Version.Split('.').Count -eq 3) { "$Version.0" } else { $Version }
}

$PublishDir = Join-Path $RepoRoot "bin\Release\net8.0-windows\publish"
$OutputDir  = Join-Path $RepoRoot "installer\output"
$OutputMsi  = Join-Path $OutputDir "AnzenSecurityWatcher-Setup-$Version-x64.msi"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Building Anzen Security Watcher MSI Installer (WiX v5)" -ForegroundColor Cyan
Write-Host " Version : $Version ($MsiVersion)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

if (Test-Path $PublishDir) {
    Remove-Item -Recurse -Force $PublishDir
}

Write-Host "[1/2] Publishing .NET 8 WPF Application..." -ForegroundColor Yellow
$publishProps = @(
    "-p:Version=$Version",
    "-p:FileVersion=$MsiVersion",
    "-p:AssemblyVersion=$MsiVersion",
    "-p:InformationalVersion=$Version"
)

if ($SelfContained) {
    dotnet publish "$RepoRoot\AnzenSecurityWatcher.csproj" -c Release -r win-x64 --self-contained true -o $PublishDir @publishProps
} else {
    dotnet publish "$RepoRoot\AnzenSecurityWatcher.csproj" -c Release -o $PublishDir @publishProps
}
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "[2/2] Building MSI package with WiX Toolset..." -ForegroundColor Yellow
wix build "$RepoRoot\installer\Package.wxs" `
    -arch x64 `
    -culture ja-JP `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -d ProductVersion="$MsiVersion" `
    -pdbtype none `
    -out $OutputMsi

if ($LASTEXITCODE -ne 0) {
    throw "wix build failed with exit code $LASTEXITCODE"
}

# ビルド成功後、Package.wxs のビルド番号をひとつインクリメント
$nextBuild = $buildNum + 1
$nextVersion = "$major.$minor.$patch.$nextBuild"
$replacementDef = '<?define ProductVersion = "' + $nextVersion + '" ?>'
$updatedWxs = [regex]::Replace(
    $wxsContent,
    '<\?define\s+ProductVersion\s*=\s*"\d+\.\d+\.\d+\.\d+"\s*\?>',
    [System.Text.RegularExpressions.MatchEvaluator]{ return $replacementDef }
)
[System.IO.File]::WriteAllText($PackageWxsPath, $updatedWxs, [System.Text.UTF8Encoding]::new($false))

# AnzenSecurityWatcher.csproj のバージョンも同期
$csprojPath = Join-Path $RepoRoot "AnzenSecurityWatcher.csproj"
if (Test-Path $csprojPath) {
    $csprojContent = Get-Content $csprojPath -Raw -Encoding UTF8
    $csprojContent = [regex]::Replace($csprojContent, '<Version>[^<]+</Version>', "<Version>$nextVersion</Version>")
    $csprojContent = [regex]::Replace($csprojContent, '<FileVersion>[^<]+</FileVersion>', "<FileVersion>$nextVersion</FileVersion>")
    $csprojContent = [regex]::Replace($csprojContent, '<AssemblyVersion>[^<]+</AssemblyVersion>', "<AssemblyVersion>$nextVersion</AssemblyVersion>")
    [System.IO.File]::WriteAllText($csprojPath, $csprojContent, [System.Text.UTF8Encoding]::new($false))
}

$msiFile = Get-Item $OutputMsi
$sizeMB = [Math]::Round($msiFile.Length / 1MB, 2)
Write-Host ""
Write-Host "Build Succeeded!" -ForegroundColor Green
Write-Host "MSI Path     : $($msiFile.FullName)" -ForegroundColor Green
Write-Host "MSI Size     : $sizeMB MB ($($msiFile.Length) bytes)" -ForegroundColor Green
Write-Host "Next Version : Package.wxs updated to $nextVersion" -ForegroundColor Cyan
