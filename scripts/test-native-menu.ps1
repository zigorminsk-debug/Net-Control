$ErrorActionPreference = 'Stop'
$process = Start-Process -FilePath (Resolve-Path 'node_modules/electron/dist/electron.exe') -ArgumentList (Resolve-Path 'scripts/test-native-menu.js') -Wait -PassThru -RedirectStandardOutput native-menu-out.txt -RedirectStandardError native-menu-err.txt
foreach ($file in @('native-menu-out.txt', 'native-menu-err.txt')) {
  if (Test-Path $file) {
    foreach ($line in Get-Content $file) {
      if ($line.Trim()) {
        $safe = $line.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
        if ($safe.Length -gt 1000) { $safe = $safe.Substring(0, 1000) }
        Write-Output "::notice::$safe"
      }
    }
  }
}
if ($process.ExitCode -ne 0) { throw "Native menu test failed: $($process.ExitCode)" }
