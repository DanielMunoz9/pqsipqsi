param(
  [string]$Source = (Join-Path $PSScriptRoot '..\public'),
  [string]$Output = (Join-Path $PSScriptRoot '..\.netlify-album-dist')
)

$sourcePath = (Resolve-Path $Source).Path
if (Test-Path $Output) {
  Remove-Item -Path $Output -Recurse -Force
}

New-Item -ItemType Directory -Path $Output | Out-Null

Copy-Item -Path (Join-Path $sourcePath 'album.html') -Destination (Join-Path $Output 'album.html')
Copy-Item -Path (Join-Path $sourcePath '404.html') -Destination (Join-Path $Output '404.html') -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $sourcePath 'robots.txt') -Destination (Join-Path $Output 'robots.txt') -ErrorAction SilentlyContinue

Copy-Item -Path (Join-Path $sourcePath 'data') -Destination (Join-Path $Output 'data') -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $sourcePath 'audio') -Destination (Join-Path $Output 'audio') -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $sourcePath 'images') -Destination (Join-Path $Output 'images') -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $sourcePath 'STICKERS') -Destination (Join-Path $Output 'STICKERS') -Recurse -Force -ErrorAction SilentlyContinue

Copy-Item -Path (Join-Path $sourcePath 'album.html') -Destination (Join-Path $Output 'index.html')

@"
/api/* https://bellatorrpg.online/api/:splat 200
/ /album.html 200
"@ | Set-Content -Path (Join-Path $Output '_redirects') -Encoding ASCII

@"
/*.html
  Cache-Control: no-store, no-cache, must-revalidate

/index.html
  Cache-Control: no-store, no-cache, must-revalidate

/album.html
  Cache-Control: no-store, no-cache, must-revalidate
"@ | Set-Content -Path (Join-Path $Output '_headers') -Encoding ASCII

Write-Host "Album standalone bundle ready at $Output"