param(
  [int]$Port = 8091,
  [string]$Root = (Join-Path $PSScriptRoot '..\public'),
  [string]$ApiBase = 'https://bellatorrpg.online'
)

$resolvedRoot = (Resolve-Path $Root).Path
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
Write-Host "Serving $resolvedRoot at http://localhost:$Port/"
Write-Host "Proxying /api requests to $ApiBase"

function Get-ContentType([string]$path) {
  switch ([System.IO.Path]::GetExtension($path).ToLowerInvariant()) {
    '.html' { 'text/html; charset=utf-8' }
    '.js'   { 'application/javascript; charset=utf-8' }
    '.css'  { 'text/css; charset=utf-8' }
    '.json' { 'application/json; charset=utf-8' }
    '.png'  { 'image/png' }
    '.jpg'  { 'image/jpeg' }
    '.jpeg' { 'image/jpeg' }
    '.gif'  { 'image/gif' }
    '.webp' { 'image/webp' }
    '.svg'  { 'image/svg+xml' }
    '.ico'  { 'image/x-icon' }
    default { 'application/octet-stream' }
  }
}

function Close-ResponseSafely([System.Net.HttpListenerResponse]$response) {
  try {
    $response.Close()
  }
  catch [System.Net.HttpListenerException] {
  }
  catch [System.ObjectDisposedException] {
  }
}

function Write-ResponseBytes([System.Net.HttpListenerContext]$context, [byte[]]$bytes) {
  try {
    if ($bytes.Length -gt 0) {
      $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    }
  }
  catch [System.Net.HttpListenerException] {
  }
  catch [System.IO.IOException] {
  }
  finally {
    Close-ResponseSafely $context.Response
  }
}

function Copy-ProxyResponse([System.Net.HttpListenerContext]$context, [System.Net.HttpWebResponse]$response) {
  $context.Response.StatusCode = [int]$response.StatusCode
  if ($response.ContentType) {
    $context.Response.ContentType = $response.ContentType
  }
  foreach ($headerKey in $response.Headers.AllKeys) {
    switch ($headerKey.ToLowerInvariant()) {
      'content-type' { }
      'content-length' { }
      'transfer-encoding' { }
      'connection' { }
      default { $context.Response.Headers[$headerKey] = $response.Headers[$headerKey] }
    }
  }

  $stream = $response.GetResponseStream()
  if ($stream) {
    try {
      $stream.CopyTo($context.Response.OutputStream)
    }
    catch [System.Net.HttpListenerException] {
    }
    catch [System.IO.IOException] {
    }
    finally {
      $stream.Dispose()
    }
  }
  Close-ResponseSafely $context.Response
}

try {
  while ($listener.IsListening) {
    $context = $listener.GetContext()
    $requestPath = [System.Uri]::UnescapeDataString($context.Request.Url.AbsolutePath.TrimStart('/'))

    if ($requestPath.StartsWith('api/', [System.StringComparison]::OrdinalIgnoreCase)) {
      $targetUrl = ($ApiBase.TrimEnd('/') + '/' + $requestPath)
      if ($context.Request.Url.Query) {
        $targetUrl += $context.Request.Url.Query
      }

      try {
        $proxyRequest = [System.Net.HttpWebRequest]::Create($targetUrl)
        $proxyRequest.Method = $context.Request.HttpMethod
        $proxyRequest.UserAgent = 'ValhalaAlbumStaticProxy/1.0'
        $proxyRequest.Accept = '*/*'
        if ($context.Request.ContentType) {
          $proxyRequest.ContentType = $context.Request.ContentType
        }
        foreach ($headerKey in $context.Request.Headers.AllKeys) {
          switch ($headerKey.ToLowerInvariant()) {
            'host' { }
            'content-length' { }
            'connection' { }
            'accept' { }
            'user-agent' { }
            'content-type' { }
            default {
              try {
                $proxyRequest.Headers[$headerKey] = $context.Request.Headers[$headerKey]
              }
              catch [System.ArgumentException] {
                continue
              }
            }
          }
        }

        if ($context.Request.HasEntityBody) {
          $requestStream = $proxyRequest.GetRequestStream()
          try {
            $context.Request.InputStream.CopyTo($requestStream)
          }
          finally {
            $requestStream.Dispose()
          }
        }

        $proxyResponse = $proxyRequest.GetResponse()
        try {
          Copy-ProxyResponse $context $proxyResponse
        }
        finally {
          $proxyResponse.Dispose()
        }
      }
      catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($webResponse) {
          try {
            Copy-ProxyResponse $context $webResponse
          }
          finally {
            $webResponse.Dispose()
          }
        } else {
          $context.Response.StatusCode = 502
          $bytes = [System.Text.Encoding]::UTF8.GetBytes('proxy error')
          Write-ResponseBytes $context $bytes
        }
      }
      continue
    }

    if ([string]::IsNullOrWhiteSpace($requestPath)) { $requestPath = 'album.html' }
    $safePath = $requestPath -replace '/', [System.IO.Path]::DirectorySeparatorChar
    $candidate = Join-Path $resolvedRoot $safePath
    $fullPath = [System.IO.Path]::GetFullPath($candidate)

    if (-not $fullPath.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      $context.Response.StatusCode = 403
      $context.Response.Close()
      continue
    }

    if (-not (Test-Path $fullPath -PathType Leaf)) {
      $context.Response.StatusCode = 404
      $bytes = [System.Text.Encoding]::UTF8.GetBytes('404')
      Write-ResponseBytes $context $bytes
      continue
    }

    $bytes = [System.IO.File]::ReadAllBytes($fullPath)
    $context.Response.StatusCode = 200
    $context.Response.ContentType = Get-ContentType $fullPath
    $context.Response.ContentLength64 = $bytes.Length
    Write-ResponseBytes $context $bytes
  }
}
finally {
  $listener.Stop()
  $listener.Close()
}
