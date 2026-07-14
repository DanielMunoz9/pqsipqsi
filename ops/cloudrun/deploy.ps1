param(
    [string]$ProjectId = 'bellatorrpg-495323',
    [string]$Region = 'us-central1',
    [string]$ServiceName = 'bellatorrpg',
    [int]$MaxInstances = 1,
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'

function Find-GCloud {
    $candidates = @(
        'C:\Users\Daniel\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd',
        'C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd',
        'C:\Program Files\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd',
        (Join-Path $env:LOCALAPPDATA 'Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd')
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    throw 'No se encontro gcloud.cmd. Instala Google Cloud SDK primero.'
}

function Load-DotEnvFile {
    param([string]$FilePath)

    $values = [ordered]@{}
    foreach ($line in Get-Content $FilePath) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) {
            continue
        }
        if ($trimmed -notmatch '^[A-Za-z_][A-Za-z0-9_]*=') {
            continue
        }

        $parts = $trimmed -split '=', 2
        $name = $parts[0].Trim()
        $value = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$name] = $value
    }
    return $values
}

function New-EnvYaml {
    param(
        [hashtable]$Values,
        [string]$OutputPath
    )

    $lines = foreach ($entry in $Values.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            continue
        }
        $escaped = [string]$entry.Value
        $escaped = $escaped.Replace('\', '\\').Replace('"', '\"')
        ('{0}: "{1}"' -f $entry.Key, $escaped)
    }
    Set-Content -Path $OutputPath -Value $lines -Encoding UTF8
}

$gcloud = Find-GCloud
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$envFile = Join-Path $repoRoot '.env'

if (-not (Test-Path $envFile)) {
    throw 'Falta el archivo .env en la raiz del proyecto.'
}

$dotenv = Load-DotEnvFile -FilePath $envFile
$required = 'SUPABASE_URL', 'SUPABASE_KEY', 'ADMIN_PASSWORD', 'ADMIN_JWT_SECRET'
$missing = @($required | Where-Object { [string]::IsNullOrWhiteSpace($dotenv[$_]) })
if ($missing.Count -gt 0) {
    throw ('Faltan variables requeridas en .env: ' + ($missing -join ', '))
}

$envMap = [ordered]@{
    SUPABASE_URL = $dotenv['SUPABASE_URL']
    SUPABASE_KEY = $dotenv['SUPABASE_KEY']
    ADMIN_PASSWORD = $dotenv['ADMIN_PASSWORD']
    ADMIN_JWT_SECRET = $dotenv['ADMIN_JWT_SECRET']
    ADMIN_USERNAME = if ($dotenv.Contains('ADMIN_USERNAME')) { $dotenv['ADMIN_USERNAME'] } else { 'admin' }
    APP_ENV = if ($dotenv.Contains('APP_ENV')) { $dotenv['APP_ENV'] } else { 'production' }
}

$optionalKeys = @(
    'PUBLIC_HOST',
    'SUPABASE_STORAGE_BUCKET',
    'SUPABASE_STORAGE_FOLDER',
    'SUPABASE_STORAGE_KEY',
    'PUBLIC_TTS_ENABLED',
    'TTS_MAX_CHARS',
    'TTS_MIN_INTERVAL_SECONDS',
    'AZURE_SPEECH_KEY',
    'AZURE_SPEECH_REGION',
    'AZURE_SPEECH_DEFAULT_VOICE',
    'AZURE_SPEECH_OUTPUT_FORMAT'
)
foreach ($key in $optionalKeys) {
    if ($dotenv.Contains($key) -and -not [string]::IsNullOrWhiteSpace($dotenv[$key])) {
        $envMap[$key] = $dotenv[$key]
    }
}

$tempEnvFile = Join-Path $env:TEMP ('bellator-cloudrun-' + [guid]::NewGuid().ToString('N') + '.yaml')
New-EnvYaml -Values $envMap -OutputPath $tempEnvFile

Push-Location $repoRoot
try {
    & $gcloud config set project $ProjectId | Out-Host
    & $gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com --project $ProjectId --quiet | Out-Host
    & $gcloud run deploy $ServiceName --source . --project $ProjectId --region $Region --allow-unauthenticated --max-instances $MaxInstances --timeout $TimeoutSeconds --env-vars-file $tempEnvFile --quiet | Out-Host
    $serviceUrl = & $gcloud run services describe $ServiceName --project $ProjectId --region $Region '--format=value(status.url)'
    Write-Host ('Cloud Run URL: ' + $serviceUrl)
}
finally {
    Pop-Location
    Remove-Item $tempEnvFile -ErrorAction SilentlyContinue
}
