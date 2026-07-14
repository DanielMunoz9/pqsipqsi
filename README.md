# Valhala - Laboratorio de Ciberseguridad Educativa

Sistema de demostración para técnicas Red Team: telemetría pasiva, exfiltración sigilosa, honeypots, análisis de superficie de ataque y forense digital.

## ✅ Adaptado para Hosting

Este proyecto está **completamente adaptado** para funcionar en cualquier hosting moderno:

- ✅ **URLs dinámicas**: APIs usan `window.location.origin` automáticamente
- ✅ **Puerto configurable**: Variable `PORT` para hosting como Railway/Render
- ✅ **Docker ready**: Dockerfile optimizado para despliegue
- ✅ **Variables de entorno**: Configuración flexible y segura

## 🚀 Despliegue Rápido

### 1. Preparar el Código
```bash
# Configurar variables de entorno
cp .env.example .env
# Edita .env con tus credenciales reales

# Ejecutar script de verificación
chmod +x deploy.sh
./deploy.sh
```

### 2. Oracle Cloud Free (Recomendada para tu caso)
1. Crea una VM Ubuntu Always Free en Oracle Cloud
2. Abre puertos `80`, `443` y `22` en el Security List y en el firewall del sistema
3. Apunta tu dominio al IP público de la VM
4. Copia `.env.example` a `.env` y completa variables reales
5. Ejecuta `docker compose -f ops/oracle/docker-compose.yml up -d --build`
6. Valida `https://tu-dominio/`, la narración desde una página pública y el panel `/bl-sentinel-9f3a2c`

### 3. Railway (Opción Rápida - 5 min)
1. Ve a [Railway.app](https://railway.app) → "New Project" → "Deploy from GitHub"
2. Conecta tu repositorio
3. **Automático**: Railway detecta el Dockerfile y configura todo
4. Variables de entorno se configuran automáticamente desde `.env`

### 4. Render (Alternativa)
1. Ve a [Render.com](https://render.com) → "New" → "Web Service"
2. Conecta GitHub repo
3. Selecciona "Docker" como runtime
4. Puerto: `8080`
5. Variables de entorno desde `.env`

### 5. DigitalOcean App Platform
1. "Create App" desde GitHub
2. Seleccionar Dockerfile
3. Configurar variables de entorno

## 🔧 Configuración Técnica

### Variables de Entorno (.env)
```bash
# Requeridas
PUBLIC_HOST=bellatorrpg.online
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_KEY=tu-supabase-anon-key
ADMIN_PASSWORD=tu-clave-admin-segura
ADMIN_JWT_SECRET=tu-jwt-secret-seguro

# Opcionales
ADMIN_USERNAME=admin
APP_ENV=production
PORT=8080  # Para hosting
PUBLIC_TTS_ENABLED=false
TTS_MAX_CHARS=700
TTS_MIN_INTERVAL_SECONDS=20
AZURE_SPEECH_KEY=tu-azure-speech-key
AZURE_SPEECH_REGION=eastus
AZURE_SPEECH_DEFAULT_VOICE=es-CO-SalomeNeural
AZURE_SPEECH_OUTPUT_FORMAT=audio-24khz-96kbitrate-mono-mp3
SUPABASE_STORAGE_BUCKET=bellator-uploads
SUPABASE_STORAGE_FOLDER=uploads
SUPABASE_STORAGE_KEY=tu-service-role-o-anon-con-permisos
```

## Oracle Cloud Free

- Usa la VM Always Free como origen unico de produccion.
- Mantiene `Sentinel`, nodos interactivos, cursor, musica y narración Azure cuando `AZURE_SPEECH_KEY` y `AZURE_SPEECH_REGION` están configurados. Si no, el frontend cae al narrador del navegador como respaldo.
- El frontend compartido depende de `core.js`, `tracker.js`, `sentinel.js` y `app.js`; si despliegas desde este repo con cache limpia, todo vuelve a la misma fuente de verdad.
- El archivo listo para levantar en Oracle es `ops/oracle/docker-compose.yml`.
- En hosts efimeros como Cloud Run, configura `SUPABASE_STORAGE_BUCKET` para que `/api/upload` persista en Supabase Storage en vez de disco local.

## Cloud Run

- El contenedor ya expone `8080`, no depende de Piper y está listo para escalar a cero.
- El script [ops/cloudrun/deploy.ps1](ops/cloudrun/deploy.ps1) ahora despliega con `--max-instances 2` y `--timeout 30` para no abrir la puerta a picos caros por error.
- La narración pública queda deshabilitada por defecto con `PUBLIC_TTS_ENABLED=false`; si la reactivas, conviene mantener `TTS_MAX_CHARS` y `TTS_MIN_INTERVAL_SECONDS` para limitar costo.
- Si despliegas desde código fuente en Google Cloud, excluye `tts/`, `.hf-deploy/` y logs pesados con `.gcloudignore`.
- Script listo para desplegar desde Windows: `ops/cloudrun/deploy.ps1`.
- Cloud Run y Cloud Build requieren billing activo en el proyecto, incluso si luego entras al free tier.

### Base de Datos Supabase
```sql
-- Crear tabla audit_logs
CREATE TABLE audit_logs (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  session_id TEXT,
  user_data JSONB,
  player_data JSONB,
  location JSONB,
  fingerprint TEXT,
  open_ports JSONB,
  exfiltration_detected BOOLEAN DEFAULT FALSE,
  ip_real_webrtc TEXT,
  vpn_detectada BOOLEAN DEFAULT FALSE,
  spamhaus_status TEXT
);
```

Para habilitar el historial de combates y la programación de peleas en el panel admin, ejecuta también el script [ops/supabase-competition-tables.sql](ops/supabase-competition-tables.sql) en el SQL Editor de Supabase.

## 📊 Funcionalidades Implementadas

### Cliente (tracker.js)
- ✅ **Telemetría automática**: Captura pasiva al cargar página
- ✅ **Fingerprinting avanzado**: Canvas, WebGL, screen, navigator
- ✅ **Escaneo de puertos**: Detección de servicios en localhost (80,443,3389,4444)
- ✅ **Exfiltración sigilosa**: Base64 encoding + sendBeacon
- ✅ **Honeypot detection**: Campos ocultos f-email/f-name

### Backend (main.go)
- ✅ **Decodificación Base64**: Payloads ofuscados
- ✅ **Detección de exfiltración**: Análisis de autofill
- ✅ **Procesamiento de puertos**: Mapeo a módulos Metasploit
- ✅ **Persistencia Supabase**: Logs completos y seguros

### Panel Admin (admin.html)
- ✅ **Decodificación forense**: Visualización de datos exfiltrados
- ✅ **Mapa de vulnerabilidades**: Puertos → exploits sugeridos
- ✅ **Feed en vivo**: Actualización cada 5 segundos
- ✅ **Simulación Metasploit**: Botones para demos educativos

## 🎯 URLs del Sistema

Después del despliegue:
- **Sitio público**: `https://tu-dominio.com`
- **Panel admin**: `https://tu-dominio.com/bl-sentinel-9f3a2c`
- **Login**: `admin` / `PAXn10HCs9edZoVm`

## 🛡️ Seguridad y Evasión

### Anti-Detección Implementada
- ✅ **Campos Honeypot ocultos**: `f-name`, `f-email`, `f-phone` con CSS agresivo
- ✅ **Ofuscación de código**: Variables y funciones con nombres ofuscados (`_0x5f`, `_0x60`)
- ✅ **Envío diferido**: Delays aleatorios (500ms-1.5s) para evadir detección
- ✅ **Verificación de entorno**: Detecta iframes, devtools, y user agents sospechosos
- ✅ **Ofuscación múltiple**: Base64 + JSON + timing aleatorio

### Técnicas de Evasión
- **Honeypots invisibles**: Campos ocultos que solo los bots llenan
- **Delays aleatorios**: Evita patrones de timing predecibles
- **Detección de análisis**: Pausa actividad en entornos de debugging
- **Ofuscación de payloads**: Múltiples capas de encoding

### Detección de Amenazas
- **Autofill detection**: Campos honeypot activados = bot detectado
- **Multi-IP tracking**: Múltiples IPs por fingerprint = atacante
- **VPN/Proxy detection**: Análisis de headers y geolocalización
- **Spamhaus checking**: Consulta de listas negras en tiempo real

## 📚 Documentación Avanzada

- **[EVASION-TECHNIQUES.md](EVASION-TECHNIQUES.md)**: Técnicas avanzadas de evasión y anti-detección
- **Dockerfile**: Configuración para despliegue containerizado
- **railway.json**: Configuración específica para Railway
- **render.yaml**: Configuración específica para Render

## 🎯 Para la Demo del Profesor

### Flujo de Presentación
1. **Sitio público** → "Parece normal, pero..."
2. **DevTools** → "Campos honeypot invisibles"
3. **Interacción** → "Telemetría activada"
4. **Panel admin** → "Datos en tiempo real"
5. **Decodificación** → "Ofuscación reversible"
6. **Vulnerabilidades** → "Análisis de superficie"

### Puntos Técnicos a Destacar
- ✅ Ofuscación múltiple (Base64 + timing)
- ✅ Honeypots con CSS agresivo
- ✅ Detección de entornos de análisis
- ✅ Envío sigiloso con delays aleatorios
- ✅ Análisis forense completo

---

**¡Listo para impresionar!** 🚀 Eliminar después de la evaluación.

```bash
# Instalar dependencias
go mod tidy

# Ejecutar
go run main.go

# O con Docker
docker build -t valhala .
docker run -p 8080:8080 --env-file .env valhala
```

## ⚠️ Importante

- **Uso exclusivo académico**: Solo para demostración educativa
- **Eliminar después**: Remover completamente el código post-evaluación
- **No usar en producción**: Este es un laboratorio de seguridad, no un sistema real

---

**Ready para hosting!** 🚀 Sube a GitHub y despliega en 5 minutos.
- **Análisis de Vulnerabilidades**: Escaneo del servidor hospedado
- **Exfiltración Sigilosa**: Envío de datos en Base64

### Backend (main.go)
- **Detección de Honeypots**: Campos `f-email` y `f-name`
- **Procesamiento de Vulnerabilidades**: Análisis de superficie de ataque
- **Integración Supabase**: Almacenamiento seguro de datos

### Panel Admin (admin.html)
- **Dashboard en Tiempo Real**: Actualización cada 5 segundos
- **Decodificación Forense**: Visualización de datos exfiltrados
- **Mapa de Vulnerabilidades**: Análisis de riesgos del servidor
- **Feed Live**: Monitoreo de actividad en tiempo real

## 📊 Técnicas Demostradas

- **Permission Grooming**: Captura de datos sin permisos explícitos
- **Clickjacking Prevention**: Detección de navegación automática
- **Honeypot Detection**: Campos ocultos para detectar bots
- **Server Vulnerability Assessment**: Análisis de endpoints expuestos
- **Data Exfiltration**: Técnicas de extracción sigilosa
- **Real-time Monitoring**: Dashboard de seguridad activa

## ⚠️ Uso Educativo

Este código es **exclusivamente para fines académicos**. Después de la evaluación:

1. **Elimina el hosting** completamente
2. **Borra la base de datos** Supabase
3. **Destruye todas las credenciales**
4. **No reutilices** en entornos reales

## 🧪 Testing del Demo

1. **Accede al sitio** desplegado
2. **Genera telemetría**: Navega y llena formularios
3. **Panel Admin**: `/admin.html` (usuario: `admin`, password: `valhala2024`)
4. **Observa**: Feed en vivo, vulnerabilidades detectadas, datos decodificados

## 🏗️ Arquitectura

```
Cliente Browser
    ↓ (Telemetría + Vulnerabilidades)
Servidor Go (Puerto 8080)
    ↓ (Procesamiento + Detección)
Supabase Database
    ↓ (Almacenamiento)
Panel Admin (Dashboard)
```</content>
<parameter name="filePath">c:\Users\Daniel\Desktop\valhala\README.md