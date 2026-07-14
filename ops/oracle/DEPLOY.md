# Oracle Cloud Free

Esta ruta sirve para dejar Bellator en un solo origen estable: Oracle VM + Docker + Caddy.

## 1. Crear la VM

- Imagen: Ubuntu 24.04
- Shape: Ampere Always Free
- Recomendado: 1 OCPU, 6 GB RAM
- Abrir puertos `22`, `80` y `443`

## 2. Preparar DNS

- Apunta `bellatorrpg.online` al IP publico de la VM.
- Si Cloudflare esta en modo proxy, deja el registro en `DNS only` durante la primera emision de certificado.

## 3. Instalar Docker

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git
sudo usermod -aG docker $USER
newgrp docker
```

## 4. Clonar y configurar

```bash
git clone <tu-repo> bellator
cd bellator
cp .env.example .env
```

Completa como minimo estas variables en `.env`:

```bash
PUBLIC_HOST=bellatorrpg.online
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_KEY=tu-supabase-key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=tu-clave-admin
ADMIN_JWT_SECRET=tu-secreto-jwt-largo
APP_ENV=production
PORT=8080
```

## 5. Levantar la app

```bash
docker compose -f ops/oracle/docker-compose.yml up -d --build
```

## 6. Validar

```bash
docker compose -f ops/oracle/docker-compose.yml ps
docker compose -f ops/oracle/docker-compose.yml logs -f app
curl https://bellatorrpg.online/api/tts/voices
```

## 7. Qué conserva esta ruta

- `Sentinel` se mantiene: es la capa visual/honeypot de consola del proyecto.
- Los nodos interactivos y el fondo viven en `public/app.js`.
- Piper TTS sigue dentro del mismo contenedor, sin depender de Hugging Face como origen.

## 8. Nota importante

El backend no arranca sin estas variables reales:

- `SUPABASE_URL`
- `SUPABASE_KEY`
- `ADMIN_PASSWORD`
- `ADMIN_JWT_SECRET`

Si faltan, la app termina al iniciar.