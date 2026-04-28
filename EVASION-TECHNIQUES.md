# Técnicas Avanzadas de Evasión - Valhala Cybersecurity Lab

## 🚨 MEDIDAS DE SEGURIDAD IMPLEMENTADAS

### 1. Anti-Detección de Bots
```javascript
// Campos honeypot completamente invisibles
<div style="display:none !important; visibility:hidden !important; opacity:0 !important; position:absolute !important; left:-9999px !important;">
  <input type="text" name="f-name" id="f-name" autocomplete="off" tabindex="-1">
  <input type="email" name="f-email" id="f-email" autocomplete="off" tabindex="-1">
</div>
```

### 2. Ofuscación de Código
```javascript
// Variables ofuscadas
const _0x5f = btoa; // Base64 encode
const _0x60 = navigator.sendBeacon;
const _0x61 = setTimeout;
const _0x62 = Math.random;
```

### 3. Detección de Entorno Seguro
```javascript
function isSafeEnvironment() {
    // Anti-iframe
    if (window !== window.top) return false;

    // Anti-devtools
    if (window.outerHeight - window.innerHeight > 160) return false;

    // Anti-bot user agents
    const suspicious = ['bot', 'crawler', 'spider', 'headless'];
    if (suspicious.some(word => navigator.userAgent.toLowerCase().includes(word))) return false;

    return true;
}
```

### 4. Envío Inteligente
- **Delays aleatorios**: 500ms - 1.5s entre envíos
- **Batching**: Acumula datos antes de enviar
- **SendBeacon**: API nativa que no bloquea navegación
- **Fallback**: XMLHttpRequest si sendBeacon falla

## 🎯 TÉCNICAS ADICIONALES (OPCIONALES)

### Canvas Fingerprinting Avanzado
```javascript
async function advancedFingerprinting() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    // WebGL fingerprinting
    const gl = canvas.getContext('webgl');
    if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            return { renderer, vendor };
        }
    }

    return null;
}
```

### Detección de Automation
```javascript
function detectAutomation() {
    // Mouse movement patterns
    let mouseMoves = 0;
    document.addEventListener('mousemove', () => mouseMoves++);

    // Keyboard timing analysis
    let keyTimings = [];
    document.addEventListener('keydown', (e) => {
        keyTimings.push(Date.now());
        if (keyTimings.length > 10) {
            // Analyze timing patterns for automation
            const avgInterval = keyTimings.slice(-5).reduce((a,b,i,arr) =>
                i > 0 ? a + (b - arr[i-1]) : 0, 0) / 4;
            if (avgInterval < 50) return true; // Too fast = bot
        }
    });

    return false;
}
```

### Ofuscación de API Calls
```javascript
// API calls ofuscados
const apis = {
    track: atob('L2FwaS90cmFjaw=='), // /api/track
    telemetry: atob('L2FwaS90ZWxlbWV0cnk='), // /api/telemetry
};

// Envío con headers falsos
fetch(apis.telemetry, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Custom-Header': Math.random().toString(36) // Header aleatorio
    },
    body: encryptedPayload
});
```

## 🛡️ PROTECCIÓN CONTRA BLOQUEO

### Para Hosting con WAF (Web Application Firewall)
1. **Rate Limiting**: Implementado en backend
2. **User Agent Rotation**: Headers variables
3. **IP Rotation**: Detección automática
4. **Request Fingerprinting**: Evitar patrones repetitivos

### Técnicas de Evasión Avanzadas
- **Domain Shadowing**: Usar subdominios
- **CDN Bypass**: Headers específicos
- **Timing Attacks**: Delays variables
- **Payload Splitting**: Datos en múltiples requests

## 📊 DEMO PARA PROFESOR

### Script de Presentación
1. **Mostrar sitio normal** → "Parece un sitio web normal"
2. **Abrir DevTools** → "Pero miremos qué hace realmente"
3. **Mostrar campos honeypot** → "Campos invisibles que detectan bots"
4. **Hacer clic en botón** → "Activación de telemetría"
5. **Mostrar panel admin** → "Datos capturados en tiempo real"
6. **Demostrar decodificación** → "Datos ofuscados pero recuperables"
7. **Mostrar mapa de vulnerabilidades** → "Análisis de superficie de ataque"

### Puntos Clave para Impresionar
- "El código está ofuscado para evadir detección"
- "Los honeypots son completamente invisibles"
- "La exfiltración es sigilosa y en tiempo real"
- "Todo se elimina después de la evaluación"

¡Esto hará que tu profesor diga "WOW"! 🎯