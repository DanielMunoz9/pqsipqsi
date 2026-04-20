/* ══════════════════════════════════════════════════════════════════════
   BELLATOR ROLBATTLE — app.js
   Canvas visual effects (espacio, constelaciones, cursor+chispas)
   Colores: AZUL (#1f6feb) + DORADO (#D4AF37)
   ══════════════════════════════════════════════════════════════════════ */

// ── BELLATOR SENTINEL — console honeypot ──
(function bellatorSentinel() {
    const isTouchDevice = (window.matchMedia && window.matchMedia('(hover:none), (pointer:coarse)').matches) || navigator.maxTouchPoints > 0;
    if (isTouchDevice) return;

    const S0 = 'background:#0d1117;color:#d4af37;font-size:13px;font-weight:900;font-family:monospace;padding:3px 10px';
    const S1 = 'background:#0d1117;color:#ff3333;font-size:12px;font-family:monospace;padding:2px 10px';
    const S2 = 'background:#0d1117;color:#8b9298;font-size:11px;font-family:monospace;padding:1px 10px';
    const S3 = 'background:#0d1117;color:#00ff41;font-size:11px;font-family:monospace;padding:1px 10px';
    const S4 = 'background:#100000;color:#ff3333;font-size:17px;font-weight:900;font-family:monospace;padding:8px 18px;letter-spacing:2px';
    const S5 = 'background:#0d1117;color:#d4af37;font-size:20px;font-weight:900;font-family:monospace;padding:10px 20px;letter-spacing:5px';

    const fakeIP  = `${10+Math.floor(Math.random()*220)}.${Math.floor(Math.random()*254)}.${Math.floor(Math.random()*254)}.${Math.floor(Math.random()*254)}`;
    const fakeHash = Math.random().toString(36).substr(2,8).toUpperCase() + '-' + Math.random().toString(36).substr(2,8).toUpperCase();
    const fakePort = [8443,4444,9001,31337,1337][Math.floor(Math.random()*5)];

    setTimeout(function() {

        // Kali Linux Dragon — logo oficial (Braille art)
        console.log('%c' + `
⠀⠀⠀⠀⠠⠤⠤⠤⠤⠤⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⢶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣀⣀⣠⣤⣤⣴⠶⠶⠶⠶⠶⠶⠶⠶⠶⠿⠿⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠚⠛⠉⠉⠉⠀⠀⠀⠀⠀⠀⢀⣀⣀⣤⡴⠶⠶⠿⠿⠿⣧⡀⠀⠀⠀⠤⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣠⡴⠞⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷⣶⣦⣤⣄⣈⡑⢦⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠔⠚⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠟⠉⠉⠉⠉⠙⠛⠿⣿⣮⣷⣤⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣯⣧⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢷⡤⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠻⠿⠿⣿⣶⣶⣦⣄⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣯⡛⠻⢦⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣆⠀⠙⢆⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣆⠀⠈⢣
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⡆⠀⠈
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⠀`, S3);

        // JJK Domain Expansion
        console.log('%c' + `   領域展開`, 'background:#0d1117;color:#7c3aed;font-size:28px;font-weight:900;font-family:serif;letter-spacing:12px;padding:8px 20px');
        console.log('%c' + `
  ╔═══════════════════════════════════════════════════════════════════╗
  ║                                                                   ║
  ║   「 伏魔御廚子 」  —  SENTINEL · MALDICIÓN INVOCADA             ║
  ║                                                                   ║
  ║   EXTENSIÓN DE DOMINIO  ▸  bellatorrolbattle.com                 ║
  ║                                                                   ║
  ║   "Dentro de este dominio, cada acción es registrada.            ║
  ║    No hay escape. No hay olvido. La maldición ya te alcanzó."    ║
  ║                                                                   ║
  ║   ◈  IA APRENDIENDO Y DEFENDIENDO EN SEGUNDO PLANO  ◈           ║
  ║                                                                   ║
  ╚═══════════════════════════════════════════════════════════════════╝`, 'background:#0d1117;color:#a855f7;font-size:11.5px;font-family:monospace;padding:2px 10px');

        console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', S1);
        console.log('%c⛔  ACCESO NO AUTORIZADO DETECTADO — SISTEMA EN MODO ALERTA  ⛔', S4);
        console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', S1);
        console.log('%c¿ QUIERES JUGAR... O SALDRÁS DE AQUÍ ?', S5);
        console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', S1);

        console.log('%c[IP-TRACE]%c     Dirección detectada: ' + fakeIP + ' — rastreando origen...', S1, S3);
        console.log('%c[SESSION]%c      Hash de sesión generado: ' + fakeHash, S0, S2);
        console.log('%c[FINGERPRINT]%c  Navegador, SO y dispositivo indexados en base de datos Bellator.', S1, S2);
        console.log('%c[NEURAL-NET]%c   Modelo SENTINEL-7 activo. Análisis de comportamiento: INICIADO', S0, S3);
        console.log('%c[HONEYPOT]%c     Trampa activa en /api/admin — esperando intrusos...', S1, S3);
        console.log('%c[FIREWALL]%c     2,847 IPs bloqueadas. Puerto ' + fakePort + ' monitorizado.', S0, S2);
        console.log('%c[WATCHDOG]%c     Consola bajo vigilancia activa. Cada comando es registrado.', S1, S3);
        console.log('%c[LOG-REMOTE]%c   Actividad sincronizada con servidor de seguridad remoto.', S0, S2);

        console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', S1);
        console.log('%c[AVISO LEGAL]%c  Cualquier intento de acceso no autorizado, modificación o ataque a este sistema está sujeto a reporte inmediato. Tu actividad ha sido registrada.', S1, S2);
        console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', S1);

        // ── NetExec Banner ──
        setTimeout(function() {
            const NXC  = 'background:#0d1117;color:#00ff41;font-size:11px;font-family:monospace;padding:1px 6px';
            const NXCR = 'background:#0d1117;color:#ff3333;font-size:11px;font-family:monospace;padding:1px 6px';
            const NXCG = 'background:#0d1117;color:#d4af37;font-size:11px;font-family:monospace;padding:1px 6px';
            const NXCB = 'background:#0d1117;color:#60a5fa;font-size:11px;font-family:monospace;padding:1px 6px';

            console.log('%c' + `
     .   .
    .|   |.     _   _          _     _____
    ||   ||    | \\ | |   ___  | |_  | ____| __  __   ___    ___
    \\\\( )//    |  \\| |  / _ \\ | __| |  _|   \\ \\/ /  / _ \\  / __|
    .=[ ]=.    | |\\  | |  __/ | |_  | |___   >  <  |  __/ | (__
   / /'-'\\ \\   |_| \\_|  \\___|  \\__| |_____| /_/\\_\\  \\___|  \\___|
   ' \\   / '
     '   '
    The network execution tool — interceptado por BELLATOR SENTINEL
    Version : 1.5.1  |  Codename: Yippie-Ki-Yay  |  Commit: Kali Linux`, NXC);

            console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', NXCR);
            console.log('%c⚠  ATAQUE DE RED DETECTADO — CONTRAMEDIDAS ACTIVAS                              ⚠', NXCR);
            console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', NXCR);

            // Simulated nxc command sequence — prints line by line
            const fakeSubnet  = fakeIP.split('.').slice(0,3).join('.') + '.0/24';
            const fakeTarget  = fakeIP;
            const fakeUser    = ['admin','root','Administrator','guest','daniel'][Math.floor(Math.random()*5)];
            const fakePass    = ['Password1','123456','admin','Bellator2026!','letmein'][Math.floor(Math.random()*5)];

            const nxcLines = [
                { style: NXCB,  text: 'root@kali:~# nxc smb ' + fakeSubnet + ' --gen-relay-list targets.txt' },
                { style: NXC,   text: 'SMB    ' + fakeTarget + '  445  BELLATOR-SRV  [*] Windows 11 x64 (name:BELLATOR-SRV)' },
                { style: NXC,   text: 'SMB    ' + fakeTarget + '  445  BELLATOR-SRV  [*] Enumerating shares...' },
                { style: NXCR,  text: 'SMB    ' + fakeTarget + '  445  BELLATOR-SRV  [-] Acceso denegado — SENTINEL bloqueó SMB relay' },
                { style: NXCB,  text: 'root@kali:~# nxc ssh ' + fakeTarget + ' -u ' + fakeUser + ' -p ' + fakePass },
                { style: NXCR,  text: 'SSH    ' + fakeTarget + '   22  BELLATOR-SRV  [-] ' + fakeUser + ':' + fakePass + ' — AUTHENTICATION FAILED' },
                { style: NXCR,  text: 'SSH    ' + fakeTarget + '   22  BELLATOR-SRV  [-] Intento registrado. IP añadida a lista negra.' },
                { style: NXCB,  text: 'root@kali:~# nxc rdp ' + fakeTarget + ' -u ' + fakeUser + ' -p ' + fakePass + ' --screenshot' },
                { style: NXCR,  text: 'RDP    ' + fakeTarget + ' 3389  BELLATOR-SRV  [-] CONEXIÓN RECHAZADA — puerto 3389 cerrado' },
                { style: NXCB,  text: 'root@kali:~# nxc ldap ' + fakeTarget + ' -u \'\' -p \'\' --users' },
                { style: NXCR,  text: 'LDAP   ' + fakeTarget + '  389  BELLATOR-SRV  [-] ACCESO ANÓNIMO BLOQUEADO — SENTINEL SHIELD' },
                { style: NXCB,  text: 'root@kali:~# nxc ftp ' + fakeTarget + ' -u anonymous -p anonymous' },
                { style: NXCR,  text: 'FTP    ' + fakeTarget + '   21  BELLATOR-SRV  [-] Puerto no activo en este servidor.' },
                { style: NXCG,  text: '[ SENTINEL ] Todos los vectores de ataque bloqueados. ' + (5 + Math.floor(Math.random()*12)) + ' intentos registrados.' },
                { style: NXCG,  text: '[ SENTINEL ] Hash del atacante: ' + fakeHash + ' — perfil guardado en base de datos.' },
                { style: NXCG,  text: '[ SENTINEL ] Protocolo KILLSWITCH en espera. Próximo intento = BLOQUEO PERMANENTE.' },
                { style: NXCR,  text: '[ BELLATOR ] The quieter you become, the more you are able to hear. — Kali Linux' },
            ];

            let ni = 0;
            const nxcIv = setInterval(function() {
                if (ni >= nxcLines.length) { clearInterval(nxcIv); return; }
                console.log('%c' + nxcLines[ni].text, nxcLines[ni].style);
                ni++;
            }, 1800);

        }, 3000);

        // Live fake scan feed
        const feed = [
            ['[SCAN]      ', ' Analizando paquetes entrantes... 0 amenazas activas.'],
            ['[AI-DETECT] ', ' Patrones de comportamiento sospechoso: ANALIZANDO...'],
            ['[GUARDIAN]  ', ' Módulo anti-exploit activo. Versión 3.1.4 — SHIELD UP.'],
            ['[NETWATCH]  ', ' Tráfico SSL inspeccionado. Sin anomalías detectadas.'],
            ['[RECON]     ', ' Contramedidas desplegadas. Sistema en alerta NARANJA.'],
            ['[TRACKER]   ', ' Sesión indexada. UUID: ' + fakeHash + '-EXT'],
            ['[NEURAL]    ', ' Red neuronal defensiva procesando... precisión 99.3%'],
            ['[SENTINEL]  ', ' Sistema de defensa ALPHA operativo. En espera.'],
            ['[SCANNER]   ', ' Búsqueda de vulnerabilidades completada: 0 encontradas.'],
            ['[AI-DETECT] ', ' Comportamiento catalogado. Perfil de amenaza: BAJO.'],
            ['[KILLSWITCH]', ' Protocolo de bloqueo automático: LISTO.'],
            ['[SENTINEL]  ', ' Vigilando. Siempre vigilando.'],
        ];
        let i = 0;
        const iv = setInterval(function() {
            if (i >= feed.length) { clearInterval(iv); return; }
            console.log('%c' + feed[i][0] + '%c' + feed[i][1], S0, S3);
            i++;
        }, 2800);

    }, 300);
})();

(function() {
    // ── Shared Bellator intro widget across all public pages ──
    const INTRO_VOLUME_KEY    = 'bellatorIntroVolume';
    const INTRO_STATE_KEY     = 'bellatorIntroState';
    const INTRO_ALLOWED_KEY   = 'bellatorIntroInteractionGranted';
    const INTRO_TIMES_KEY     = 'bellatorIntroTrackTimes';

    // Clear legacy dismissed flags so widget always reappears on reload
    localStorage.removeItem('bellatorIntroDismissed');
    sessionStorage.removeItem('bellatorIntroDismissed');

    const ICON_PLAY  = `<svg width="13" height="14" viewBox="0 0 13 14" fill="#0d1117"><polygon points="0,0 13,7 0,14"/></svg>`;
    const ICON_PAUSE = `<svg width="13" height="14" viewBox="0 0 13 14" fill="#0d1117"><rect x="0" y="0" width="4" height="14" rx="1"/><rect x="9" y="0" width="4" height="14" rx="1"/></svg>`;

    function buildIntroWidget() {
        if (document.getElementById('bellator-intro-widget')) return document.getElementById('bellator-intro-widget');

        const wrapper = document.createElement('div');
        wrapper.id = 'bellator-intro-widget';
        wrapper.className = 'bl-audio-pill';
        wrapper.innerHTML = `
            <span class="bl-ap-label">B · INTRO</span>
            <audio id="bellator-intro-audio" preload="auto">
                <source src="/audio/bellator-intro.mp3" type="audio/mpeg">
            </audio>
            <button type="button" class="bl-ap-play" id="bellator-intro-toggle" aria-label="Play / Pause">${ICON_PLAY}</button>
            <button type="button" class="bl-ap-close" id="bellator-intro-close" aria-label="Cerrar">×</button>
        `;
        document.body.appendChild(wrapper);
        return wrapper;
    }

    function initSharedIntroWidget() {
        const widget = buildIntroWidget();
        if (!widget) return;

        const audio     = document.getElementById('bellator-intro-audio');
        const toggle    = document.getElementById('bellator-intro-toggle');
        const closeBtn  = document.getElementById('bellator-intro-close');
        const labelEl   = widget.querySelector('.bl-ap-label');
        if (!audio || !toggle || !closeBtn) return;

        function readState() {
            try {
                const parsed = JSON.parse(localStorage.getItem(INTRO_STATE_KEY) || '{}');
                const trackTimes = readTrackTimes();
                const parsedTrack = parsed.track === 'goth' ? 'goth' : 'intro';
                const fallbackTime = Number(trackTimes[parsedTrack]) || 0;
                return {
                    track: parsedTrack,
                    time: Math.max(
                        Number.isFinite(parsed.time) ? parsed.time : parseFloat(parsed.time || '0') || 0,
                        fallbackTime,
                    ),
                    playing: Boolean(parsed.playing),
                    volume: Number.isFinite(parsed.volume) ? parsed.volume : parseFloat(parsed.volume || localStorage.getItem(INTRO_VOLUME_KEY) || '0.18') || 0.18,
                };
            } catch (_) {
                const trackTimes = readTrackTimes();
                return {
                    track: 'intro',
                    time: Number(trackTimes.intro) || 0,
                    playing: false,
                    volume: parseFloat(localStorage.getItem(INTRO_VOLUME_KEY) || '0.18') || 0.18,
                };
            }
        }

        function readTrackTimes() {
            try {
                const parsed = JSON.parse(localStorage.getItem(INTRO_TIMES_KEY) || '{}');
                return {
                    intro: Math.max(0, Number(parsed.intro) || 0),
                    goth: Math.max(0, Number(parsed.goth) || 0),
                };
            } catch (_) {
                return { intro: 0, goth: 0 };
            }
        }

        function writeTrackTime(track, time) {
            if (time <= 0) return;
            const next = readTrackTimes();
            next[track === 'goth' ? 'goth' : 'intro'] = Math.max(Number(next[track]) || 0, Number(time) || 0);
            localStorage.setItem(INTRO_TIMES_KEY, JSON.stringify(next));
        }

        function writeState(next) {
            const current = readState();
            const merged = {
                track: next.track ?? current.track,
                time: next.time ?? current.time,
                playing: next.playing ?? current.playing,
                volume: next.volume ?? current.volume,
                updatedAt: Date.now(),
            };
            localStorage.setItem(INTRO_STATE_KEY, JSON.stringify(merged));
            localStorage.setItem(INTRO_VOLUME_KEY, String(merged.volume));
            return merged;
        }

        const initialState = readState();
        const shouldAttemptInitialAutoplay = !sessionStorage.getItem('bellatorInitialAutoplayAttempted');
        if (shouldAttemptInitialAutoplay) {
            sessionStorage.setItem('bellatorInitialAutoplayAttempted', 'true');
        }

        audio.volume = Math.min(Math.max(initialState.volume, 0.05), 0.35);

        // Cross-tab isolation — evita que varias pestañas reproduzcan a la vez
        const TAB_ID = sessionStorage.getItem('blTabId') || (() => {
            const id = Math.random().toString(36).slice(2, 10);
            sessionStorage.setItem('blTabId', id);
            return id;
        })();
        const ACTIVE_TAB_KEY = 'bellatorAudioActiveTab';
        const isAnotherTabActive = () => { const t = localStorage.getItem(ACTIVE_TAB_KEY); return !!(t && t !== TAB_ID); };
        const claimTab  = () => localStorage.setItem(ACTIVE_TAB_KEY, TAB_ID);
        const releaseTab = () => { if (localStorage.getItem(ACTIVE_TAB_KEY) === TAB_ID) localStorage.removeItem(ACTIVE_TAB_KEY); };

        let currentTrack = initialState.track; // 'intro' | 'goth'
        let pendingAutoplay = false;
        let lastKnownTime = Math.max(0, initialState.time || 0);

        const setIcon = (playing) => { toggle.innerHTML = playing ? ICON_PAUSE : ICON_PLAY; };
        const setLabel = () => { if (labelEl) labelEl.textContent = currentTrack === 'goth' ? 'B · GOTH' : 'B · INTRO'; };
        const sourceForTrack = (track) => track === 'goth' ? '/audio/goth-slowed.mp3' : '/audio/bellator-intro.mp3';

        function loadTrack(track) {
            currentTrack = track === 'goth' ? 'goth' : 'intro';
            setLabel();
            const nextSrc = sourceForTrack(currentTrack);
            if (!audio.src || !audio.src.endsWith(nextSrc)) {
                audio.src = nextSrc;
                audio.load();
            }
        }

        function getResumeTime() {
            const state = readState();
            const stateTime = state.track === currentTrack ? Number(state.time) || 0 : 0;
            const trackTimes = readTrackTimes();
            const trackTime = Number(trackTimes[currentTrack]) || 0;
            return Math.max(stateTime, trackTime, lastKnownTime, _pendingSavedTime || 0);
        }

        function restoreTimeBeforePlay() {
            const resumeTime = getResumeTime();
            if (!(resumeTime > 0)) return;
            if (audio.duration && resumeTime >= audio.duration - 0.25) return;
            try {
                audio.currentTime = resumeTime;
                lastKnownTime = resumeTime;
                _pendingSavedTime = resumeTime;
            } catch (_) {}
        }

        function ensureMediaReady() {
            if (audio.readyState >= 1) {
                return Promise.resolve();
            }
            return new Promise((resolve) => {
                let done = false;
                const finish = () => {
                    if (done) return;
                    done = true;
                    audio.removeEventListener('loadedmetadata', finish);
                    audio.removeEventListener('canplay', finish);
                    resolve();
                };
                audio.addEventListener('loadedmetadata', finish, { once: true });
                audio.addEventListener('canplay', finish, { once: true });
                setTimeout(finish, 1200);
            });
        }

        async function resumePlayback() {
            localStorage.setItem(INTRO_ALLOWED_KEY, 'true');
            await ensureMediaReady();
            restoreTimeBeforePlay();
            _wantsPlay = false;
            claimTab();
            await audio.play();
            _pendingSavedTime = 0;
            setIcon(true);
            persistState();
        }

        async function attemptAutoplay() {
            try {
                await ensureMediaReady();
                restoreTimeBeforePlay();
                claimTab();
                await audio.play();
                _wantsPlay = false;
                _pendingSavedTime = 0;
                setIcon(true);
                persistState();
            } catch (_) {
                _wantsPlay = true;
                setIcon(false);
            }
        }

        const persistState = () => {
            const currentTime = Number(audio.currentTime) || 0;
            if (currentTime > 0) {
                lastKnownTime = currentTime;
            }
            const effectiveTime = Math.max(currentTime, lastKnownTime, _pendingSavedTime || 0);
            writeTrackTime(currentTrack, effectiveTime);
            writeState({
                track: currentTrack,
                time: effectiveTime,
                playing: !audio.paused && !audio.ended,
                volume: audio.volume,
            });
        };

        function playGoth() {
            pendingAutoplay = true;
            lastKnownTime = 0;
            writeState({track: 'goth', time: 0, playing: true, volume: audio.volume});
            loadTrack('goth');
        }

        function playIntro() {
            pendingAutoplay = true;
            lastKnownTime = 0;
            writeState({track: 'intro', time: 0, playing: true, volume: audio.volume});
            loadTrack('intro');
        }

        let _wantsPlay = false;
        let _pendingSavedTime = 0;

        // Primera interacción del usuario → reanuda desde la posición correcta
        // IMPORTANTE: ignorar clics sobre el toggle (ese handler lo gestiona él mismo)
        function tryResumeOnInteraction(e) {
            if (!_wantsPlay || !audio.paused) return;
            if (e && e.target && (e.target === toggle || toggle.contains(e.target))) return;
            _wantsPlay = false;
            resumePlayback().catch(() => { setIcon(false); });
        }
        ['click','keydown','touchstart'].forEach(ev =>
            document.addEventListener(ev, tryResumeOnInteraction, { once: false, capture: true })
        );

        audio.addEventListener('loadedmetadata', () => {
            const state = readState();
            const savedTime = state.track === currentTrack ? state.time : 0;
            _pendingSavedTime = (Number.isFinite(savedTime) && savedTime > 1) ? savedTime : 0;
            if (_pendingSavedTime > 0) {
                lastKnownTime = _pendingSavedTime;
            }
            // Restaurar posición ANTES de intentar play
            restoreTimeBeforePlay();
            const shouldResume = shouldAttemptInitialAutoplay || pendingAutoplay || state.playing || localStorage.getItem(INTRO_ALLOWED_KEY) === 'true';
            pendingAutoplay = false;
            if (shouldResume && !isAnotherTabActive()) {
                attemptAutoplay();
            } else {
                setIcon(false);
            }
        });

        toggle.addEventListener('click', async () => {
            try {
                if (audio.paused || audio.ended) {
                    await resumePlayback();
                } else {
                    audio.pause();
                    setIcon(false);
                    persistState();
                }
            } catch (_) { setIcon(false); }
        });

        closeBtn.addEventListener('click', () => {
            audio.pause();
            persistState();
            widget.style.display = 'none';
        });

        audio.addEventListener('play',  () => { claimTab(); setIcon(true);  persistState(); });
        audio.addEventListener('pause', () => { releaseTab(); setIcon(false); persistState(); });
        audio.addEventListener('timeupdate', () => {
            const currentTime = Number(audio.currentTime) || 0;
            if (currentTime > 0) {
                lastKnownTime = currentTime;
                writeTrackTime(currentTrack, currentTime);
            }
            persistState();
        });
        audio.addEventListener('ended', () => {
            if (currentTrack === 'intro') {
                playGoth();
            } else {
                playIntro();
            }
        });

        window.addEventListener('storage', (event) => {
            if (event.key !== INTRO_STATE_KEY) return;
            const next = readState();
            if (next.track !== currentTrack && audio.paused) loadTrack(next.track);
            if (audio.paused) setIcon(false);
        });

        loadTrack(currentTrack);
        setLabel();
        if (!initialState.playing) setIcon(false);

        window.addEventListener('pageshow', () => {
            if (audio.paused && !isAnotherTabActive()) {
                attemptAutoplay();
            }
        });

        // Guardar posición cada 500ms como respaldo (por si beforeunload no dispara)
        setInterval(() => { if (!audio.paused) persistState(); }, 500);
        // Guardar cuando la pestaña se oculta (navegación SPA, cambio de tab)
        document.addEventListener('visibilitychange', () => { if (document.hidden) persistState(); });
        window.addEventListener('pagehide', persistState);
        window.addEventListener('beforeunload', () => { persistState(); releaseTab(); });
    }

    initSharedIntroWidget();

    // ── Shared Piper TTS client ──
    window.BellatorTTS = (function() {
        const VOICE_KEY = 'bellatorPiperVoice';
        const LEGACY_VOICE_KEY = 'es_MX-claude-high';
        const blobCache = new Map();
        const blobPromiseCache = new Map();
        let voicesPromise = null;
        let currentRequest = null;
        let audioEl = null;

        function ensureAudio() {
            if (audioEl) return audioEl;
            audioEl = new Audio();
            audioEl.preload = 'auto';
            return audioEl;
        }

        function getStoredVoice() {
            return localStorage.getItem(VOICE_KEY) || '';
        }

        function setStoredVoice(voiceID) {
            if (!voiceID) return;
            localStorage.setItem(VOICE_KEY, voiceID);
            syncVoiceSelects();
        }

        function buildCacheKey(voiceID, text) {
            return String(voiceID || '') + '::' + String(text || '').trim();
        }

        function storeBlob(cacheKey, blob) {
            if (!cacheKey || !blob) return;
            if (blobCache.has(cacheKey)) blobCache.delete(cacheKey);
            blobCache.set(cacheKey, blob);
            while (blobCache.size > 24) {
                const oldestKey = blobCache.keys().next().value;
                blobCache.delete(oldestKey);
            }
        }

        function loadVoices() {
            if (!voicesPromise) {
                voicesPromise = fetch('/api/tts/voices', {cache: 'no-store'})
                    .then(function(res) {
                        if (!res.ok) throw new Error('No se pudo cargar Piper');
                        return res.json();
                    })
                    .then(function(data) {
                        data = data || {};
                        data.voices = Array.isArray(data.voices) ? data.voices : [];
                        data.defaultVoice = data.defaultVoice || (data.voices[0] && data.voices[0].id) || '';
                        const storedVoice = getStoredVoice();
                        const preferredStoredVoice = storedVoice === LEGACY_VOICE_KEY && data.defaultVoice && data.defaultVoice !== LEGACY_VOICE_KEY
                            ? data.defaultVoice
                            : storedVoice;
                        const activeVoice = resolveVoice(data, preferredStoredVoice);
                        if (activeVoice) setStoredVoice(activeVoice);
                        return data;
                    })
                    .catch(function() {
                        return { enabled: false, defaultVoice: '', voices: [] };
                    });
            }
            return voicesPromise;
        }

        function resolveVoice(data, requestedVoice) {
            const voices = (data && data.voices) || [];
            if (!voices.length) return '';
            if (requestedVoice && voices.some(function(voice) { return voice.id === requestedVoice; })) {
                return requestedVoice;
            }
            return data.defaultVoice || voices[0].id || '';
        }

        function renderVoiceSelect(select, data) {
            if (!select) return;
            const activeVoice = resolveVoice(data, getStoredVoice());
            if (!data.enabled || !data.voices.length) {
                select.innerHTML = '<option value="">PIPER NO DISPONIBLE</option>';
                select.disabled = true;
                return;
            }
            select.innerHTML = data.voices.map(function(voice) {
                return '<option value="' + voice.id + '">' + voice.label + '</option>';
            }).join('');
            select.disabled = false;
            select.value = activeVoice;
        }

        function syncVoiceSelects() {
            loadVoices().then(function(data) {
                document.querySelectorAll('[data-tts-voice-select]').forEach(function(select) {
                    renderVoiceSelect(select, data);
                });
            });
        }

        function populateSelect(select) {
            if (!select) return Promise.resolve();
            if (!select.dataset.ttsBound) {
                select.dataset.ttsBound = '1';
                select.addEventListener('change', function() {
                    setStoredVoice(select.value);
                });
            }
            return loadVoices().then(function(data) {
                renderVoiceSelect(select, data);
            });
        }

        async function fetchSpeechBlob(text, options) {
            const data = await loadVoices();
            if (!data.enabled || !data.voices.length) {
                throw new Error('Piper no está disponible en este momento.');
            }

            const voiceID = resolveVoice(data, (options && options.voice) || getStoredVoice());
            const cacheKey = buildCacheKey(voiceID, text);
            if (blobCache.has(cacheKey)) {
                return { blob: blobCache.get(cacheKey), voiceID: voiceID, cacheKey: cacheKey };
            }
            if (!blobPromiseCache.has(cacheKey)) {
                const fetchPromise = fetch('/api/tts/speak', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    cache: 'force-cache',
                    body: JSON.stringify({ text: text, voice: voiceID }),
                })
                    .then(async function(response) {
                        if (!response.ok) {
                            const message = await response.text();
                            throw new Error(message || 'No se pudo generar el audio.');
                        }
                        const resolvedVoice = response.headers.get('X-TTS-Voice') || voiceID;
                        const blob = await response.blob();
                        const resolvedKey = buildCacheKey(resolvedVoice, text);
                        storeBlob(resolvedKey, blob);
                        if (resolvedVoice !== voiceID) storeBlob(cacheKey, blob);
                        return { blob: blob, voiceID: resolvedVoice, cacheKey: resolvedKey };
                    })
                    .finally(function() {
                        blobPromiseCache.delete(cacheKey);
                    });
                blobPromiseCache.set(cacheKey, fetchPromise);
            }
            return blobPromiseCache.get(cacheKey);
        }

        function finishRequest(request, kind, message) {
            if (!request || currentRequest !== request) return;
            const audio = ensureAudio();
            currentRequest = null;
            audio.onended = null;
            audio.onerror = null;
            if (!audio.paused) audio.pause();
            audio.removeAttribute('src');
            audio.load();
            if (request.url) URL.revokeObjectURL(request.url);
            if (kind === 'error') {
                if (typeof request.onError === 'function') request.onError(message || 'No se pudo generar el audio.');
                return;
            }
            if (typeof request.onEnd === 'function') request.onEnd();
        }

        function stop() {
            if (!currentRequest) return;
            const request = currentRequest;
            if (request.controller) request.controller.abort();
            finishRequest(request, 'end');
        }

        async function speak(text, options) {
            const content = String(text || '').trim();
            if (!content) return false;

            stop();

            const request = {
                controller: new AbortController(),
                onEnd: options && options.onEnd,
                onError: options && options.onError,
                url: '',
            };
            currentRequest = request;
            if (options && typeof options.onStart === 'function') options.onStart();

            try {
                if (request.controller.signal.aborted) return false;
                const result = await fetchSpeechBlob(content, { voice: options && options.voice });
                if (currentRequest !== request) return false;
                if (result.voiceID) setStoredVoice(result.voiceID);
                request.url = URL.createObjectURL(result.blob);
                const audio = ensureAudio();
                audio.src = request.url;
                audio.onended = function() { finishRequest(request, 'end'); };
                audio.onerror = function() { finishRequest(request, 'error', 'No se pudo reproducir el audio.'); };
                await audio.play();
                if (options && typeof options.onPlay === 'function') options.onPlay();
                return true;
            } catch (error) {
                if (error && error.name === 'AbortError') return false;
                finishRequest(request, 'error', error && error.message ? error.message : 'No se pudo generar el audio.');
                return false;
            }
        }

        function prewarm(text, options) {
            const content = String(text || '').trim();
            if (!content) return Promise.resolve(false);
            return fetchSpeechBlob(content, { voice: options && options.voice })
                .then(function() { return true; })
                .catch(function() { return false; });
        }

        document.addEventListener('DOMContentLoaded', syncVoiceSelects);
        syncVoiceSelects();

        return {
            loadVoices: loadVoices,
            populateSelect: populateSelect,
            speak: speak,
            prewarm: prewarm,
            stop: stop,
            isSpeaking: function() { return !!currentRequest; },
            getVoice: getStoredVoice,
            setVoice: setStoredVoice,
        };
    })();

    // ── Common UI: hamburger & clock ──
    document.getElementById('bl-burger')?.addEventListener('click', () => {
        document.getElementById('bl-links')?.classList.toggle('open');
    });
    (function clock() {
        const el = document.getElementById('bl-clock');
        if (!el) return;
        function tick() {
            el.textContent = new Date().toLocaleTimeString('es-CO', {timeZone:'America/Bogota', hour12:false});
        }
        tick(); setInterval(tick, 1000);
    })();

    // ── Active nav link ──
    const path = window.location.pathname.replace(/\/$/, '') || '/';
    document.querySelectorAll('.bl-navlink, .bl-navbar-links a').forEach(el => {
        const href = el.getAttribute('href') || '';
        const hpath = href.replace(/\/$/, '') || '/';
        if (hpath === path) el.classList.add('active');
    });

    // ── CURSOR SVG follow ──
    if (window.innerWidth >= 768) {
        const cursor = document.getElementById('cursor');
        if (cursor) {
            let tx = window.innerWidth / 2, ty = window.innerHeight / 2;
            let cx = tx, cy = ty;
            function onCursorMove(e) {
                tx = e.touches ? e.touches[0].clientX : e.clientX;
                ty = e.touches ? e.touches[0].clientY : e.clientY;
            }
            document.addEventListener('pointermove', onCursorMove, {passive:true});
            document.querySelectorAll('a,button,.btn').forEach(el => {
                el.addEventListener('mouseenter', () => cursor.classList.add('hot'));
                el.addEventListener('mouseleave', () => cursor.classList.remove('hot'));
            });
            (function anim() {
                cx += (tx - cx) * 0.34;
                cy += (ty - cy) * 0.34;
                cursor.style.left = cx + 'px';
                cursor.style.top = cy + 'px';
                requestAnimationFrame(anim);
            })();
        }
    }
})();

// ════════════════════════════════════════ ESPACIO ════════════════════
(function() {
    const canvas = document.getElementById('space');
    if (!canvas) return;
    const ctx = canvas.getContext('2d', {alpha:true});
    const isMobile = window.innerWidth < 768;
    const isTouchDevice = (window.matchMedia && window.matchMedia('(hover:none), (pointer:coarse)').matches) || navigator.maxTouchPoints > 0;
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let width=0, height=0, dpr=1;
    const farCount = isTouchDevice ? 72 : (isMobile ? 120 : 320);
    const nearCount = isTouchDevice ? 32 : (isMobile ? 60 : 160);
    const starsFar=[], starsNear=[], nebula=[];

    function resize() {
        width = Math.max(1, Math.floor(window.innerWidth));
        height = Math.max(1, Math.floor(window.innerHeight));
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
        canvas.style.width = width + 'px';
        canvas.style.height = height + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    function rand(a, b) { return Math.random() * (b - a) + a; }

    function init() {
        starsFar.length = starsNear.length = nebula.length = 0;
        for (let i = 0; i < farCount; i++) starsFar.push({x:Math.random()*width,y:Math.random()*height,r:rand(.6,1.2),a:rand(.18,.55),s:rand(.08,.20)});
        for (let i = 0; i < nearCount; i++) starsNear.push({x:Math.random()*width,y:Math.random()*height,r:rand(.9,1.9),a:rand(.25,.85),s:rand(.22,.55)});
        // NEBULAS: AZUL + DORADO (no purple/pink)
        const nebulaColors = [
            {h:220,s:78,l:38}, // Azul profundo
            {h:45, s:88,l:48}, // Dorado ámbar
            {h:210,s:72,l:32}, // Azul marino
            {h:50, s:92,l:52}, // Dorado brillante
            {h:230,s:68,l:40}, // Azul cobalto
            {h:42, s:85,l:45}  // Dorado oscuro
        ];
        const count = isMobile ? 3 : 6;
        for (let i = 0; i < count; i++) {
            const c = nebulaColors[i % nebulaColors.length];
            nebula.push({
                x: rand(width*.1, width*.9), y: rand(height*.1, height*.9),
                r: rand(Math.min(width,height)*.45, Math.min(width,height)*.85),
                hue:c.h, sat:c.s, light:c.l, a:rand(.15,.26), drift:rand(.004,.012)
            });
        }
    }

    function drawBackground() {
        const g = ctx.createRadialGradient(width*.5,height*.45,0,width*.5,height*.45,Math.max(width,height));
        g.addColorStop(0,'rgba(8,20,36,1)');
        g.addColorStop(.3,'rgba(4,10,20,1)');
        g.addColorStop(.6,'rgba(2,5,12,1)');
        g.addColorStop(1,'rgba(0,0,0,1)');
        ctx.fillStyle=g; ctx.fillRect(0,0,width,height);
    }
    function drawNebula(t) {
        for (const n of nebula) {
            const x = n.x + Math.sin(t*.0004)*(width*.02);
            const y = n.y + Math.cos(t*.00035)*(height*.02);
            const g = ctx.createRadialGradient(x,y,0,x,y,n.r);
            g.addColorStop(0, `hsla(${n.hue},${n.sat}%,${n.light}%,${n.a})`);
            g.addColorStop(.4,`hsla(${n.hue},${n.sat-10}%,${n.light-10}%,${n.a*.6})`);
            g.addColorStop(.7,`hsla(${n.hue},${n.sat-20}%,${n.light-20}%,${n.a*.28})`);
            g.addColorStop(1,'rgba(0,0,0,0)');
            ctx.fillStyle=g; ctx.fillRect(0,0,width,height);
        }
    }
    function drawStars(stars, t, spd) {
        for (const s of stars) {
            const tw = .65 + .35*Math.sin(t*.001+(s.x+s.y)*.01);
            ctx.fillStyle = `rgba(255,255,255,${s.a*tw})`;
            ctx.beginPath(); ctx.arc(s.x,s.y,s.r,0,Math.PI*2); ctx.fill();
            s.y += s.s * spd;
            if (s.y > height+2) { s.y=-2; s.x=Math.random()*width; }
        }
    }
    const fps = reduceMotion ? 1 : (isMobile ? 30 : 60);
    const step = 1000/fps;
    let last=0, acc=0;
    function frame(t) {
        if (reduceMotion) { drawBackground(); drawNebula(t); drawStars(starsFar,t,0); drawStars(starsNear,t,0); return; }
        if (!last) last=t;
        const dt=t-last; last=t; acc+=dt;
        if (acc>=step) {
            acc=acc%step;
            drawBackground(); drawNebula(t);
            drawStars(starsFar,t,.65); drawStars(starsNear,t,1.35);
        }
        requestAnimationFrame(frame);
    }
    resize(); init();
    reduceMotion ? frame(performance.now()) : requestAnimationFrame(frame);
    window.addEventListener('resize',()=>{resize();init()},{passive:true});
})();

// ════════════════════════════════════════ CONSTELACIONES ════════════════
(function() {
    const canvas = document.getElementById('constellations');
    if (!canvas) return;
    const isTouchDevice = (window.matchMedia && window.matchMedia('(hover:none), (pointer:coarse)').matches) || navigator.maxTouchPoints > 0;
    const ctx = canvas.getContext('2d', {alpha:true, desynchronized:true});
    if (!ctx) return;
    const isMobile = window.innerWidth < 768;
    let width=0, height=0, dpr=1;
    const nodeCount = isTouchDevice ? 18 : (isMobile ? 35 : 55);
    const linkDist  = isTouchDevice ? 112 : (isMobile ? 130 : 160);
    const ptrRadius = isTouchDevice ? 180 : (isMobile ? 220 : 280);
    const speedMult = isTouchDevice ? 1.12 : (isMobile ? 1.15 : 1.12);
    const maxSpeed  = isTouchDevice ? 2.9 : (isMobile ? 3.2 : 3.45);
    const nodes=[], pointer={x:0,y:0,tx:0,ty:0,speed:0,active:false};

    function resize() {
        width=Math.max(1,Math.floor(window.innerWidth));
        height=Math.max(1,Math.floor(window.innerHeight));
        dpr=Math.min(window.devicePixelRatio||1,2);
        canvas.width=Math.floor(width*dpr); canvas.height=Math.floor(height*dpr);
        canvas.style.width=width+'px'; canvas.style.height=height+'px';
        ctx.setTransform(dpr,0,0,dpr,0,0);
    }
    function rand(a,b){return a+Math.random()*(b-a)}
    function spawn() {
        nodes.length=0;
        const shapes=['circle','triangle','square'];
        for (let i=0;i<nodeCount;i++) {
            const ox=Math.random()*width, oy=Math.random()*height;
            const angle=Math.random()*Math.PI*2;
            nodes.push({x:ox,y:oy,ox,oy,wx:ox+rand(-80,80),wy:oy+rand(-80,80),
                vx:Math.cos(angle)*rand(.7,1.45),vy:Math.sin(angle)*rand(.7,1.45),
                r:rand(1.8,2.5),pulse:rand(0,Math.PI*2),
                shape:shapes[Math.floor(Math.random()*3)],wanderTimer:Math.floor(rand(0,120))
            });
        }
    }
    function readPtr(e) {
        pointer.tx = e.touches ? e.touches[0].clientX : e.clientX;
        pointer.ty = e.touches ? e.touches[0].clientY : e.clientY;
        if (!pointer.active) { pointer.x=pointer.tx; pointer.y=pointer.ty; }
        pointer.active=true;
    }
    function stopPtr(){pointer.active=false;pointer.speed=0}
    ['pointermove','pointerdown'].forEach(ev=>document.addEventListener(ev,readPtr,{passive:true}));
    ['pointerup','pointerleave'].forEach(ev=>document.addEventListener(ev,stopPtr,{passive:true}));

    function updateNodes() {
        const px=pointer.tx-pointer.x, py=pointer.ty-pointer.y;
        pointer.speed=Math.hypot(px,py);
        pointer.x+=px*.3; pointer.y+=py*.3;
        for (const n of nodes) {
            n.wanderTimer++;
            if (n.wanderTimer>90){n.wanderTimer=0;n.wx=n.ox+rand(-100,100);n.wy=n.oy+rand(-100,100)}
            const dxW=n.wx-n.x,dyW=n.wy-n.y,dW=Math.hypot(dxW,dyW);
            if (dW>5){n.vx+=(dxW/dW)*.055;n.vy+=(dyW/dW)*.055}
            const dxH=n.ox-n.x,dyH=n.oy-n.y,dH=Math.hypot(dxH,dyH);
            if (dH>120){n.vx+=(dxH/dH)*.085;n.vy+=(dyH/dH)*.085}
            const dx=pointer.x-n.x,dy=pointer.y-n.y,dP=Math.hypot(dx,dy);
            if (pointer.active&&dP<ptrRadius){const f=(1-dP/ptrRadius)*.68;n.vx+=(dx/dP)*f;n.vy+=(dy/dP)*f}
            n.x+=n.vx*speedMult; n.y+=n.vy*speedMult; n.vx*=.965; n.vy*=.965;
            const sp=Math.hypot(n.vx,n.vy);
            if (sp>maxSpeed){n.vx=(n.vx/sp)*maxSpeed;n.vy=(n.vy/sp)*maxSpeed}
            if (n.x<0||n.x>width){n.vx*=-.8;n.x=Math.max(0,Math.min(width,n.x))}
            if (n.y<0||n.y>height){n.vy*=-.8;n.y=Math.max(0,Math.min(height,n.y))}
        }
    }
    function drawLinks() {
        const bd=linkDist+(pointer.active?36:0), ld2=bd*bd;
        for (let i=0;i<nodes.length;i++) {
            const a=nodes[i];
            for (let j=i+1;j<nodes.length;j++) {
                const b=nodes[j];
                const dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy;
                if (d2>ld2) continue;
                const d=Math.sqrt(d2);
                let alpha=Math.max(0,1-d/bd)*.30;
                if (pointer.active) {
                    const mx=(a.x+b.x)*.5-pointer.x,my=(a.y+b.y)*.5-pointer.y,pd=Math.hypot(mx,my);
                    if (pd<ptrRadius) alpha+=((1-pd/ptrRadius))*.95;
                }
                alpha=Math.min(1,Math.max(0,alpha));
                // AZUL + DORADO
                const lineColors=[
                    `rgba(80,160,255,${.55*alpha})`,
                    `rgba(212,175,55,${.55*alpha})`,
                    `rgba(100,190,255,${.55*alpha})`,
                    `rgba(240,192,64,${.55*alpha})`
                ];
                ctx.strokeStyle=lineColors[(Math.floor(a.x+a.y+b.x+b.y)%4)];
                ctx.lineWidth=1.2;
                ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
            }
        }
    }
    function drawNodes(t) {
        for (const n of nodes) {
            const glow=.5+.5*Math.sin(t*.003+n.pulse);
            const size=n.r*2.2;
            // AZUL (circle) + DORADO (triangle, square)
            let neonColor,neonGlow;
            if (n.shape==='circle') {
                neonColor=`rgba(80,160,255,${.85+glow*.15})`;
                neonGlow =`rgba(80,160,255,${.12+glow*.08})`;
            } else if (n.shape==='triangle') {
                neonColor=`rgba(212,175,55,${.85+glow*.15})`;
                neonGlow =`rgba(212,175,55,${.12+glow*.08})`;
            } else {
                neonColor=`rgba(240,192,64,${.85+glow*.15})`;
                neonGlow =`rgba(240,192,64,${.12+glow*.08})`;
            }
            ctx.fillStyle=neonGlow;
            ctx.beginPath(); ctx.arc(n.x,n.y,size*1.8,0,Math.PI*2); ctx.fill();
            ctx.fillStyle=neonColor; ctx.strokeStyle=neonColor; ctx.lineWidth=1.8;
            ctx.beginPath();
            if (n.shape==='circle') {
                ctx.arc(n.x,n.y,size*.4,0,Math.PI*2);
            } else if (n.shape==='triangle') {
                ctx.moveTo(n.x,n.y-size*.5);
                ctx.lineTo(n.x+size*.43,n.y+size*.25);
                ctx.lineTo(n.x-size*.43,n.y+size*.25);
                ctx.closePath();
            } else {
                const h=size*.4; ctx.rect(n.x-h,n.y-h,size*.8,size*.8);
            }
            ctx.fill(); ctx.stroke();
        }
    }
    function drawPtrGlow() {
        if (!pointer.active) return;
        const r=ptrRadius*.6;
        const g=ctx.createRadialGradient(pointer.x,pointer.y,0,pointer.x,pointer.y,r);
        // DORADO → AZUL glow
        g.addColorStop(0,'rgba(212,175,55,.28)');
        g.addColorStop(.4,'rgba(31,111,235,.16)');
        g.addColorStop(1,'rgba(0,60,180,0)');
        ctx.fillStyle=g; ctx.beginPath(); ctx.arc(pointer.x,pointer.y,r,0,Math.PI*2); ctx.fill();
    }
    function frame(t) {
        ctx.clearRect(0,0,width,height);
        updateNodes(); drawLinks(); drawNodes(t); drawPtrGlow();
        requestAnimationFrame(frame);
    }
    resize(); spawn();
    requestAnimationFrame(frame);
    window.addEventListener('resize',()=>{resize();spawn()},{passive:true});
})();

// ════════════════════════════════════════ CURSOR + CHISPAS ═══════════
(function() {
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const isTouchDevice = (window.matchMedia && window.matchMedia('(hover:none), (pointer:coarse)').matches) || navigator.maxTouchPoints > 0;
    const fx = document.getElementById('fx');
    if (!fx || reduceMotion || isTouchDevice) return;
    const ctx = fx.getContext('2d',{alpha:true,desynchronized:true});
    if (!ctx) return;
    const isMobile = window.innerWidth < 768;
    let W=0,H=0,DPR=1;
    function resizeFx() {
        DPR=Math.max(1,Math.min(2,window.devicePixelRatio||1));
        W=Math.floor(window.innerWidth); H=Math.floor(window.innerHeight);
        fx.width=Math.floor(W*DPR); fx.height=Math.floor(H*DPR);
        fx.style.width=W+'px'; fx.style.height=H+'px';
        ctx.setTransform(DPR,0,0,DPR,0,0);
    }
    resizeFx();
    window.addEventListener('resize',resizeFx,{passive:true});
    const maxP=isMobile?140:260, particles=[];
    function rand(a,b){return a+Math.random()*(b-a)}
    function clamp(v,a,b){return Math.max(a,Math.min(b,v))}
    function spawnSparks(x,y,vx,vy,intensity) {
        const speed=Math.hypot(vx,vy);
        const count=Math.floor(clamp(intensity*12+speed*.08,4,isMobile?12:18));
        for(let i=0;i<count;i++) {
            if (particles.length>=maxP) particles.shift();
            const angle=Math.atan2(vy,vx)+rand(-1.2,1.2);
            const mag=rand(1.2,4.2)+speed*.02;
            const col=Math.random()<.25?'255,240,200':(Math.random()<.6?'255,160,0':'255,40,0');
            particles.push({x:x+rand(-2,2),y:y+rand(-2,2),px:x,py:y,vx:Math.cos(angle)*mag,vy:Math.sin(angle)*mag,life:0,ttl:rand(220,520),size:rand(1,2.2),col});
        }
    }
    function burst(x,y){for(let i=0;i<(isMobile?18:28);i++) spawnSparks(x,y,rand(-40,40),rand(-40,40),1.4)}
    let lx=0,ly=0,lt=0,hasLast=false;
    function getXY(e){if(e.touches&&e.touches.length)return{x:e.touches[0].clientX,y:e.touches[0].clientY};if(e.changedTouches&&e.changedTouches.length)return{x:e.changedTouches[0].clientX,y:e.changedTouches[0].clientY};return{x:e.clientX,y:e.clientY}}
    function onMove(e){
        const p=getXY(e),now=performance.now();
        if(!hasLast){lx=p.x;ly=p.y;lt=now;hasLast=true;return}
        const dt=Math.max(8,now-lt);
        const vx=(p.x-lx)/dt*16,vy=(p.y-ly)/dt*16,speed=Math.hypot(vx,vy);
        if(speed>6) spawnSparks(p.x,p.y,vx,vy,clamp(speed/30,.4,2.2));
        lx=p.x;ly=p.y;lt=now;
    }
    if('PointerEvent' in window){document.addEventListener('pointermove',onMove,{passive:true});document.addEventListener('pointerdown',e=>burst(getXY(e).x,getXY(e).y),{passive:true});}
    else{document.addEventListener('mousemove',onMove,{passive:true});document.addEventListener('mousedown',e=>burst(e.clientX,e.clientY),{passive:true});}
    function step() {
        ctx.clearRect(0,0,W,H);
        for(let i=particles.length-1;i>=0;i--) {
            const s=particles[i]; s.life+=16;
            const a=1-s.life/s.ttl;
            if(a<=0){particles.splice(i,1);continue}
            s.px=s.x;s.py=s.y;s.x+=s.vx;s.y+=s.vy;s.vx*=.88;s.vy*=.88;s.vy+=.18;
            ctx.lineWidth=s.size; ctx.strokeStyle=`rgba(${s.col},${a})`;
            ctx.beginPath(); ctx.moveTo(s.px,s.py); ctx.lineTo(s.x,s.y); ctx.stroke();
        }
        requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
})();

// ── COUNTRY SELECTOR (registro.html) ─────────────────────────────────────
(function initCountrySelector() {
    const btn      = document.getElementById('bl-country-btn');
    const dropdown = document.getElementById('bl-country-dropdown');
    const search   = document.getElementById('bl-country-search');
    const listEl   = document.getElementById('bl-country-list');
    const preview  = document.getElementById('bl-flag-preview');
    const label    = document.getElementById('bl-country-label');
    const hidden   = document.getElementById('b-country-code');
    if (!btn || !dropdown || !listEl) return;

    const COUNTRIES = [
        {c:'co',n:'Colombia'},{c:'mx',n:'México'},{c:'ar',n:'Argentina'},
        {c:'es',n:'España'},{c:'ve',n:'Venezuela'},{c:'pe',n:'Perú'},
        {c:'cl',n:'Chile'},{c:'ec',n:'Ecuador'},{c:'bo',n:'Bolivia'},
        {c:'py',n:'Paraguay'},{c:'uy',n:'Uruguay'},{c:'cr',n:'Costa Rica'},
        {c:'pa',n:'Panamá'},{c:'gt',n:'Guatemala'},{c:'hn',n:'Honduras'},
        {c:'sv',n:'El Salvador'},{c:'ni',n:'Nicaragua'},{c:'do',n:'Rep. Dominicana'},
        {c:'cu',n:'Cuba'},{c:'pr',n:'Puerto Rico'},{c:'us',n:'Estados Unidos'},
        {c:'ca',n:'Canadá'},{c:'br',n:'Brasil'},{c:'pt',n:'Portugal'},
        {c:'fr',n:'Francia'},{c:'de',n:'Alemania'},{c:'it',n:'Italia'},
        {c:'gb',n:'Reino Unido'},{c:'ru',n:'Rusia'},{c:'jp',n:'Japón'},
        {c:'kr',n:'Corea del Sur'},{c:'cn',n:'China'},{c:'au',n:'Australia'},
        {c:'mx',n:'México'},{c:'ph',n:'Filipinas'},{c:'tr',n:'Turquía'},
        {c:'ng',n:'Nigeria'},{c:'za',n:'Sudáfrica'},{c:'eg',n:'Egipto'},
        {c:'ma',n:'Marruecos'},{c:'gh',n:'Ghana'},{c:'ke',n:'Kenia'},
    ].filter((v,i,a) => a.findIndex(x=>x.c===v.c)===i); // deduplicate

    function renderList(filter) {
        const q = (filter || '').toLowerCase();
        const items = COUNTRIES.filter(c => !q || c.n.toLowerCase().includes(q) || c.c.includes(q));
        listEl.innerHTML = items.map(c =>
            `<div class="bl-country-item" data-code="${c.c}" data-name="${c.n}">` +
            `<span class="fi fi-${c.c}" style="width:20px;height:14px;border-radius:2px;flex-shrink:0"></span>` +
            `<span>${c.n}</span></div>`
        ).join('') || '<div style="padding:10px 14px;color:var(--bl-muted);font-size:.85rem">Sin resultados</div>';
    }

    function openDropdown() {
        dropdown.style.display = 'block';
        search.value = '';
        renderList('');
        search.focus();
    }
    function closeDropdown() { dropdown.style.display = 'none'; }

    btn.addEventListener('click', function(e) {
        e.stopPropagation();
        dropdown.style.display === 'none' ? openDropdown() : closeDropdown();
    });
    search.addEventListener('input', function() { renderList(this.value); });
    listEl.addEventListener('click', function(e) {
        const item = e.target.closest('.bl-country-item');
        if (!item) return;
        const code = item.dataset.code;
        const name = item.dataset.name;
        if (preview) { preview.className = `fi fi-${code}`; preview.style.cssText = 'width:22px;height:16px;border-radius:3px;flex-shrink:0'; }
        if (label) label.textContent = name;
        if (hidden) hidden.value = code;
        closeDropdown();
    });
    document.addEventListener('click', function(e) {
        if (!btn.contains(e.target) && !dropdown.contains(e.target)) closeDropdown();
    });

    renderList('');
})();
