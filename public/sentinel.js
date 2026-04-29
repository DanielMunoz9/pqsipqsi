(function(global) {
  'use strict';

  var BellatorCore = global.BellatorCore || {
    safe: function(_name, fn) {
      try { return fn(); } catch (_) { return null; }
    },
    safeWrap: function(_name, fn) {
      return function() {
        try { return fn.apply(this, arguments); } catch (_) { return null; }
      };
    }
  };

  if (global.BellatorSentinel && global.BellatorSentinel.__managed) return;

  function initSentinel() {
    var isTouchDevice = (global.matchMedia && global.matchMedia('(hover:none), (pointer:coarse)').matches) || navigator.maxTouchPoints > 0;
    if (isTouchDevice) return;

    var S0 = 'background:#0d1117;color:#d4af37;font-size:13px;font-weight:900;font-family:monospace;padding:3px 10px';
    var S1 = 'background:#0d1117;color:#ff3333;font-size:12px;font-family:monospace;padding:2px 10px';
    var S2 = 'background:#0d1117;color:#8b9298;font-size:11px;font-family:monospace;padding:1px 10px';
    var S3 = 'background:#0d1117;color:#00ff41;font-size:11px;font-family:monospace;padding:1px 10px';
    var S4 = 'background:#100000;color:#ff3333;font-size:17px;font-weight:900;font-family:monospace;padding:8px 18px;letter-spacing:2px';
    var S5 = 'background:#0d1117;color:#d4af37;font-size:20px;font-weight:900;font-family:monospace;padding:10px 20px;letter-spacing:5px';

    var fakeIP = (10 + Math.floor(Math.random() * 220)) + '.' + Math.floor(Math.random() * 254) + '.' + Math.floor(Math.random() * 254) + '.' + Math.floor(Math.random() * 254);
    var fakeHash = Math.random().toString(36).substr(2, 8).toUpperCase() + '-' + Math.random().toString(36).substr(2, 8).toUpperCase();
    var fakePort = [8443, 4444, 9001, 31337, 1337][Math.floor(Math.random() * 5)];

    global.setTimeout(BellatorCore.safeWrap('sentinel.banner', function() {
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

      console.log('%c' + '   領域展開', 'background:#0d1117;color:#7c3aed;font-size:28px;font-weight:900;font-family:serif;letter-spacing:12px;padding:8px 20px');
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

      global.setTimeout(BellatorCore.safeWrap('sentinel.netexec', function() {
        var NXC = 'background:#0d1117;color:#00ff41;font-size:11px;font-family:monospace;padding:1px 6px';
        var NXCR = 'background:#0d1117;color:#ff3333;font-size:11px;font-family:monospace;padding:1px 6px';
        var NXCG = 'background:#0d1117;color:#d4af37;font-size:11px;font-family:monospace;padding:1px 6px';
        var NXCB = 'background:#0d1117;color:#60a5fa;font-size:11px;font-family:monospace;padding:1px 6px';

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

        var fakeSubnet = fakeIP.split('.').slice(0, 3).join('.') + '.0/24';
        var fakeTarget = fakeIP;
        var fakeUser = ['admin', 'root', 'Administrator', 'guest', 'daniel'][Math.floor(Math.random() * 5)];
        var fakePass = ['Password1', '123456', 'admin', 'Bellator2026!', 'letmein'][Math.floor(Math.random() * 5)];

        var nxcLines = [
          { style: NXCB, text: 'root@kali:~# nxc smb ' + fakeSubnet + ' --gen-relay-list targets.txt' },
          { style: NXC, text: 'SMB    ' + fakeTarget + '  445  BELLATOR-SRV  [*] Windows 11 x64 (name:BELLATOR-SRV)' },
          { style: NXC, text: 'SMB    ' + fakeTarget + '  445  BELLATOR-SRV  [*] Enumerating shares...' },
          { style: NXCR, text: 'SMB    ' + fakeTarget + '  445  BELLATOR-SRV  [-] Acceso denegado — SENTINEL bloqueó SMB relay' },
          { style: NXCB, text: 'root@kali:~# nxc ssh ' + fakeTarget + ' -u ' + fakeUser + ' -p ' + fakePass },
          { style: NXCR, text: 'SSH    ' + fakeTarget + '   22  BELLATOR-SRV  [-] ' + fakeUser + ':' + fakePass + ' — AUTHENTICATION FAILED' },
          { style: NXCR, text: 'SSH    ' + fakeTarget + '   22  BELLATOR-SRV  [-] Intento registrado. IP añadida a lista negra.' },
          { style: NXCB, text: 'root@kali:~# nxc rdp ' + fakeTarget + ' -u ' + fakeUser + ' -p ' + fakePass + ' --screenshot' },
          { style: NXCR, text: 'RDP    ' + fakeTarget + ' 3389  BELLATOR-SRV  [-] CONEXIÓN RECHAZADA — puerto 3389 cerrado' },
          { style: NXCB, text: 'root@kali:~# nxc ldap ' + fakeTarget + ' -u \'\' -p \'\' --users' },
          { style: NXCR, text: 'LDAP   ' + fakeTarget + '  389  BELLATOR-SRV  [-] ACCESO ANÓNIMO BLOQUEADO — SENTINEL SHIELD' },
          { style: NXCB, text: 'root@kali:~# nxc ftp ' + fakeTarget + ' -u anonymous -p anonymous' },
          { style: NXCR, text: 'FTP    ' + fakeTarget + '   21  BELLATOR-SRV  [-] Puerto no activo en este servidor.' },
          { style: NXCG, text: '[ SENTINEL ] Todos los vectores de ataque bloqueados. ' + (5 + Math.floor(Math.random() * 12)) + ' intentos registrados.' },
          { style: NXCG, text: '[ SENTINEL ] Hash del atacante: ' + fakeHash + ' — perfil guardado en base de datos.' },
          { style: NXCG, text: '[ SENTINEL ] Protocolo KILLSWITCH en espera. Próximo intento = BLOQUEO PERMANENTE.' },
          { style: NXCR, text: '[ BELLATOR ] The quieter you become, the more you are able to hear. — Kali Linux' }
        ];

        var ni = 0;
        var nxcIv = global.setInterval(BellatorCore.safeWrap('sentinel.netexec.feed', function() {
          if (ni >= nxcLines.length) {
            global.clearInterval(nxcIv);
            return;
          }
          console.log('%c' + nxcLines[ni].text, nxcLines[ni].style);
          ni += 1;
        }), 1800);
      }), 3000);

      var feed = [
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
        ['[SENTINEL]  ', ' Vigilando. Siempre vigilando.']
      ];

      var index = 0;
      var iv = global.setInterval(BellatorCore.safeWrap('sentinel.feed', function() {
        if (index >= feed.length) {
          global.clearInterval(iv);
          return;
        }
        console.log('%c' + feed[index][0] + '%c' + feed[index][1], S0, S3);
        index += 1;
      }), 2800);
    }), 300);
  }

  global.BellatorSentinel = {
    __managed: true,
    init: function() {
      return BellatorCore.safe('sentinel.init', initSentinel);
    }
  };

  global.BellatorSentinel.init();
})(window);