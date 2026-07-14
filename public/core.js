(function(global) {
  'use strict';

  if (global.BellatorCore && global.BellatorCore.__managed) {
    if (typeof global.safe !== 'function') global.safe = global.BellatorCore.safe;
    if (typeof global.safeFetch !== 'function') global.safeFetch = global.BellatorCore.safeFetch;
    if (typeof global.generateDeviceFingerprint !== 'function') {
      global.generateDeviceFingerprint = global.BellatorCore.generateDeviceFingerprint;
    }
    return;
  }

  var fingerprintValue = null;
  var fingerprintPromise = null;
  var guardsInstalled = false;

  function toMessage(error) {
    if (!error) return 'Unknown error';
    if (typeof error === 'string') return error;
    if (error instanceof Error && error.message) return error.message;
    if (error && typeof error.message === 'string') return error.message;
    try {
      return JSON.stringify(error);
    } catch (_) {
      return String(error);
    }
  }

  function log(name, error, meta) {
    var prefix = '[BellatorCore:' + String(name || 'unknown') + ']';
    if (meta !== undefined) {
      console.warn(prefix, toMessage(error), meta);
      return;
    }
    console.warn(prefix, toMessage(error));
  }

  function resolveFallback(fallback, error) {
    if (typeof fallback === 'function') {
      try {
        return fallback(error);
      } catch (fallbackError) {
        log('fallback', fallbackError);
        return null;
      }
    }
    return fallback === undefined ? null : fallback;
  }

  function safe(name, fn, fallback) {
    try {
      return fn();
    } catch (error) {
      log(name, error);
      return resolveFallback(fallback, error);
    }
  }

  function safeAsync(name, fn, fallback) {
    try {
      var result = fn();
      if (result && typeof result.then === 'function') {
        return result.catch(function(error) {
          log(name, error);
          return resolveFallback(fallback, error);
        });
      }
      return Promise.resolve(result);
    } catch (error) {
      log(name, error);
      return Promise.resolve(resolveFallback(fallback, error));
    }
  }

  function safeWrap(name, fn, fallback) {
    return function wrappedSafeCall() {
      var context = this;
      var args = arguments;
      return safeAsync(name, function() {
        return fn.apply(context, args);
      }, fallback);
    };
  }

  function installGlobalGuards() {
    if (guardsInstalled) return;
    guardsInstalled = true;

    var previousOnError = global.onerror;
    global.onerror = function(message, source, lineno, colno, error) {
      var onErrorArgs = arguments;
      log('window.onerror', error || message, {
        source: source || '',
        line: lineno || 0,
        column: colno || 0,
      });
      if (typeof previousOnError === 'function') {
        safe('window.onerror.previous', function() {
          previousOnError.apply(global, onErrorArgs);
        });
      }
      return true;
    };

    global.addEventListener('unhandledrejection', function(event) {
      log('unhandledrejection', event && event.reason ? event.reason : 'Unhandled promise rejection');
      if (event && typeof event.preventDefault === 'function') event.preventDefault();
    });

    global.addEventListener('error', function(event) {
      if (!event || !event.target || event.target === global || event.error) return;
      var target = event.target;
      log('resource.error', new Error(target.currentSrc || target.src || target.href || target.tagName || 'Resource load failed'));
    }, true);
  }

  function getNavigatorLanguage() {
    if (global.navigator && Array.isArray(global.navigator.languages) && global.navigator.languages.length) {
      return global.navigator.languages.join(',');
    }
    return (global.navigator && global.navigator.language) || '';
  }

  function getScreenSignature() {
    var screenRef = global.screen || {};
    return [
      screenRef.width || 0,
      screenRef.height || 0,
      screenRef.colorDepth || 0,
    ].join('x');
  }

  function getTimeZone() {
    return safe('fingerprint.timezone', function() {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    }, '');
  }

  function simpleHash(value) {
    var input = String(value || '');
    var hash = 0;
    for (var index = 0; index < input.length; index += 1) {
      hash = ((hash << 5) - hash) + input.charCodeAt(index);
      hash |= 0;
    }
    return 'fp_' + Math.abs(hash).toString(16);
  }

  function buildFingerprintSeed() {
    var nav = global.navigator || {};
    return JSON.stringify({
      userAgent: nav.userAgent || '',
      language: nav.language || '',
      languages: getNavigatorLanguage(),
      screen: getScreenSignature(),
      timezone: getTimeZone(),
      platform: nav.platform || '',
      vendor: nav.vendor || '',
      hardwareConcurrency: nav.hardwareConcurrency || 0,
      deviceMemory: nav.deviceMemory || 0,
      touchPoints: nav.maxTouchPoints || 0,
    });
  }

  function fallbackFingerprint() {
    return simpleHash(buildFingerprintSeed());
  }

  function generateDeviceFingerprint() {
    if (fingerprintValue) return Promise.resolve(fingerprintValue);
    if (fingerprintPromise) return fingerprintPromise;

    fingerprintPromise = safeAsync('fingerprint.generate', function() {
      var seed = buildFingerprintSeed();
      if (global.crypto && global.crypto.subtle && global.TextEncoder) {
        var encoded = new TextEncoder().encode(seed);
        return global.crypto.subtle.digest('SHA-256', encoded).then(function(digest) {
          return Array.from(new Uint8Array(digest)).map(function(byte) {
            return byte.toString(16).padStart(2, '0');
          }).join('');
        });
      }
      return fallbackFingerprint();
    }, function() {
      return fallbackFingerprint();
    }).then(function(value) {
      fingerprintValue = String(value || fallbackFingerprint());
      return fingerprintValue;
    });

    return fingerprintPromise;
  }

  function resolveRequestLabel(input) {
    if (typeof input === 'string') return input;
    if (input && typeof input.url === 'string') return input.url;
    return 'unknown-request';
  }

  function cloneFetchOptions(options) {
    var cloned = {};
    Object.keys(options || {}).forEach(function(key) {
      if (key === 'timeoutMs' || key === 'allowStatuses' || key === 'label') return;
      cloned[key] = options[key];
    });
    return cloned;
  }

  async function safeFetch(input, options) {
    var opts = options || {};
    if (typeof global.fetch !== 'function') {
      log('fetch', new Error('window.fetch is not available'), { url: resolveRequestLabel(input) });
      return null;
    }

    var timeoutMs = Number(opts.timeoutMs);
    if (!(timeoutMs > 0)) timeoutMs = 10000;

    var fetchOptions = cloneFetchOptions(opts);
    var controller = null;
    var timeoutId = 0;

    if (!fetchOptions.signal && typeof AbortController === 'function') {
      controller = new AbortController();
      fetchOptions.signal = controller.signal;
      timeoutId = global.setTimeout(function() {
        controller.abort();
      }, timeoutMs);
    }

    try {
      var response = await global.fetch(input, fetchOptions);
      var allowStatuses = Array.isArray(opts.allowStatuses) ? opts.allowStatuses : [];
      if (!response.ok && allowStatuses.indexOf(response.status) === -1) {
        log('fetch', new Error('HTTP ' + response.status), {
          url: opts.label || resolveRequestLabel(input),
          status: response.status,
        });
        return null;
      }
      return response;
    } catch (error) {
      log('fetch', error, { url: opts.label || resolveRequestLabel(input) });
      return null;
    } finally {
      if (timeoutId) global.clearTimeout(timeoutId);
    }
  }

  function readJSONSafe(response, fallback) {
    if (!response) return Promise.resolve(fallback === undefined ? null : fallback);
    return response.json().catch(function(error) {
      log('json.parse', error);
      return fallback === undefined ? null : fallback;
    });
  }

  function readTextSafe(response, fallback) {
    if (!response) return Promise.resolve(fallback === undefined ? '' : fallback);
    return response.text().catch(function(error) {
      log('text.read', error);
      return fallback === undefined ? '' : fallback;
    });
  }

  function readBlobSafe(response, fallback) {
    if (!response) return Promise.resolve(fallback === undefined ? null : fallback);
    return response.blob().catch(function(error) {
      log('blob.read', error);
      return fallback === undefined ? null : fallback;
    });
  }

  function createTTSClient() {
    var VOICE_KEY = 'bellatorNarratorVoice';
    var LEGACY_KEYS = ['bellatorPiperVoice'];
    var LATAM_LOCALES = [
      'es-CO', 'es-MX', 'es-US', 'es-AR', 'es-CL', 'es-PE', 'es-VE', 'es-UY',
      'es-PA', 'es-CR', 'es-EC', 'es-DO', 'es-GT', 'es-HN', 'es-NI', 'es-PY',
      'es-SV', 'es-BO', 'es-CU', 'es-PR', 'es-419'
    ];
    var blobCache = new Map();
    var blobPromiseCache = new Map();
    var voicesPromise = null;
    var currentRequest = null;
    var audioEl = null;
    var voiceListenerBound = false;

    function ensureAudio() {
      if (audioEl) return audioEl;
      audioEl = new Audio();
      audioEl.preload = 'auto';
      return audioEl;
    }

    function getSynth() {
      return global.speechSynthesis || null;
    }

    function supportsBrowserNarrator() {
      return Boolean(getSynth() && global.SpeechSynthesisUtterance);
    }

    function normalizeLang(lang) {
      return String(lang || '').replace(/_/g, '-').trim();
    }

    function isSpanishVoice(voice) {
      return /^es([_-]|$)/i.test(normalizeLang(voice && voice.lang));
    }

    function localePriority(lang) {
      var normalized = normalizeLang(lang).toLowerCase();
      var i;
      for (i = 0; i < LATAM_LOCALES.length; i += 1) {
        if (normalized === LATAM_LOCALES[i].toLowerCase()) return i;
      }
      if (normalized.indexOf('es-') === 0) return 200;
      if (normalized === 'es') return 210;
      return 1000;
    }

    function voiceId(voice, index) {
      return (voice && (voice.voiceURI || voice.name)) || ('voice-' + String(index || 0));
    }

    function escapeHTML(text) {
      return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function buildBrowserVoiceLabel(voice) {
      var lang = normalizeLang(voice && voice.lang) || 'SYSTEM';
      var bucket = localePriority(lang) < 200 ? 'LATAM' : (isSpanishVoice(voice) ? 'ESPANOL' : 'SISTEMA');
      return bucket + ' · ' + lang.toUpperCase() + ' · ' + String((voice && voice.name) || 'Narrador');
    }

    function compareBrowserVoices(a, b) {
      var diff = localePriority(a.lang) - localePriority(b.lang);
      if (diff !== 0) return diff;
      if (a.default !== b.default) return a.default ? -1 : 1;
      if (a.localService !== b.localService) return a.localService ? -1 : 1;
      return String(a.name || '').localeCompare(String(b.name || ''));
    }

    function readAvailableBrowserVoices() {
      if (!supportsBrowserNarrator()) return [];
      return (getSynth().getVoices() || []).map(function(voice, index) {
        return {
          id: voiceId(voice, index),
          label: buildBrowserVoiceLabel(voice),
          lang: normalizeLang(voice.lang),
          name: String(voice.name || ''),
          default: Boolean(voice.default),
          localService: Boolean(voice.localService),
        };
      }).sort(compareBrowserVoices);
    }

    function buildBrowserVoiceData() {
      var allVoices = readAvailableBrowserVoices();
      var voices = allVoices.filter(isSpanishVoice);
      if (!voices.length) voices = allVoices;
      return {
        enabled: supportsBrowserNarrator() && voices.length > 0,
        provider: 'browser',
        defaultVoice: voices.length ? voices[0].id : '',
        voices: voices,
      };
    }

    function normalizeRemoteVoicesResponse(data) {
      var normalized = data || {};
      normalized.voices = Array.isArray(normalized.voices) ? normalized.voices : [];
      normalized.defaultVoice = normalized.defaultVoice || (normalized.voices[0] && normalized.voices[0].id) || '';
      normalized.enabled = Boolean(normalized.enabled && normalized.voices.length);
      normalized.provider = normalized.provider || 'azure';
      return normalized;
    }

    function getStoredVoice() {
      return safe('tts.voice.get', function() {
        var stored = global.localStorage.getItem(VOICE_KEY) || '';
        var i;
        if (stored) return stored;
        for (i = 0; i < LEGACY_KEYS.length; i += 1) {
          stored = global.localStorage.getItem(LEGACY_KEYS[i]) || '';
          if (stored) return stored;
        }
        return '';
      }, '');
    }

    function setStoredVoice(voiceID) {
      if (!voiceID) return;
      if (voiceID === getStoredVoice()) return;
      safe('tts.voice.set', function() {
        global.localStorage.setItem(VOICE_KEY, voiceID);
      });
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
        var oldestKey = blobCache.keys().next().value;
        blobCache.delete(oldestKey);
      }
    }

    function resolveVoice(data, requestedVoice) {
      var voices = (data && data.voices) || [];
      if (!voices.length) return '';
      if (requestedVoice && voices.some(function(voice) { return voice.id === requestedVoice; })) {
        return requestedVoice;
      }
      return data.defaultVoice || voices[0].id || '';
    }

    function findVoiceByID(voiceID) {
      var synth = getSynth();
      var voices = synth ? (synth.getVoices() || []) : [];
      var i;
      for (i = 0; i < voices.length; i += 1) {
        if (voiceId(voices[i], i) === voiceID) return voices[i];
      }
      return null;
    }

    function ensureVoiceListener() {
      var synth = getSynth();
      if (!supportsBrowserNarrator() || voiceListenerBound || !synth) return;

      var refreshVoices = function() {
        voicesPromise = Promise.resolve(buildBrowserVoiceData());
        syncVoiceSelects();
      };

      if (typeof synth.addEventListener === 'function') {
        synth.addEventListener('voiceschanged', refreshVoices);
        voiceListenerBound = true;
        return;
      }

      if ('onvoiceschanged' in synth) {
        var previousHandler = synth.onvoiceschanged;
        synth.onvoiceschanged = function(event) {
          if (typeof previousHandler === 'function') previousHandler.call(this, event);
          refreshVoices();
        };
        voiceListenerBound = true;
      }
    }

    function waitForBrowserVoices(timeoutMs) {
      return new Promise(function(resolve) {
        var synth = getSynth();
        var initialData;
        var timer = null;

        if (!supportsBrowserNarrator() || !synth) {
          resolve({ enabled: false, provider: 'browser', defaultVoice: '', voices: [] });
          return;
        }

        ensureVoiceListener();
        initialData = buildBrowserVoiceData();
        if (initialData.voices.length) {
          resolve(initialData);
          return;
        }

        function finalize() {
          if (timer) global.clearTimeout(timer);
          resolve(buildBrowserVoiceData());
        }

        timer = global.setTimeout(finalize, timeoutMs || 1600);
        if (typeof synth.addEventListener === 'function') {
          var once = function() {
            synth.removeEventListener('voiceschanged', once);
            finalize();
          };
          synth.addEventListener('voiceschanged', once);
        }
      });
    }

    function loadVoices(forceRefresh) {
      if (!voicesPromise || forceRefresh) {
        voicesPromise = safeAsync('tts.loadVoices', async function() {
          var response = await safeFetch('/api/tts/voices', {
            cache: 'no-store',
            timeoutMs: 8000,
            label: 'tts.voices',
          });

          if (response) {
            var remoteData = normalizeRemoteVoicesResponse(await readJSONSafe(response, {
              enabled: false,
              provider: 'azure',
              defaultVoice: '',
              voices: []
            }));
            if (remoteData.enabled && remoteData.voices.length) {
              var remoteVoice = resolveVoice(remoteData, getStoredVoice());
              if (remoteVoice) setStoredVoice(remoteVoice);
              return remoteData;
            }
          }

          var browserData = await waitForBrowserVoices(1800);
          var browserVoice = resolveVoice(browserData, getStoredVoice());
          if (browserVoice) setStoredVoice(browserVoice);
          return browserData;
        }, function() {
          return waitForBrowserVoices(1800);
        });
      }
      return voicesPromise;
    }

    function renderVoiceSelect(select, data) {
      if (!select) return;
      var activeVoice = resolveVoice(data, getStoredVoice());
      if (!data.enabled || !data.voices.length) {
        select.innerHTML = '<option value="">NARRADOR NO DISPONIBLE</option>';
        select.disabled = true;
        return;
      }
      select.innerHTML = data.voices.map(function(voice) {
        return '<option value="' + escapeHTML(voice.id) + '">' + escapeHTML(voice.label) + '</option>';
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
      var content = String(text || '').trim();
      if (!content) {
        throw new Error('El texto esta vacio.');
      }

      var data = options && options.data ? options.data : await loadVoices();
      if (!data.enabled || data.provider !== 'azure' || !data.voices.length) {
        throw new Error('Azure Speech no esta disponible en este momento.');
      }

      var voiceID = resolveVoice(data, (options && options.voice) || getStoredVoice());
      if (!voiceID) {
        throw new Error('No hay voz disponible para reproducir.');
      }

      var cacheKey = buildCacheKey(voiceID, content);
      if (blobCache.has(cacheKey)) {
        return { blob: blobCache.get(cacheKey), voiceID: voiceID, cacheKey: cacheKey };
      }

      if (!blobPromiseCache.has(cacheKey)) {
        var fetchPromise = safeAsync('tts.fetchSpeechBlob', async function() {
          var response = await safeFetch('/api/tts/speak', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            cache: 'no-store',
            signal: options && options.signal,
            timeoutMs: 25000,
            allowStatuses: [400, 422, 429, 500, 502, 503],
            label: 'tts.speak',
            body: JSON.stringify({ text: content, voice: voiceID }),
          });

          if (!response) {
            throw new Error('No se pudo conectar con Azure Speech.');
          }
          if (!response.ok) {
            var errorMessage = await readTextSafe(response, 'No se pudo generar el audio.');
            throw new Error(errorMessage || 'No se pudo generar el audio.');
          }

          var resolvedVoice = response.headers.get('X-TTS-Voice') || voiceID;
          var blob = await readBlobSafe(response, null);
          if (!blob) {
            throw new Error('No se pudo leer el audio generado.');
          }
          var resolvedKey = buildCacheKey(resolvedVoice, content);
          storeBlob(resolvedKey, blob);
          if (resolvedVoice !== voiceID) storeBlob(cacheKey, blob);
          return { blob: blob, voiceID: resolvedVoice, cacheKey: resolvedKey };
        }).finally(function() {
          blobPromiseCache.delete(cacheKey);
        });
        blobPromiseCache.set(cacheKey, fetchPromise);
      }

      return blobPromiseCache.get(cacheKey);
    }

    function cleanupAzureAudio(request) {
      var audio = ensureAudio();
      audio.onended = null;
      audio.onerror = null;
      if (!audio.paused) audio.pause();
      audio.removeAttribute('src');
      audio.load();
      if (request && request.url) URL.revokeObjectURL(request.url);
    }

    function finishRequest(request, kind, message) {
      if (!request || currentRequest !== request) return;
      currentRequest = null;
      if (request.provider === 'azure') {
        cleanupAzureAudio(request);
      }
      if (kind === 'error') {
        if (typeof request.onError === 'function') request.onError(message || 'No se pudo generar el audio.');
        return;
      }
      if (typeof request.onEnd === 'function') request.onEnd();
    }

    function stop() {
      if (!currentRequest) return;
      var request = currentRequest;
      currentRequest = null;
      if (request.provider === 'azure') {
        if (request.controller) request.controller.abort();
        cleanupAzureAudio(request);
      } else {
        safe('tts.stop', function() {
          var synth = getSynth();
          if (synth) synth.cancel();
        });
      }
      if (typeof request.onEnd === 'function') request.onEnd();
    }

    async function speakWithAzure(content, options, data) {
      var request = {
        provider: 'azure',
        controller: typeof AbortController === 'function' ? new AbortController() : null,
        onEnd: options && options.onEnd,
        onError: options && options.onError,
        onPlay: options && options.onPlay,
        url: '',
      };
      currentRequest = request;

      try {
        var result = await fetchSpeechBlob(content, {
          voice: options && options.voice,
          signal: request.controller ? request.controller.signal : null,
          data: data,
        });
        if (currentRequest !== request) return false;
        if (result.voiceID) setStoredVoice(result.voiceID);
        request.url = URL.createObjectURL(result.blob);
        var audio = ensureAudio();
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

    async function speakWithBrowser(content, options, data) {
      if (!supportsBrowserNarrator()) {
        if (options && typeof options.onError === 'function') {
          options.onError('Este navegador no soporta narracion integrada.');
        }
        return false;
      }

      var selectedVoiceID = resolveVoice(data, (options && options.voice) || getStoredVoice());
      var utterance = new global.SpeechSynthesisUtterance(content);
      var selectedVoice = findVoiceByID(selectedVoiceID);
      if (selectedVoiceID) setStoredVoice(selectedVoiceID);
      if (selectedVoice) {
        utterance.voice = selectedVoice;
        utterance.lang = normalizeLang(selectedVoice.lang) || 'es-CO';
      } else {
        utterance.lang = 'es-CO';
      }
      utterance.rate = 1;
      utterance.pitch = 1;
      utterance.volume = 1;

      var request = {
        provider: 'browser',
        onEnd: options && options.onEnd,
        onError: options && options.onError,
        onPlay: options && options.onPlay,
      };
      currentRequest = request;

      try {
        utterance.onstart = function() {
          if (currentRequest !== request) return;
          if (typeof request.onPlay === 'function') request.onPlay();
        };
        utterance.onend = function() {
          finishRequest(request, 'end');
        };
        utterance.onerror = function(event) {
          if (event && (event.error === 'canceled' || event.error === 'interrupted')) {
            finishRequest(request, 'end');
            return;
          }
          finishRequest(request, 'error', 'No se pudo reproducir el narrador.');
        };
        safe('tts.speak.browser', function() {
          var synth = getSynth();
          if (!synth) throw new Error('Narrador no disponible');
          synth.cancel();
          synth.speak(utterance);
        });
        return true;
      } catch (error) {
        finishRequest(request, 'error', error && error.message ? error.message : 'No se pudo reproducir el narrador.');
        return false;
      }
    }

    async function speak(text, options) {
      var content = String(text || '').replace(/\s+/g, ' ').trim();
      if (!content) {
        if (options && typeof options.onError === 'function') {
          options.onError('El texto esta vacio.');
        }
        return false;
      }

      stop();

      if (options && typeof options.onStart === 'function') options.onStart();

      var data = await loadVoices();
      if (!data.enabled || !data.voices.length) {
        if (options && typeof options.onError === 'function') {
          options.onError('No se encontro un narrador disponible.');
        }
        return false;
      }

      if (data.provider === 'azure') {
        return speakWithAzure(content, options, data);
      }
      return speakWithBrowser(content, options, data);
    }

    function prewarm(text, options) {
      var content = String(text || '').replace(/\s+/g, ' ').trim();
      if (!content) return Promise.resolve(false);
      return loadVoices().then(function(data) {
        if (!data.enabled || !data.voices.length) return false;
        if (data.provider !== 'azure') return true;
        return fetchSpeechBlob(content, { voice: options && options.voice, data: data })
          .then(function() { return true; })
          .catch(function() { return false; });
      }).catch(function() {
        return false;
      });
    }

    if (supportsBrowserNarrator()) {
      ensureVoiceListener();
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
  }

  var core = {
    __managed: true,
    safe: safe,
    safeAsync: safeAsync,
    safeWrap: safeWrap,
    safeFetch: safeFetch,
    readJSONSafe: readJSONSafe,
    readTextSafe: readTextSafe,
    readBlobSafe: readBlobSafe,
    simpleHash: simpleHash,
    generateDeviceFingerprint: generateDeviceFingerprint,
    createTTSClient: createTTSClient,
    installGlobalGuards: installGlobalGuards,
    log: log,
  };

  global.BellatorCore = core;
  global.safe = safe;
  global.safeFetch = safeFetch;
  global.generateDeviceFingerprint = generateDeviceFingerprint;

  installGlobalGuards();

  if (!global.BellatorTTS) {
    global.BellatorTTS = createTTSClient();
  }
})(window);