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
    var VOICE_KEY = 'bellatorPiperVoice';
    var LEGACY_VOICE_KEY = 'es_MX-claude-high';
    var blobCache = new Map();
    var blobPromiseCache = new Map();
    var voicesPromise = null;
    var currentRequest = null;
    var audioEl = null;

    function ensureAudio() {
      if (audioEl) return audioEl;
      audioEl = new Audio();
      audioEl.preload = 'auto';
      return audioEl;
    }

    function getStoredVoice() {
      return safe('tts.voice.get', function() {
        return global.localStorage.getItem(VOICE_KEY) || '';
      }, '');
    }

    function setStoredVoice(voiceID) {
      if (!voiceID) return;
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

    function normalizeVoicesResponse(data) {
      var normalized = data || {};
      normalized.voices = Array.isArray(normalized.voices) ? normalized.voices : [];
      normalized.defaultVoice = normalized.defaultVoice || (normalized.voices[0] && normalized.voices[0].id) || '';
      normalized.enabled = Boolean(normalized.enabled && normalized.voices.length);
      return normalized;
    }

    function loadVoices() {
      if (!voicesPromise) {
        voicesPromise = safeAsync('tts.loadVoices', async function() {
          var response = await safeFetch('/api/tts/voices', {
            cache: 'no-store',
            timeoutMs: 8000,
            label: 'tts.voices',
          });
          if (!response) {
            return { enabled: false, defaultVoice: '', voices: [] };
          }

          var data = normalizeVoicesResponse(await readJSONSafe(response, { enabled: false, defaultVoice: '', voices: [] }));
          var storedVoice = getStoredVoice();
          var preferredStoredVoice = storedVoice === LEGACY_VOICE_KEY && data.defaultVoice && data.defaultVoice !== LEGACY_VOICE_KEY
            ? data.defaultVoice
            : storedVoice;
          var activeVoice = resolveVoice(data, preferredStoredVoice);
          if (activeVoice) setStoredVoice(activeVoice);
          return data;
        }, function() {
          return { enabled: false, defaultVoice: '', voices: [] };
        });
      }
      return voicesPromise;
    }

    function renderVoiceSelect(select, data) {
      if (!select) return;
      var activeVoice = resolveVoice(data, getStoredVoice());
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
      var content = String(text || '').trim();
      if (!content) {
        throw new Error('El texto esta vacio.');
      }

      var data = await loadVoices();
      if (!data.enabled || !data.voices.length) {
        throw new Error('Piper no esta disponible en este momento.');
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
            timeoutMs: 20000,
            allowStatuses: [400, 422, 429, 500, 503],
            label: 'tts.speak',
            body: JSON.stringify({ text: content, voice: voiceID }),
          });

          if (!response) {
            throw new Error('No se pudo conectar con el servicio de voz.');
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

    function finishRequest(request, kind, message) {
      if (!request || currentRequest !== request) return;
      var audio = ensureAudio();
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
      var request = currentRequest;
      if (request.controller) request.controller.abort();
      finishRequest(request, 'end');
    }

    async function speak(text, options) {
      var content = String(text || '').trim();
      if (!content) {
        if (options && typeof options.onError === 'function') {
          options.onError('El texto esta vacio.');
        }
        return false;
      }

      stop();

      var request = {
        controller: typeof AbortController === 'function' ? new AbortController() : null,
        onEnd: options && options.onEnd,
        onError: options && options.onError,
        url: '',
      };
      currentRequest = request;
      if (options && typeof options.onStart === 'function') options.onStart();

      try {
        var result = await fetchSpeechBlob(content, {
          voice: options && options.voice,
          signal: request.controller ? request.controller.signal : null,
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

    function prewarm(text, options) {
      var content = String(text || '').trim();
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