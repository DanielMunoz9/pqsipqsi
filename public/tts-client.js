(function(){
  'use strict';

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

    function resolveVoice(data, requestedVoice) {
      const voices = (data && data.voices) || [];
      if (!voices.length) return '';
      if (requestedVoice && voices.some(function(voice) { return voice.id === requestedVoice; })) {
        return requestedVoice;
      }
      return data.defaultVoice || voices[0].id || '';
    }

    function loadVoices() {
      if (!voicesPromise) {
        voicesPromise = fetch('/api/tts/voices', { cache: 'no-store' })
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
          headers: { 'Content-Type': 'application/json' },
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
})();