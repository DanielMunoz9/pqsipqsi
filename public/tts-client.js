(function(){
  'use strict';

  if (window.BellatorTTS) {
    if (typeof window.BellatorTTS.loadVoices === 'function') {
      window.BellatorTTS.loadVoices();
    }
    return;
  }

  window.BellatorTTS = window.BellatorTTS || (function() {
    const VOICE_KEY = 'bellatorPiperVoice';
    const LEGACY_VOICE_KEY = 'es_MX-claude-high';
    const blobCache = new Map();
    const blobPromiseCache = new Map();
    let voicesPromise = null;
    let currentRequest = null;
    let audioEl = null;
(function() {
  function bootNarrator() {
    if (!window.BellatorTTS && window.BellatorCore && typeof window.BellatorCore.createTTSClient === 'function') {
      window.BellatorTTS = window.BellatorCore.createTTSClient();
    }
    if (window.BellatorTTS && typeof window.BellatorTTS.loadVoices === 'function') {
      window.BellatorTTS.loadVoices();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootNarrator, { once: true });
  } else {
    bootNarrator();
  }
})();