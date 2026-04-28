/* Bellator RolBattle — Button SFX + Google Translate */
(function () {
  'use strict';

  /* ── Button SFX (videogame UI click — todos los dispositivos) ──────────── */
  var _sfxCtx = null;

  function _getCtx() {
    if (!_sfxCtx) {
      try { _sfxCtx = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) {}
    }
    if (_sfxCtx && _sfxCtx.state === 'suspended') {
      try { _sfxCtx.resume(); } catch (e) {}
    }
    return _sfxCtx;
  }

  function _playBtnSfx() {
    var ctx = _getCtx();
    if (!ctx) return;
    try {
      var osc  = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = 'square';
      var t = ctx.currentTime;
      osc.frequency.setValueAtTime(900, t);
      osc.frequency.exponentialRampToValueAtTime(350, t + 0.065);
      gain.gain.setValueAtTime(0.22, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.065);
      osc.start(t);
      osc.stop(t + 0.065);
    } catch (e) {}
  }

  document.addEventListener('click', function (e) {
    var el = e.target;
    var hit = el && el.closest
      ? el.closest('button, input[type="submit"], input[type="button"], input[type="reset"], [role="button"]')
      : null;
    if (hit) _playBtnSfx();
  }, false);

  /* ── Google Translate (solo desktop) ──────────────────────────────────── */
  var isMobile = window.matchMedia &&
    window.matchMedia('(max-width:768px), (hover:none) and (pointer:coarse)').matches;
  if (isMobile) return;

  var includedLanguages = 'en,pt,ru,ja,zh-CN,zh-TW,ko,fr,de,it,ar';

  var wrap = document.createElement('div');
  wrap.style.cssText = 'position:fixed;bottom:16px;left:16px;z-index:9000;' +
    'background:rgba(13,17,23,.82);border-radius:8px;padding:4px 10px 4px 8px;' +
    'border:1px solid rgba(212,175,55,.22);backdrop-filter:blur(8px)';
  var inner = document.createElement('div');
  inner.id = 'google_translate_element';
  wrap.appendChild(inner);
  document.body.appendChild(wrap);

  window.googleTranslateElementInit = function () {
    new google.translate.TranslateElement(
      { pageLanguage: 'es', includedLanguages: includedLanguages, layout: 1 },
      'google_translate_element'
    );
  };
  var s = document.createElement('script');
  s.src = '//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit';
  document.head.appendChild(s);
})();
