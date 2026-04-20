/* Bellator RolBattle — Google Translate widget (en from es) */
(function(){
  'use strict';
  var wrap=document.createElement('div');
  wrap.style.cssText='position:fixed;bottom:16px;right:16px;z-index:9000;' +
    'background:rgba(13,17,23,.82);border-radius:8px;padding:4px 10px 4px 8px;' +
    'border:1px solid rgba(212,175,55,.22);backdrop-filter:blur(8px)';
  var inner=document.createElement('div');
  inner.id='google_translate_element';
  wrap.appendChild(inner);
  document.body.appendChild(wrap);
  window.googleTranslateElementInit=function(){
    new google.translate.TranslateElement(
      {pageLanguage:'es',includedLanguages:'en,pt,ru,ja,zh-CN,zh-TW,ko,fr,de,it,ar',layout:1},
      'google_translate_element'
    );
  };
  var s=document.createElement('script');
  s.src='//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit';
  document.head.appendChild(s);
})();
