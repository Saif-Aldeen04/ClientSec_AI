/*__SALLA_WRAP_V1__*/
(function () {
    var s = document.currentScript;
    Salla.onReady(function () {
        var scoped = window.Salla.appScope(s.dataset.scopeId);
        var salla = scoped, Salla = scoped;
        var document = new Proxy(window.document, {
            get: function (d, p) { if (p === 'currentScript') { return s; } var v = d[p]; return typeof v === 'function' ? v.bind(d) : v; },
            set: function (d, p, v) { d[p] = v; return true; }
        });
/*__SALLA_USER_CODE_START__*/
(() => {
  const style = document.createElement('link');
  style.rel = 'stylesheet';
  style.href = 'https://cdn.assets.salla.network/static/js/reviews-translator/app.css';
  document.head.appendChild(style);

  const script = document.createElement('script');
  script.src = 'https://cdn.assets.salla.network/static/js/reviews-translator/app.js';
  document.head.appendChild(script);
})();
/*__SALLA_USER_CODE_END__*/
    });
})();
