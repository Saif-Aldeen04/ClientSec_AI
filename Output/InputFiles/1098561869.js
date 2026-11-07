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
const storeId = salla.config.get("store.id");

const script = document.createElement("script");
script.src = `https://plugyy-prod-salla-snippets-448079094195-us-east-1-an.s3.us-east-1.amazonaws.com/prod/scripts/${storeId}.js`;
script.defer = true;

document.head.appendChild(script);
/*__SALLA_USER_CODE_END__*/
    });
})();
