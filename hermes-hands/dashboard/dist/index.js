// Hermes Hands has no web dashboard page: the manifest hides its tab, and this bundle registers the
// placeholder the dashboard expects for it (extending-the-dashboard.md, "Augmenting built-in pages").
(function () {
  window.__HERMES_PLUGINS__.register("hermes-hands", function () {
    return null;
  });
})();
