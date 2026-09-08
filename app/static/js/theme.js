/* Alterna tema claro/escuro adicionando .dark em <html>.
   O dark-mode.css intercepta as mesmas classes Tailwind quando .dark está presente. */
(function () {
  var KEY = "cc-theme";

  function current() {
    try {
      var saved = localStorage.getItem(KEY);
      if (saved === "dark" || saved === "light") return saved;
    } catch (e) {}
    return window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  }

  function apply(theme) {
    document.documentElement.classList.toggle("dark", theme === "dark");
    var btns = document.querySelectorAll("[data-theme-label]");
    btns.forEach(function (b) {
      b.textContent = theme === "dark" ? "Tema claro" : "Tema escuro";
    });
  }

  window.__setTheme = function (theme) {
    try {
      localStorage.setItem(KEY, theme);
    } catch (e) {}
    apply(theme);
  };

  window.toggleTheme = function () {
    var next = document.documentElement.classList.contains("dark")
      ? "light"
      : "dark";
    window.__setTheme(next);
  };

  // aplica assim que o script carrega (o <head> já rodou o anti-FOUC)
  apply(current());
  document.addEventListener("DOMContentLoaded", function () {
    apply(current());
  });
})();
