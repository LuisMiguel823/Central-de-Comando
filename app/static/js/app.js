/* Interações do APP CENTRAL: modais, confirmação, toasts, carregando, paleta. */
(function () {
  "use strict";

  // ---------------------------------------------------------------- toasts
  window.toast = function (msg, kind) {
    var host = document.getElementById("toast-host");
    if (!host) return;
    var el = document.createElement("div");
    el.className = "toast" + (kind ? " is-" + kind : "");
    el.textContent = msg;
    host.appendChild(el);
    setTimeout(function () {
      el.classList.add("is-out");
      setTimeout(function () {
        el.remove();
      }, 220);
    }, 2600);
  };

  // ---------------------------------------------------------------- modais
  function anyModalOpen() {
    return !!document.querySelector(".modal-overlay.flex, .palette.is-open");
  }
  window.openModal = function (id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.classList.remove("hidden");
    el.classList.add("flex");
    document.body.style.overflow = "hidden";
    var first = el.querySelector("input:not([type=hidden]):not([type=checkbox]), select, textarea");
    if (first) setTimeout(function () { first.focus(); }, 60);
  };
  window.closeModal = function (id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.classList.add("hidden");
    el.classList.remove("flex");
    if (!anyModalOpen()) document.body.style.overflow = "";
  };
  function closeAllModals() {
    document.querySelectorAll(".modal-overlay").forEach(function (m) {
      m.classList.add("hidden");
      m.classList.remove("flex");
    });
    document.body.style.overflow = "";
  }

  document.addEventListener("click", function (e) {
    var t = e.target;
    if (!t || !t.closest) return;

    var closer = t.closest("[data-close-modal]");
    if (closer) return window.closeModal(closer.getAttribute("data-close-modal"));
    var opener = t.closest("[data-open-modal]");
    if (opener) return window.openModal(opener.getAttribute("data-open-modal"));

    // clique no fundo escuro fecha o modal
    if (t.classList && t.classList.contains("modal-overlay")) {
      t.classList.add("hidden");
      t.classList.remove("flex");
      if (!anyModalOpen()) document.body.style.overflow = "";
    }

    // copiar
    var btn = t.closest("[data-copy-target]");
    if (btn) {
      var el = document.getElementById(btn.getAttribute("data-copy-target"));
      if (!el) return;
      var text = "value" in el ? el.value : el.textContent;
      navigator.clipboard.writeText(text).then(function () {
        window.toast("Copiado para a área de transferência", "ok");
        var original = btn.textContent;
        btn.textContent = "Copiado!";
        setTimeout(function () { btn.textContent = original; }, 1500);
      });
    }

    // fechar menu do usuário ao clicar fora
    document.querySelectorAll("details.user-menu[open]").forEach(function (d) {
      if (!d.contains(t)) d.removeAttribute("open");
    });
  });

  // ---------------------------------------------------- confirmação própria
  var confirmEl;
  function askConfirm(message, onYes) {
    if (!confirmEl) {
      confirmEl = document.createElement("div");
      confirmEl.className = "modal-overlay fixed inset-0 z-[95] hidden items-center justify-center p-4";
      confirmEl.innerHTML =
        '<div class="confirm-box" role="alertdialog" aria-modal="true">' +
        '<h3 class="text-lg font-semibold" data-c-title></h3>' +
        '<p class="mt-2 text-sm leading-relaxed" style="color:var(--muted)" data-c-msg></p>' +
        '<div class="mt-5 flex justify-end gap-2">' +
        '<button type="button" data-c-no class="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-600">Cancelar</button>' +
        '<button type="button" data-c-yes class="rounded-lg px-4 py-2 text-sm font-semibold"></button>' +
        "</div></div>";
      document.body.appendChild(confirmEl);
      confirmEl.addEventListener("click", function (e) {
        if (e.target === confirmEl || e.target.hasAttribute("data-c-no")) hide();
      });
    }
    var danger = /^(excluir|remover|rotacionar|apagar|revogar)/i.test(message);
    confirmEl.querySelector("[data-c-title]").textContent = danger ? "Tem certeza?" : "Confirmar ação";
    confirmEl.querySelector("[data-c-msg]").textContent = message;
    var yes = confirmEl.querySelector("[data-c-yes]");
    yes.textContent = danger ? "Sim, continuar" : "Confirmar";
    yes.className = "rounded-lg px-4 py-2 text-sm font-semibold " + (danger ? "btn-danger" : "btn-primary");
    yes.onclick = function () {
      hide();
      onYes();
    };
    confirmEl.classList.remove("hidden");
    confirmEl.classList.add("flex");
    setTimeout(function () { yes.focus(); }, 40);
  }
  function hide() {
    if (!confirmEl) return;
    confirmEl.classList.add("hidden");
    confirmEl.classList.remove("flex");
  }

  // ------------------------------------- submit: confirmar + estado carregando
  var confirmed = new WeakSet();
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var msg = form.getAttribute && form.getAttribute("data-confirm");
    if (msg && !confirmed.has(form)) {
      e.preventDefault();
      askConfirm(msg, function () {
        confirmed.add(form);
        form.requestSubmit ? form.requestSubmit() : form.submit();
      });
      return;
    }
    var btn = e.submitter || form.querySelector("button:not([type]), button[type=submit]");
    if (btn && !btn.hasAttribute("data-no-loading")) {
      setTimeout(function () { btn.classList.add("is-loading"); }, 0);
    }
  });
  window.addEventListener("pageshow", function () {
    document.querySelectorAll("button.is-loading").forEach(function (b) {
      b.classList.remove("is-loading");
    });
  });

  // -------------------------------------------------------------- topbar
  var bar = document.querySelector(".topbar");
  if (bar) {
    var onScroll = function () { bar.classList.toggle("is-stuck", window.scrollY > 6); };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  // ---------------------------------------------------- paleta Ctrl+K
  var pal = document.getElementById("palette");
  if (pal) {
    var input = document.getElementById("palette-input");
    var list = document.getElementById("palette-list");
    var items = [];
    var sel = 0;

    function collect() {
      var out = [];
      document.querySelectorAll(".sidebar a[href]").forEach(function (a) {
        var label = (a.querySelector(".sidebar-label") || a).textContent.trim();
        out.push({ label: label, hint: a.getAttribute("href"), run: function () { location.href = a.getAttribute("href"); } });
      });
      out.push({ label: "Alternar tema claro/escuro", hint: "tema", run: function () { window.toggleTheme(); } });
      var out2 = document.querySelector('a[href="/logout"]');
      if (out2) out.push({ label: "Sair", hint: "/logout", run: function () { location.href = "/logout"; } });
      return out;
    }
    function render() {
      var q = input.value.trim().toLowerCase();
      var shown = items.filter(function (it) {
        return !q || it.label.toLowerCase().indexOf(q) !== -1 || it.hint.toLowerCase().indexOf(q) !== -1;
      });
      sel = Math.min(sel, Math.max(shown.length - 1, 0));
      list.innerHTML = "";
      shown.forEach(function (it, i) {
        var row = document.createElement("div");
        row.className = "palette-item" + (i === sel ? " is-sel" : "");
        row.innerHTML = "<span></span><small></small>";
        row.children[0].textContent = it.label;
        row.children[1].textContent = it.hint;
        row.onmousemove = function () { sel = i; mark(); };
        row.onclick = function () { close(); it.run(); };
        list.appendChild(row);
      });
      list._shown = shown;
      if (!shown.length) list.innerHTML = '<div class="palette-item"><small>Nada encontrado</small></div>';
    }
    function mark() {
      Array.prototype.forEach.call(list.children, function (c, i) {
        c.classList.toggle("is-sel", i === sel);
      });
    }
    function open() {
      items = collect();
      input.value = "";
      sel = 0;
      render();
      pal.classList.add("is-open");
      pal.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
      setTimeout(function () { input.focus(); }, 30);
    }
    function close() {
      pal.classList.remove("is-open");
      pal.setAttribute("aria-hidden", "true");
      if (!anyModalOpen()) document.body.style.overflow = "";
    }
    input.addEventListener("input", function () { sel = 0; render(); });
    input.addEventListener("keydown", function (e) {
      var n = (list._shown || []).length;
      if (e.key === "ArrowDown") { e.preventDefault(); sel = (sel + 1) % Math.max(n, 1); mark(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); sel = (sel - 1 + n) % Math.max(n, 1); mark(); }
      else if (e.key === "Enter") { e.preventDefault(); var it = (list._shown || [])[sel]; if (it) { close(); it.run(); } }
    });
    pal.addEventListener("click", function (e) { if (e.target === pal) close(); });
    document.addEventListener("click", function (e) {
      if (e.target.closest && e.target.closest("[data-open-palette]")) open();
    });
    document.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        pal.classList.contains("is-open") ? close() : open();
      } else if (e.key === "Escape" && pal.classList.contains("is-open")) {
        close();
      }
    });
    window.__closePalette = close;
  }

  // ------------------------------------------------------------------ Esc
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    hide();
    closeAllModals();
    document.querySelectorAll("details.user-menu[open]").forEach(function (d) { d.removeAttribute("open"); });
  });
})();
