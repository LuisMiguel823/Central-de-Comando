/* Utilidades de UI: modais e confirmações. */
(function () {
  window.openModal = function (id) {
    var el = document.getElementById(id);
    if (el) {
      el.classList.remove("hidden");
      el.classList.add("flex");
    }
  };
  window.closeModal = function (id) {
    var el = document.getElementById(id);
    if (el) {
      el.classList.add("hidden");
      el.classList.remove("flex");
    }
  };
  document.addEventListener("click", function (e) {
    var t = e.target;
    if (t && t.hasAttribute && t.hasAttribute("data-close-modal")) {
      window.closeModal(t.getAttribute("data-close-modal"));
    }
    if (t && t.hasAttribute && t.hasAttribute("data-open-modal")) {
      window.openModal(t.getAttribute("data-open-modal"));
    }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-overlay").forEach(function (m) {
        m.classList.add("hidden");
        m.classList.remove("flex");
      });
    }
  });
})();
