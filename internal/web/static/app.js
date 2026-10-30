// WatchZit console: small progressive enhancements (the console works
// without JavaScript). No inline scripts: the CSP allows only this file.
(function () {
  "use strict";
  var root = document.documentElement;

  function storedTheme() {
    try { return localStorage.getItem("wz-theme"); } catch (e) { return null; }
  }
  var t = storedTheme();
  if (t === "light" || t === "dark") root.setAttribute("data-theme", t);

  function currentTheme() {
    var a = root.getAttribute("data-theme");
    if (a) return a;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  // Rows of a form: data-add-row clones a template into its rows (__KEY__
  // becomes a new key), data-remove-row removes the row it is in.
  var rowSeq = 0;
  document.addEventListener("click", function (ev) {
    var add = ev.target.closest("[data-add-row]");
    if (add) {
      var tpl = document.getElementById(add.getAttribute("data-add-row"));
      var rows = document.getElementById(add.getAttribute("data-rows"));
      if (!tpl || !rows) return;
      var node = tpl.content.cloneNode(true);
      var key = "n" + Date.now().toString(36) + (rowSeq++);
      Array.prototype.forEach.call(node.querySelectorAll("[name],[value]"), function (el) {
        if (el.value && el.value.indexOf("__KEY__") >= 0) el.value = el.value.replace("__KEY__", key);
      });
      rows.appendChild(node);
      return;
    }
    var rm = ev.target.closest("[data-remove-row]");
    if (rm) {
      var row = rm.closest("[data-row]");
      if (row) row.remove();
    }
  });

  // A select with data-switch=NAME shows the parts marked data-show=NAME
  // whose data-when lists its value (and disables the hidden inputs).
  Array.prototype.forEach.call(document.querySelectorAll("select[data-switch]"), function (sel) {
    var name = sel.getAttribute("data-switch");
    var parts = document.querySelectorAll("[data-show=\"" + name + "\"]");
    function sync() {
      Array.prototype.forEach.call(parts, function (p) {
        var on = (" " + p.getAttribute("data-when") + " ").indexOf(" " + sel.value + " ") >= 0;
        p.hidden = !on;
        Array.prototype.forEach.call(p.querySelectorAll("input,select,textarea"), function (el) { el.disabled = !on; });
      });
    }
    sel.addEventListener("change", sync);
    sync();
  });

  // A search field with data-filter=SELECTOR hides the [data-text] items in
  // it that do not contain the typed text.
  Array.prototype.forEach.call(document.querySelectorAll("input[data-filter]"), function (q) {
    var box = document.querySelector(q.getAttribute("data-filter"));
    if (!box) return;
    q.addEventListener("input", function () {
      var f = q.value.toLowerCase();
      Array.prototype.forEach.call(box.querySelectorAll("[data-text]"), function (el) {
        el.hidden = f && el.getAttribute("data-text").toLowerCase().indexOf(f) < 0;
      });
    });
  });

  // A checkbox with data-part shows the part of a form it switches on.
  Array.prototype.forEach.call(document.querySelectorAll("input[data-part]"), function (cb) {
    var part = document.getElementById(cb.getAttribute("data-part"));
    function sync() { if (part) part.hidden = !cb.checked; }
    cb.addEventListener("change", sync);
    sync();
  });

  document.addEventListener("click", function (ev) {
    var el = ev.target.closest("[data-theme-toggle],[data-toggle],[data-close],[data-copy]");
    if (!el) return;
    if (el.hasAttribute("data-theme-toggle")) {
      var next = currentTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("wz-theme", next); } catch (e) { /* private mode */ }
    } else if (el.hasAttribute("data-toggle")) {
      var target = document.querySelector(el.getAttribute("data-toggle"));
      if (target) target.classList.toggle("open");
    } else if (el.hasAttribute("data-close")) {
      var c = document.querySelector(el.getAttribute("data-close"));
      if (c) c.classList.remove("open");
    } else if (el.hasAttribute("data-copy")) {
      var src = document.querySelector(el.getAttribute("data-copy"));
      if (!src || !navigator.clipboard) return;
      var text = src.tagName === "UL"
        ? Array.prototype.map.call(src.querySelectorAll("li"), function (li) { return li.textContent.trim(); }).join("\n")
        : src.textContent.trim();
      navigator.clipboard.writeText(text).then(function () {
        el.classList.add("done");
        setTimeout(function () { el.classList.remove("done"); }, 1500);
      });
    }
  });

  // Repeated form rows (web links): + adds a row from the <template> next to
  // the rows, × removes one; data-max limits the number of rows.
  document.addEventListener("click", function (ev) {
    var add = ev.target.closest("[data-add-row]");
    if (add) {
      var box = add.parentElement, rows = box.querySelector("[data-rows]"), tpl = box.querySelector("template[data-row-template]");
      if (!rows || !tpl) return;
      if (rows.children.length < (+add.getAttribute("data-max") || 20)) {
        rows.appendChild(tpl.content.cloneNode(true));
        var inputs = rows.lastElementChild.querySelectorAll("input");
        if (inputs.length) inputs[0].focus();
      }
      add.hidden = rows.children.length >= (+add.getAttribute("data-max") || 20);
      return;
    }
    var rm = ev.target.closest("[data-remove-row]");
    if (rm) {
      var box2 = rm.closest("fieldset"), b = box2 && box2.querySelector("[data-add-row]");
      rm.parentElement.remove();
      if (b) b.hidden = false;
    }
  });

  document.addEventListener("change", function (ev) {
    if (ev.target.matches("select[data-autosubmit],input[data-autosubmit]")) ev.target.form.submit();
  });

  document.addEventListener("submit", function (ev) {
    var b = ev.submitter;
    var msg = (b && b.getAttribute("data-confirm")) || ev.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) ev.preventDefault();
  });
})();

// Sidebar clock: the server's time, ticking every second from the value at
// page load (data-ms: Unix ms, data-off: zone offset in seconds).
document.addEventListener("DOMContentLoaded", function () {
  "use strict";
  var el = document.getElementById("clock");
  if (!el) return;
  var delta = Number(el.getAttribute("data-ms")) - Date.now();
  var off = Number(el.getAttribute("data-off")) * 1000;
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };
  setInterval(function () {
    var d = new Date(Date.now() + delta + off); // read in UTC = server zone
    el.textContent = d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) + " " +
      pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds());
  }, 1000);
});

// Only one action menu open at a time.
document.addEventListener("toggle", function (ev) {
  "use strict";
  var d = ev.target;
  if (!(d instanceof HTMLDetailsElement) || !d.open || !d.classList.contains("pop")) return;
  document.querySelectorAll("details.pop[open]").forEach(function (o) { if (o !== d) o.open = false; });
}, true);

// Settings on a narrow screen: the side tabs scroll sideways; show the current one.
document.addEventListener("DOMContentLoaded", function () {
  "use strict";
  var on = document.querySelector(".sidetabs a.on");
  if (on && on.parentElement.scrollWidth > on.parentElement.clientWidth) {
    on.parentElement.scrollLeft = on.offsetLeft - 10;
  }
});

// Forms that wait for a long answer (scripts): show that the page is working.
document.addEventListener("submit", function (ev) {
  "use strict";
  var f = ev.target;
  if (ev.defaultPrevented || !f.hasAttribute("data-busy") || f.classList.contains("busy")) return;
  f.classList.add("busy");
  var p = document.createElement("p");
  p.className = "muted small busy-note";
  p.setAttribute("role", "status");
  p.textContent = f.getAttribute("data-busy");
  f.appendChild(p);
});

// "Select all" checkboxes (data-check-all="field name") and pages that wait
// for an agent (data-autorefresh: reload every 15 s while it is shown).
document.addEventListener("change", function (ev) {
  "use strict";
  var name = ev.target.getAttribute && ev.target.getAttribute("data-check-all");
  if (!name) return;
  ev.target.form.querySelectorAll('input[type=checkbox][name="' + name + '"]').forEach(function (c) { c.checked = ev.target.checked; });
});
document.addEventListener("DOMContentLoaded", function () {
  "use strict";
  if (document.querySelector("[data-autorefresh]")) {
    setTimeout(function () { window.location.reload(); }, 15000);
  }
});

// Report page: print (the browser can save it as PDF).
document.addEventListener("click", function (ev) {
  "use strict";
  if (ev.target.closest && ev.target.closest("[data-print]")) window.print();
});

// Remote desktop in its own window (only the remote screen, like a desktop
// app); if the browser blocks the window, the link opens in this page.
document.addEventListener("click", function (ev) {
  "use strict";
  var a = ev.target.closest && ev.target.closest("a[data-rdwin]");
  if (a) {
    var w = Math.min(screen.availWidth, 1600), h = Math.min(screen.availHeight, 960);
    var url = a.getAttribute("href").split("?")[0] + "?w=1";
    var name = (a.getAttribute("data-winname") || "czrd") + a.getAttribute("data-rdwin");
    var win = window.open(url, name, "popup=yes,width=" + w + ",height=" + h);
    if (win) {
      ev.preventDefault();
      win.focus();
      // A viewer in this page would be a second session: go back to the device.
      if (document.getElementById("rd") || document.getElementById("term")) window.location.href = url.replace(/\/(rd|terminal)\?w=1$/, "");
    }
    return;
  }
  if (ev.target.closest && ev.target.closest("[data-closewin]")) window.close();
});
