/* cwift.net — navigation, order form, photo uploader. No dependencies. */
(function () {
  "use strict";
  var t0 = Date.now();

  // mobile nav
  var tog = document.querySelector(".nav-toggle"), nav = document.getElementById("site-nav");
  if (tog && nav) {
    tog.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      tog.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // signed form token (shared by the order form and the uploader)
  var tokenPromise = null;
  function getToken() {
    if (!tokenPromise) {
      tokenPromise = fetch("/api/form-token", { cache: "no-store" })
        .then(function (r) { return r.ok ? r.json() : { token: "" }; })
        .then(function (j) { return j.token || ""; })
        .catch(function () { return ""; });
    }
    return tokenPromise;
  }
  if (document.querySelector("[data-needs-token]")) getToken();

  function qs(name) {
    var m = new RegExp("[?&]" + name + "=([^&]*)").exec(location.search);
    return m ? decodeURIComponent(m[1].replace(/\+/g, " ")) : "";
  }

  // ---------------- order form ----------------
  var form = document.getElementById("order-form");
  if (form) {
    var when = form.querySelectorAll("input[name=valuation]");
    var dateWrap = document.getElementById("date-wrap");
    var purposeSel = form.querySelector("select[name=purpose]");
    var pre = qs("purpose");
    if (pre && purposeSel) {
      for (var i = 0; i < purposeSel.options.length; i++) {
        if (purposeSel.options[i].value === pre) purposeSel.selectedIndex = i;
      }
    }
    var svc = qs("service");
    if (svc) {
      var r = form.querySelector("input[name=service][value='" + svc.replace(/[^a-z-]/g, "") + "']");
      if (r) r.checked = true;
    }
    function syncDate() {
      var past = form.querySelector("input[name=valuation]:checked");
      var show = past && past.value === "past";
      if (dateWrap) {
        dateWrap.style.display = show ? "" : "none";
        var d = dateWrap.querySelector("input");
        if (d) d.required = !!show;
      }
    }
    for (var k = 0; k < when.length; k++) when[k].addEventListener("change", syncDate);
    if (purposeSel) purposeSel.addEventListener("change", function () {
      var past = ["date-of-death", "gift-tax", "prop-19", "property-tax-appeal"];
      if (past.indexOf(purposeSel.value) > -1) {
        var p = form.querySelector("input[name=valuation][value=past]");
        if (p) { p.checked = true; syncDate(); }
      }
    });
    syncDate();

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var msg = document.getElementById("order-msg");
      var btn = form.querySelector("button[type=submit]");
      msg.className = "form-msg"; msg.textContent = "";
      btn.disabled = true; btn.textContent = "Sending…";
      getToken().then(function (tok) {
        var fd = new FormData(form);
        fd.set("form_token", tok);
        fd.set("dwell_ms", String(Date.now() - t0));
        return fetch(form.action, { method: "POST", body: fd, headers: { Accept: "application/json" } });
      }).then(function (r) {
        return r.json().catch(function () { return { ok: false }; });
      }).then(function (j) {
        if (j && j.ok) {
          var email = form.querySelector("[name=email]").value;
          var addr = [form.querySelector("[name=street]").value, form.querySelector("[name=city]").value,
                      form.querySelector("[name=zip]").value].filter(Boolean).join(", ");
          form.style.display = "none";
          var ok = document.getElementById("order-success");
          ok.classList.add("show");
          var up = document.getElementById("uploader");
          if (up) { up.querySelector("[name=email]").value = email; up.querySelector("[name=property_address]").value = addr; }
          ok.scrollIntoView({ behavior: "smooth", block: "start" });
        } else {
          msg.className = "form-msg err";
          msg.textContent = (j && j.error) ? j.error : "Something went wrong. Please email contact@cwift.net and we'll take it from there.";
          btn.disabled = false; btn.textContent = "Send my request";
          if (window.turnstile) try { window.turnstile.reset(); } catch (e) {}
        }
      }).catch(function () {
        msg.className = "form-msg err";
        msg.textContent = "Connection problem. Please try again, or email contact@cwift.net.";
        btn.disabled = false; btn.textContent = "Send my request";
      });
    });
  }

  // ---------------- photo uploader ----------------
  var up = document.getElementById("uploader");
  if (up) {
    var input = up.querySelector("input[type=file]");
    var zone = up.querySelector(".dropzone");
    var list = up.querySelector(".file-list");
    var bar = up.querySelector(".progress");
    var fill = bar ? bar.querySelector("span") : null;
    var sendBtn = up.querySelector("button[type=submit]");
    var umsg = up.querySelector(".form-msg");
    var done = up.querySelector(".upload-done");
    var files = [];
    var MAX = 25 * 1024 * 1024;
    if (!up.querySelector("[name=email]").value) up.querySelector("[name=email]").value = qs("email");
    if (!up.querySelector("[name=property_address]").value) up.querySelector("[name=property_address]").value = qs("address");

    function render() {
      list.innerHTML = "";
      files.forEach(function (f) {
        var li = document.createElement("li");
        var a = document.createElement("span"); a.textContent = f.name;
        var b = document.createElement("span"); b.textContent = (f.size / 1048576).toFixed(1) + " MB";
        li.appendChild(a); li.appendChild(b); list.appendChild(li);
      });
      sendBtn.textContent = files.length ? "Upload " + files.length + " file" + (files.length > 1 ? "s" : "") : "Upload photos";
    }
    function addFiles(fl) {
      for (var i = 0; i < fl.length; i++) {
        if (fl[i].size > MAX) { umsg.className = "form-msg err"; umsg.textContent = fl[i].name + " is over 25 MB; please email it instead."; continue; }
        files.push(fl[i]);
      }
      render();
    }
    zone.addEventListener("click", function () { input.click(); });
    zone.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
    input.addEventListener("change", function () { addFiles(input.files); input.value = ""; });
    ["dragenter", "dragover"].forEach(function (n) { zone.addEventListener(n, function (e) { e.preventDefault(); zone.classList.add("drag"); }); });
    ["dragleave", "drop"].forEach(function (n) { zone.addEventListener(n, function (e) { e.preventDefault(); zone.classList.remove("drag"); }); });
    zone.addEventListener("drop", function (e) { if (e.dataTransfer) addFiles(e.dataTransfer.files); });

    up.addEventListener("submit", function (ev) {
      ev.preventDefault();
      umsg.className = "form-msg"; umsg.textContent = "";
      var email = up.querySelector("[name=email]").value.trim();
      var addr = up.querySelector("[name=property_address]").value.trim();
      var notes = (up.querySelector("[name=notes]") || { value: "" }).value;
      if (!email || !addr) { umsg.className = "form-msg err"; umsg.textContent = "Please enter your email and the property address."; return; }
      if (!files.length) { umsg.className = "form-msg err"; umsg.textContent = "Choose at least one photo."; return; }
      sendBtn.disabled = true; bar.style.display = "block";
      var folder = "", n = files.length, idx = 0;
      getToken().then(function (tok) {
        function next() {
          if (idx >= n) {
            sendBtn.textContent = "Uploaded";
            up.querySelector(".up-fields").style.display = "none";
            done.style.display = "block";
            return;
          }
          var fd = new FormData();
          fd.append("file", files[idx]);
          fd.append("email", email);
          fd.append("property_address", addr);
          fd.append("folder_id", folder);
          fd.append("is_last", idx === n - 1 ? "true" : "false");
          fd.append("total_count", String(n));
          fd.append("notes", notes);
          fd.append("_token", tok);
          fd.append("website", up.querySelector("[name=website]").value);
          sendBtn.textContent = "Uploading " + (idx + 1) + " of " + n + "…";
          fetch("/api/upload-photos", { method: "POST", body: fd })
            .then(function (r) { return r.json().catch(function () { return {}; }); })
            .then(function (j) {
              if (!j || !j.success) throw new Error((j && j.error) || "Upload failed");
              folder = j.folderId || folder; idx++;
              fill.style.width = Math.round(idx / n * 100) + "%";
              next();
            })
            .catch(function (e) {
              umsg.className = "form-msg err";
              umsg.textContent = e.message + " — you can also email photos to contact@cwift.net.";
              sendBtn.disabled = false; sendBtn.textContent = "Retry upload";
              files = files.slice(idx); n = files.length; idx = 0;
            });
        }
        next();
      });
    });
  }
})();
