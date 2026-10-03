(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var currentPassword = "";

  function post(path, body) {
    return fetch(path, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body), credentials: "same-origin"
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (!r.ok) throw new Error(d.error || ("HTTP " + r.status));
        return d;
      });
    });
  }
  function error(text) { $("msg").textContent = text; $("msg").hidden = !text; }

  $("login-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    error("");
    currentPassword = $("password").value;
    post("/api/login", { user: $("user").value, password: currentPassword }).then(function (r) {
      if (r.mustChange) {
        $("login-form").hidden = true; $("change-form").hidden = false; $("new1").focus();
      } else {
        location.replace("/");
      }
    }).catch(function (e) { $("password").value = ""; error(e.message); });
  });

  $("change-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    if ($("new1").value !== $("new2").value) { error("The passwords do not match"); return; }
    post("/api/password", { current: currentPassword, "new": $("new1").value })
      .then(function () { currentPassword = ""; location.replace("/"); })
      .catch(function (e) { error(e.message); });
  });
})();
