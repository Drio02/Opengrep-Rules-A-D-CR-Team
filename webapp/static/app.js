(function () {
  "use strict";

  var S = { state: null, services: [], resolved: [], labels: {}, version: -1, all: [] };
  var $ = function (id) { return document.getElementById(id); };

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function api(method, path, body) {
    var opts = { method: method, headers: {}, credentials: "same-origin" };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        // session expired / logged out elsewhere / default password must be changed
        if (r.status === 401 || (r.status === 403 && data.mustChange)) { location.replace("/"); }
        if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
        return data;
      });
    });
  }

  function flash(text, isError) {
    var el = $("msg");
    el.textContent = text; el.hidden = false;
    el.className = "msg" + (isError ? " error" : "");
    clearTimeout(flash.t);
    flash.t = setTimeout(function () { el.hidden = true; }, isError ? 9000 : 4000);
  }

  function impactRank(i) {
    var order = S.state ? S.state.impactOrder : [];
    var k = order.indexOf(i); return k < 0 ? order.length : k;
  }
  function label(f) { return S.labels[f.key] || {}; }

  // ---- loading -------------------------------------------------------------
  function loadAll() {
    return Promise.all([api("GET", "/api/state"), api("GET", "/api/findings")]).then(function (r) {
      S.state = r[0];
      S.services = r[1].services || [];
      S.resolved = r[1].resolved || [];
      S.labels = r[1].labels || {};
      S.version = r[0].version;
      S.all = [];
      S.services.forEach(function (s, si) {
        s.findings.forEach(function (f) { f.service = s.name; f.si = si; S.all.push(f); });
      });
      renderSettings(); renderJob(S.state.job); renderGitAccess(); renderPatchers(); renderSummary(); fillFilters(); renderList();
    }).catch(function (e) { flash(e.message, true); });
  }

  // ---- settings / actions ----------------------------------------------------
  var settingsShown = false;
  function renderSettings() {
    var st = S.state.settings;
    if (!settingsShown || document.activeElement !== $("root")) $("root").value = st.root || "";
    if (!settingsShown) {
      $("branch").value = st.branch; $("ssh_key").value = st.ssh_key; $("opengrep").value = st.opengrep;
      $("severity").value = st.severity; $("parallel").value = st.parallel; $("skip_compose").checked = !!st.skip_compose;
      $("allow").value = (st.allow || []).join(", "); $("deny").value = (st.deny || []).join(", ");
      settingsShown = true;
    }
    renderAccessInfo();
    var sc = S.state.scan || {};
    $("last-run").textContent = sc.finished
      ? "Last analysis " + sc.finished.replace("T", " ") + " - " + sc.root +
        (sc.skip_compose ? " - docker-compose skipped" : "") + " - min severity " + sc.severity
      : "No analysis yet - set the services directory and click Run analysis";
    $("btn-report").hidden = !sc.finished;
    $("btn-report").href = "/api/report.html";
  }

  $("root-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    api("POST", "/api/settings", { root: $("root").value }).then(function (r) {
      $("root-info").textContent = r.services.length + " service(s): " + r.services.join(", ");
      flash("Services directory saved"); refresh(true);
    }).catch(function (e) { flash(e.message, true); });
  });

  $("settings-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    api("POST", "/api/settings", {
      branch: $("branch").value, ssh_key: $("ssh_key").value, opengrep: $("opengrep").value,
      severity: $("severity").value, parallel: Number($("parallel").value) || 1,
      skip_compose: $("skip_compose").checked,
      allow: $("allow").value, deny: $("deny").value
    }).then(function () {
      flash("Settings saved - IP rules apply to new connections right away");
      settingsShown = false;   // show the values as the server normalized them
      refresh(true);
    })
      .catch(function (e) { flash(e.message, true); });
  });

  function startJob(path, what) {
    api("POST", path, {}).then(function () { flash(what + " started"); pollJob(); })
      .catch(function (e) { flash(e.message, true); });
  }
  $("btn-scan").addEventListener("click", function () { startJob("/api/scan", "Analysis"); });
  $("btn-pull").addEventListener("click", function () { startJob("/api/pull", "Pull"); });
  $("btn-pull-scan").addEventListener("click", function () { startJob("/api/pull-scan", "Pull + analysis"); });

  // ---- session: user, logout, password -------------------------------------------
  function loadMe() {
    return api("GET", "/api/me").then(function (me) {
      if (!me.user) { location.replace("/"); return; }
      $("whoami").textContent = "Logged in as " + me.user;
      $("default-pw").hidden = !me.defaultPassword;
      S.minPassword = me.minPassword;
      S.myIp = me.ip;
      renderAccessInfo();
    }).catch(function () {});
  }
  function renderAccessInfo() {
    if (!S.state) return;
    var st = S.state.settings, allow = st.allow || [], deny = st.deny || [];
    $("ip-info").textContent = "Your IP as seen by the server: " + (S.myIp || "?") + ". Active now: " +
      (allow.length ? "only " + allow.join(", ") : "every IP") + (deny.length ? ", except " + deny.join(", ") : "") +
      ". Localhost is always allowed, and a rule that would block your own IP is refused.";
  }
  $("btn-logout").addEventListener("click", function () {
    api("POST", "/api/logout", {}).then(function () { location.replace("/"); }, function () { location.replace("/"); });
  });
  $("btn-change-pw").addEventListener("click", function () {
    $("pw-panel").hidden = !$("pw-panel").hidden;
    if (!$("pw-panel").hidden) $("pw-current").focus();
  });
  $("pw-cancel").addEventListener("click", function () { $("pw-form").reset(); $("pw-panel").hidden = true; });
  $("pw-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    if ($("pw-new1").value !== $("pw-new2").value) { flash("The new passwords do not match", true); return; }
    api("POST", "/api/password", { current: $("pw-current").value, "new": $("pw-new1").value }).then(function () {
      $("pw-form").reset(); $("pw-panel").hidden = true; flash("Password changed"); loadMe();
    }).catch(function (e) { flash(e.message, true); });
  });

  // ---- git access (detected at start, before any pull) -----------------------------
  var accessOpenedSettings = false;
  function renderGitAccess() {
    var a = S.state.gitAccess || { state: "none" }, box = $("git-access"), txt = $("git-access-text");
    var jobRunning = S.state.job && S.state.job.state === "running";
    var pullBlocked = a.state === "failed" && !a.running;
    ["btn-pull", "btn-pull-scan"].forEach(function (id) {
      $(id).disabled = jobRunning || pullBlocked;
      $(id).title = pullBlocked ? "No git access to the remotes: fix it first (see the message below)" : "";
    });
    if (a.running && a.state === "none") {
      box.hidden = false; box.className = "access checking";
      txt.textContent = "Checking git access to the service remotes..."; return;
    }
    if (a.state === "none" || !a.hosts) { box.hidden = !a.error; txt.textContent = a.error || ""; return; }
    box.hidden = false;
    box.className = "access " + (a.running ? "checking" : a.state);
    var parts = [];
    if (a.running) parts.push("<div class='sub'>Re-checking...</div>");
    var good = a.hosts.filter(function (h) { return h.ok; }), bad = a.hosts.filter(function (h) { return !h.ok; });
    if (bad.length) {
      parts.push("<div><span class='bad'>Git pull will fail</span> - checked " + esc((a.checked || "").replace("T", " ")) + "</div><ul>" +
        bad.map(function (h) {
          return "<li><span class='host'>" + esc(h.host) + "</span> (" + h.services.length + " service(s): " +
            esc(h.services.join(", ")) + "): <b>" + esc(h.error) + "</b>" + (h.hint ? "<br>Fix: " + esc(h.hint) : "") + "</li>";
        }).join("") + "</ul>");
    }
    if (good.length) {
      parts.push("<div><span class='good'>Git access OK</span>: " + good.map(function (h) {
        return "<span class='host'>" + esc(h.host) + "</span> (" + h.services.length + ")";
      }).join(", ") + "</div>");
    }
    if (a.no_git && a.no_git.length) parts.push("<div class='sub'>Not git repositories (not pulled): " + esc(a.no_git.join(", ")) + "</div>");
    if (a.no_remote && a.no_remote.length) parts.push("<div class='sub'>No 'origin' remote: " + esc(a.no_remote.join(", ")) + "</div>");
    txt.innerHTML = parts.join("");
    // point straight at the field to fix
    if (!accessOpenedSettings && bad.some(function (h) { return /^(auth|key_)/.test(h.kind); })) {
      $("settings").open = true; accessOpenedSettings = true;
    }
  }
  $("btn-git-check").addEventListener("click", function () {
    api("POST", "/api/git-check", {}).then(function (r) {
      S.state.gitAccess = r.gitAccess; renderGitAccess(); setTimeout(function () { refresh(true); }, 1500);
    }).catch(function (e) { flash(e.message, true); });
  });

  // ---- job progress ------------------------------------------------------------
  var STEP_LABEL = { queued: "queued", running: "running...", ok: "ok", failed: "FAILED", skipped: "skipped" };
  function renderJob(job) {
    var running = !!job && job.state === "running";
    ["btn-scan", "btn-pull", "btn-pull-scan"].forEach(function (id) { $(id).disabled = running; });
    var pill = $("job-pill");
    if (!job) { pill.hidden = true; $("job-panel").hidden = true; return; }
    var names = { scan: "Analysis", pull: "Pull", "pull-scan": "Pull + analysis" };
    var failedSteps = 0;
    Object.keys(job.steps).forEach(function (n) {
      ["pull", "scan"].forEach(function (p) { if (job.steps[n][p] && job.steps[n][p].state === "failed") failedSteps++; });
    });
    var shown = job.state === "done" && failedSteps ? "failed" : job.state;
    pill.hidden = false;
    pill.className = "job-pill " + shown;
    pill.textContent = names[job.kind] + ": " + job.state + (failedSteps && job.state !== "running" ? " (" + failedSteps + " failed)" : "");
    $("job-panel").hidden = false;
    $("job-title").textContent = names[job.kind] + " - " + job.state + " (started " + job.started.replace("T", " ") +
      (job.finished ? ", finished " + job.finished.replace("T", " ") : "") + ")" + (job.error ? " - " + job.error : "");
    $("job-steps").innerHTML = Object.keys(job.steps).sort().map(function (name) {
      var st = job.steps[name];
      function cell(p) {
        var x = st[p];
        if (!x) return "<td class='sub'>-</td>";
        return "<td><span class='st " + esc(x.state) + "'>" + esc(STEP_LABEL[x.state] || x.state) + "</span> " +
          "<span class='sub'>" + esc(x.message) + "</span></td>";
      }
      return "<tr><td><b>" + esc(name) + "</b></td>" + cell("pull") + cell("scan") + "</tr>";
    }).join("");
    var log = $("job-log");
    var atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 5;
    log.textContent = job.log.join("\n");
    if (atBottom) log.scrollTop = log.scrollHeight;
  }

  var jobTimer = null;
  function pollJob() {
    clearTimeout(jobTimer);
    api("GET", "/api/job").then(function (r) {
      renderJob(r.job);
      if (r.job && r.job.state === "running") jobTimer = setTimeout(pollJob, 1200);
      else { jobTimer = null; refresh(true); }
    }).catch(function () { jobTimer = setTimeout(pollJob, 3000); });
  }

  // ---- patchers ---------------------------------------------------------------
  function renderPatchers() {
    var defaults = S.state.defaultPatchers;
    $("patchers").innerHTML = S.state.patchers.map(function (p) {
      var isDefault = defaults.indexOf(p) >= 0;
      return "<span class='person" + (isDefault ? " default" : "") + "'>" + esc(p) +
        (isDefault ? "" : "<button type='button' class='rm-patcher' data-name='" + esc(p) + "' title='Remove'>x</button>") + "</span>";
    }).join("");
    var sel = $("f-assignee"), cur = sel.value;
    sel.innerHTML = "<option value=''>Any assignee</option><option value='-'>Unassigned</option>" +
      S.state.patchers.map(function (p) { return "<option>" + esc(p) + "</option>"; }).join("");
    sel.value = cur;
  }
  function addPatcher(name) {
    return api("POST", "/api/patchers", { name: name }).then(function (r) {
      S.state.patchers = r.patchers; renderPatchers(); renderList(); flash(name + " added as patcher");
      return true;
    }).catch(function (e) { flash(e.message, true); return false; });
  }
  $("patcher-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var n = $("patcher-name").value.trim();
    if (n) addPatcher(n).then(function (ok) { if (ok) $("patcher-name").value = ""; });
  });
  $("patchers").addEventListener("click", function (ev) {
    var b = ev.target.closest(".rm-patcher");
    if (!b) return;
    var name = b.getAttribute("data-name");
    if (!confirm("Remove patcher " + name + "? Their findings become unassigned.")) return;
    api("POST", "/api/patchers/remove", { name: name }).then(function () { refresh(true); })
      .catch(function (e) { flash(e.message, true); });
  });

  // ---- summary ------------------------------------------------------------------
  function counts(list) {
    var c = { ERROR: 0, WARNING: 0, INFO: 0, open: 0, in_progress: 0, patched: 0, false_positive: 0 };
    list.forEach(function (f) { c[f.sev] = (c[f.sev] || 0) + 1; c[label(f).status || "open"]++; });
    return c;
  }
  function renderSummary() {
    var c = counts(S.all), imp = {};
    S.all.forEach(function (f) { var i = f.impact || "other"; imp[i] = (imp[i] || 0) + 1; });
    var cards = [["Services", S.services.length], ["Findings", S.all.length], ["Error", c.ERROR],
      ["Warning", c.WARNING], ["Open", c.open], ["Patch in progress", c.in_progress],
      ["Patched in prod", c.patched], ["False positive", c.false_positive],
      ["Resolved since last run", S.resolved.length]];
    Object.keys(imp).sort(function (a, b) { return impactRank(a) - impactRank(b); })
      .forEach(function (i) { cards.push([i, imp[i]]); });
    $("cards").innerHTML = S.all.length || S.services.length ? cards.map(function (x) {
      return "<div class='card'><div class='n'>" + esc(x[1]) + "</div><div class='l'>" + esc(x[0]) + "</div></div>";
    }).join("") : "";

    $("svc-table").hidden = !S.services.length;
    document.querySelector("#svc-table tbody").innerHTML = S.services.map(function (s, si) {
      var k = counts(s.findings), g = s.git || {}, notes = [];
      if (s.missing) notes.push("no results (see scan.log)");
      if (s.binary_only) notes.push("binary-only: reverse it");
      else if (s.binaries && s.binaries.length) notes.push("binaries not analyzed: " + s.binaries.slice(0, 2).join(", "));
      if (s.errors && s.errors.length) notes.push(s.errors.length + " scan error(s)");
      var gitTxt = g.git ? esc(g.branch || "detached") + " @ " + esc(g.head) +
        (g.dirty ? " <span class='pill'>" + g.dirty + " local change(s)</span>" : "") +
        "<div class='sub'>" + esc((g.date || "").replace("T", " ").slice(0, 16)) + " " + esc(g.subject) + "</div>" : "<span class='sub'>no git</span>";
      return "<tr class='svc-row' data-si='" + si + "'><td><b>" + esc(s.name) + "</b><div class='sub'>" +
        esc((s.packs || []).join(" ")) + "</div></td><td>" + gitTxt + "</td><td class='num'>" + s.findings.length +
        "</td><td class='num'>" + k.ERROR + "</td><td class='num'>" + k.WARNING + "</td><td class='num'>" + k.INFO +
        "</td><td class='num'>" + k.open + "</td><td class='num'>" + k.in_progress + "</td><td class='num'>" + k.patched +
        "</td><td class='num'>" + k.false_positive + "</td><td>" + esc(notes.join("; ")) + "</td></tr>";
    }).join("");
  }
  document.querySelector("#svc-table tbody").addEventListener("click", function (ev) {
    var tr = ev.target.closest("tr.svc-row");
    if (!tr) return;
    $("f-svc").value = tr.getAttribute("data-si"); renderList();
    document.querySelector(".toolbar").scrollIntoView({ behavior: "smooth" });
  });

  function fillFilters() {
    var sv = $("f-svc"), cur = sv.value;
    sv.innerHTML = "<option value=''>All services</option>" + S.services.map(function (s, si) {
      return "<option value='" + si + "'>" + esc(s.name) + "</option>";
    }).join("");
    sv.value = cur;
    var im = $("f-imp"), curI = im.value, imps = {};
    S.all.forEach(function (f) { imps[f.impact || "other"] = 1; });
    im.innerHTML = "<option value=''>All impacts</option>" + Object.keys(imps)
      .sort(function (a, b) { return impactRank(a) - impactRank(b); })
      .map(function (i) { return "<option>" + esc(i) + "</option>"; }).join("");
    im.value = curI;
  }

  // ---- findings ---------------------------------------------------------------
  function visible() {
    var q = $("q").value.trim().toLowerCase();
    var sevs = Array.prototype.filter.call(document.querySelectorAll(".sev"), function (c) { return c.checked; })
      .map(function (c) { return c.value; });
    var si = $("f-svc").value, imp = $("f-imp").value, st = $("f-status").value, who = $("f-assignee").value;
    var onlyNew = $("f-new").checked;
    return S.all.filter(function (f) {
      var l = label(f);
      if (sevs.indexOf(f.sev) < 0) return false;
      if (si !== "" && String(f.si) !== si) return false;
      if (imp && (f.impact || "other") !== imp) return false;
      if (st === "open" && l.status) return false;
      if (st === "todo" && (l.status === "patched" || l.status === "false_positive")) return false;
      if (st && st !== "open" && st !== "todo" && l.status !== st) return false;
      if (who === "-" && l.assignee) return false;
      if (who && who !== "-" && l.assignee !== who) return false;
      if (onlyNew && !f.new) return false;
      if (q) {
        var hay = (f.rule + " " + f.path + " " + f.message + " " + f.code + " " + f.service + " " + f.cwe + " " +
          (l.assignee || "")).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });
  }

  function ctxHtml(f) {
    if (f.context && f.context.length) {
      return "<pre class='ctx'>" + f.context.map(function (l) {
        return "<span class='ln" + (l[2] ? " hit" : "") + "'><span class='no'>" + esc(l[0]) + "</span>" + esc(l[1]) + "</span>";
      }).join("") + "</pre>";
    }
    return f.code ? "<pre class='ctx'><span class='ln hit'><span class='no'>" + f.line + "</span>" + esc(f.code) + "</span></pre>" : "";
  }

  function findingHtml(f, readOnly) {
    var l = label(f), st = l.status || "";
    var statusSel = "<select class='set-status' data-key='" + f.key + "' title='Label'>" +
      Object.keys(S.state.statuses).map(function (k) {
        return "<option value='" + k + "'" + (k === st ? " selected" : "") + ">" + esc(S.state.statuses[k]) + "</option>";
      }).join("") + "</select>";
    var who = l.assignee || "";
    var whoSel = "<select class='set-assignee' data-key='" + f.key + "' title='Patcher'>" +
      "<option value=''>Unassigned</option>" + S.state.patchers.map(function (p) {
        return "<option" + (p === who ? " selected" : "") + ">" + esc(p) + "</option>";
      }).join("") + "<option value='__add__'>+ Add patcher...</option></select>";
    var right = readOnly
      ? (st ? "<span class='pill lab-" + st + "'>" + esc(S.state.statuses[st]) + "</span>" : "") +
        (who ? "<span class='pill'>" + esc(who) + "</span>" : "")
      : statusSel + whoSel;
    return "<div class='f " + f.sev + (st ? " lab-" + st : "") + "'>" +
      "<div class='fh'><span class='badge " + f.sev + "'>" + f.sev + "</span>" +
      (f.new ? "<span class='badge new' title='Not in the previous analysis'>NEW</span>" : "") +
      (f.impact ? "<span class='pill imp'>" + esc(f.impact) + "</span>" : "") +
      "<span class='rule'>" + esc(f.rule) + "</span>" +
      "<span class='loc' title='Click to copy' data-loc='" + esc(f.service + "/" + f.path + ":" + f.line) + "'>" +
      (readOnly ? esc(f.service) + "/" : "") + esc(f.path) + ":" + f.line + "</span>" +
      (f.cwe ? "<span class='pill'>" + esc(f.cwe) + "</span>" : "") +
      (f.confidence ? "<span class='pill'>conf " + esc(f.confidence) + "</span>" : "") +
      "<span class='right'>" + right + "</span></div>" +
      "<div class='msgtext'>" + esc(f.message) + "</div>" + ctxHtml(f) + "</div>";
  }

  var openGroups = {};
  function renderList() {
    if (!S.state) return;
    var list = visible(), mode = $("group").value, groups = {}, order = [];
    list.forEach(function (f) {
      var k = mode === "service" ? f.service : mode === "rule" ? f.rule :
        mode === "impact" ? (f.impact || "other") : (label(f).assignee || "Unassigned");
      if (!groups[k]) { groups[k] = []; order.push(k); }
      groups[k].push(f);
    });
    if (mode === "impact") order.sort(function (a, b) { return impactRank(a) - impactRank(b); });
    if (mode === "rule" || mode === "assignee") order.sort(function (a, b) { return groups[b].length - groups[a].length; });
    var out = order.map(function (k) {
      var g = groups[k], c = counts(g), gid = mode + ":" + k;
      var open = openGroups[gid] !== false;
      var extra = "";
      if (mode === "service" && S.services[g[0].si].binary_only)
        extra = "<div class='warnbox'>Binary-only service: opengrep could not analyze it. Reverse the binary.</div>";
      return "<details class='group' data-gid='" + esc(gid) + "'" + (open ? " open" : "") + "><summary>" + esc(k) +
        "<span class='meta'>" + g.length + " finding(s) - " + c.ERROR + " error - " + c.open + " open - " +
        c.in_progress + " in progress - " + c.patched + " patched</span></summary>" + extra +
        g.map(function (f) { return findingHtml(f, false); }).join("") + "</details>";
    });
    if (mode === "service" && !$("q").value && $("f-svc").value === "") {
      S.services.forEach(function (s) {
        if (groups[s.name]) return;
        var why = s.binary_only ? "binary-only service, not analyzed - reverse it" :
          s.missing ? "no results (see scan.log)" : s.findings.length ? "all findings filtered out" : "no findings";
        out.push("<details class='group'><summary>" + esc(s.name) + "<span class='meta'>" + esc(why) + "</span></summary></details>");
      });
    }
    $("list").innerHTML = out.join("") || (S.services.length
      ? "<div class='empty'>No findings match the current filters.</div>"
      : "<div class='empty'>No analysis yet.</div>");
    $("count").textContent = list.length + " / " + S.all.length + " shown";

    $("resolved").innerHTML = S.resolved.length
      ? "<details class='group resolved'><summary>Resolved since the previous analysis<span class='meta'>" +
        S.resolved.length + " finding(s) no longer detected - check that the service still works</span></summary>" +
        S.resolved.map(function (f) { return findingHtml(f, true); }).join("") + "</details>"
      : "";
  }

  $("list").addEventListener("toggle", function (ev) {
    var d = ev.target;
    if (d.classList && d.classList.contains("group")) openGroups[d.getAttribute("data-gid")] = d.open;
  }, true);

  // label / assignee changes
  $("list").addEventListener("change", function (ev) {
    var t = ev.target, key = t.getAttribute("data-key");
    if (!key) return;
    var body = {};
    if (t.classList.contains("set-status")) body.status = t.value;
    if (t.classList.contains("set-assignee")) {
      if (t.value === "__add__") {
        var name = (prompt("New patcher name:") || "").trim();
        if (!name) { t.value = label({ key: key }).assignee || ""; return; }
        addPatcher(name).then(function (ok) {
          if (ok) setLabel(key, { assignee: name });
          else renderList();
        });
        return;
      }
      body.assignee = t.value;
    }
    setLabel(key, body);
  });
  function setLabel(key, body) {
    body.key = key;
    api("POST", "/api/label", body).then(function (r) {
      if (r.label.status || r.label.assignee) S.labels[key] = r.label; else delete S.labels[key];
      S.version = r.version;
      renderSummary(); renderList();
    }).catch(function (e) { flash(e.message, true); renderList(); });
  }

  document.body.addEventListener("click", function (ev) {
    var t = ev.target;
    if (!t.classList.contains("loc")) return;
    var v = t.getAttribute("data-loc");
    if (navigator.clipboard) navigator.clipboard.writeText(v).then(function () { flash("Copied " + v); }, function () {});
  });

  ["q", "f-svc", "f-imp", "f-status", "f-assignee", "group"].forEach(function (id) {
    $(id).addEventListener("input", renderList);
  });
  $("f-new").addEventListener("change", renderList);
  Array.prototype.forEach.call(document.querySelectorAll(".sev"), function (c) { c.addEventListener("change", renderList); });

  // ---- live updates (teammates labelling at the same time) ----------------------
  function refresh(force) {
    var busy = document.activeElement && document.activeElement.tagName === "SELECT" &&
      document.activeElement.closest("#list");
    if (busy && !force) return Promise.resolve();
    return loadAll();
  }
  setInterval(function () {
    api("GET", "/api/version").then(function (r) {
      if (r.job === "running" && !jobTimer) pollJob();
      if (r.version !== S.version) refresh(false);
    }).catch(function () {});
  }, 4000);

  loadMe();
  loadAll().then(function () {
    if (S.state && S.state.job && S.state.job.state === "running") pollJob();
  });
})();
