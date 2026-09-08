const TOKEN = location.hash.slice(1);
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));

const icon = (n, cls = "") =>
  `<svg class="ic ${cls}" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-${n}"/></svg>`;

// --- feedback -----------------------------------------------------------
// Native alert/confirm/prompt block the page and can't be styled; these are
// the replacements used everywhere.

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.innerHTML = icon(kind === "ok" ? "check" : "alert") + `<span>${esc(msg)}</span>`;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), kind === "err" ? 7000 : 4000);
}

function confirmDlg(title, body, yesLabel = "Delete") {
  return new Promise((resolve) => {
    $("#confirm-title").textContent = title;
    $("#confirm-body").textContent = body || "";
    $("#confirm-yes").textContent = yesLabel;
    const dlg = $("#confirm-dlg");
    const done = (v) => { resolve(v); dlg.close(); };
    $("#confirm-yes").onclick = () => done(true);
    $("#confirm-no").onclick = () => done(false);
    dlg.onclose = () => resolve(false);        // Esc / backdrop = no
    dlg.showModal();
    $("#confirm-no").focus();                  // destructive action never pre-focused
  });
}

// A click-to-choose list. Replaces typing a name into prompt().
function pick(title, note, items) {
  return new Promise((resolve) => {
    $("#pick-title").textContent = title;
    $("#pick-note").textContent = note || "";
    const list = $("#pick-list");
    list.innerHTML = items.map((it, i) =>
      `<button class="pick-row" data-i="${i}">${icon("zap")}<span>${esc(it.label)}</span>${
        it.hint ? `<small>${esc(it.hint)}</small>` : ""}</button>`).join("");
    const dlg = $("#pick-dlg");
    const done = (v) => { resolve(v); dlg.close(); };
    list.querySelectorAll(".pick-row").forEach((b) =>
      b.onclick = () => done(items[+b.dataset.i].value));
    $("#pick-cancel").onclick = () => done(null);
    dlg.onclose = () => resolve(null);
    dlg.showModal();
    list.querySelector(".pick-row")?.focus();
  });
}

// --- chrome theme -------------------------------------------------------
function applyChromeTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  $("#theme-btn").innerHTML = icon(t === "light" ? "moon" : "sun");
  try { localStorage.setItem("chromeTheme", t); } catch {}
}
$("#theme-btn").onclick = () => {
  const t = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  applyChromeTheme(t);
  // Keep terminals readable next to the new chrome. Only on an explicit toggle,
  // so a terminal theme picked in prefs survives a reload; prefs still overrides.
  termPrefs.theme = t === "light" ? "light" : "shelldeck";
  try { localStorage.setItem("termPrefs", JSON.stringify(termPrefs)); } catch {}
  applyPrefs();
};
applyChromeTheme((() => {
  try { return localStorage.getItem("chromeTheme") || "dark"; } catch { return "dark"; }
})());

async function api(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: { "Authorization": "Bearer " + TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.status);
  return r.json();
}

// --- vault gate ---------------------------------------------------------

async function refreshGate() {
  const v = await api("/api/vault");
  $("#gate-hint").textContent = v.exists ? "Unlock your vault" : "Create a master password (8+ chars)";
  $("#gate").hidden = v.unlocked;
  $("#app").hidden = !v.unlocked;
  if (v.unlocked) { loadTree(); loadVpns(); render(); }
  else { clearTimeout(vpnTimer); $("#master").focus(); }
}

$("#unlock-form").onsubmit = async (e) => {
  e.preventDefault();
  $("#gate-error").textContent = "";
  try {
    await api("/api/vault/unlock", { method: "POST", body: JSON.stringify({ password: $("#master").value }) });
    $("#master").value = "";
    await refreshGate();
  } catch (err) { $("#gate-error").textContent = err.message; }
};

$("#passwd-btn").onclick = () => {
  $("#passwd-form").reset();
  $("#passwd-error").textContent = "";
  $("#passwd-dlg").showModal();
};
$("#passwd-dlg").onclose = async () => {
  if ($("#passwd-dlg").returnValue !== "save") return;
  const f = $("#passwd-form");
  const [old, nw, nw2] = [f.old.value, f.new.value, f.new2.value];
  if (nw !== nw2) { toastPasswd("The two new passwords do not match"); return; }
  try {
    await api("/api/vault/change", { method: "POST", body: JSON.stringify({ old, new: nw }) });
    toast("Master password changed — use the new one next time you unlock.", "ok");
  } catch (err) { toastPasswd(err.message); }
};
// Re-open the dialog with the error, since a dialog cannot show one after it closed.
function toastPasswd(msg) {
  $("#passwd-error").textContent = msg;
  $("#passwd-dlg").showModal();
}

$("#lock-btn").onclick = async () => {
  await api("/api/vault/lock", { method: "POST" });
  tabs.slice().forEach(closeTab);
  await refreshGate();
};

// --- connection tree ----------------------------------------------------

let conns = [];

async function loadTree() {
  conns = await api("/api/connections");
  renderTree();
}

// Everything a person might type when hunting for a host. Joined with spaces:
// concatenating name+host directly let "app110" match "app1" + "10.2.137.119".
function searchText(c) {
  return [c.name, c.host, c.serial_device, c.user, c.group, c.proto,
          c.port, c.jump ? nameOf(c.jump) : ""]
    .filter(Boolean).join(" ").toLowerCase();
}

// Every term must match, so "star db" narrows to db hosts in the STAR group.
function matchesFilter(c, terms) {
  if (!terms.length) return true;
  const hay = searchText(c);
  return terms.every((t) => hay.includes(t));
}

function renderTree() {
  const terms = $("#filter").value.toLowerCase().split(/\s+/).filter(Boolean);
  const groups = {};
  for (const c of conns.filter((c) => matchesFilter(c, terms)))
    (groups[c.group || "Ungrouped"] ??= []).push(c);

  const shown = Object.values(groups).reduce((n, l) => n + l.length, 0);
  if (!shown) {
    $("#tree").innerHTML = conns.length
      ? `<div class="empty">${icon("search")}<div>No connections match &ldquo;${esc($("#filter").value)}&rdquo;</div></div>`
      : `<div class="empty">${icon("server")}
           <div>No connections yet</div>
           <button class="btn primary" id="empty-new">${icon("plus")}<span>Add a connection</span></button>
           <button class="btn ghost" id="empty-import">${icon("download")}<span>Import from ssh_config</span></button>
         </div>`;
    const en = $("#empty-new"), ei = $("#empty-import");
    if (en) en.onclick = () => openEditor(null);
    if (ei) ei.onclick = () => $("#import-btn").click();
    return;
  }

  $("#tree").innerHTML = Object.entries(groups).map(([g, list]) => {
    const gval = list[0].group || "";
    const shut = collapsed.has(gval);
    return `
    <div class="group ${shut ? "collapsed" : ""}" data-group="${esc(gval)}">
      <div class="group-name" data-group="${esc(gval)}" role="button" tabindex="0"
           aria-expanded="${!shut}" aria-label="${esc(g)} group, ${list.length} connections">
        <span class="caret">${icon("chevron-down")}</span><span>${esc(g)}</span>
        <span class="group-count">${list.length}</span>
        <button class="group-open" data-group="${esc(gval)}"
                aria-label="Open all ${list.length} connections in ${esc(g)} in one tab"
                title="Open all in one tab (for broadcast)">${icon("grid")}</button>
      </div>
      <div class="group-body">
      ${list.map((c) => `
        <div class="conn" draggable="true" data-id="${c.id}" role="button" tabindex="0"
             aria-label="Open ${esc(c.name)}, ${esc(c.user)}@${esc(c.host)}">
          ${icon(c.proto === "serial" ? "sliders" : c.proto === "telnet" ? "server" : "terminal", "conn-ic")}
          <span class="conn-name">${esc(c.name)}${
            c.autorun_macro ? icon("zap", "conn-badge") : ""}</span>
          <span class="conn-host">${esc(c.user ? c.user + "@" : "")}${esc(c.host || c.serial_device || "")}${
            c.jump ? " &#8674; " + esc(nameOf(c.jump)) : ""}${
            c.forwards && c.forwards.length ? " &middot; " + c.forwards.length + "&#8644;" : ""}</span>
          <span class="conn-actions">
            <button class="sftp" data-id="${c.id}" aria-label="Browse files on ${esc(c.name)}"
                    title="Browse files (SFTP)">${icon("folder")}</button>
            <button class="clone" data-id="${c.id}" aria-label="Clone ${esc(c.name)}"
                    title="Clone">${icon("copy")}</button>
            <button class="edit" data-id="${c.id}" aria-label="Edit ${esc(c.name)}"
                    title="Edit">${icon("edit")}</button>
            <button class="del" data-id="${c.id}" aria-label="Delete ${esc(c.name)}"
                    title="Delete">${icon("trash")}</button>
          </span>
        </div>`).join("")}
      </div>
    </div>`;
  }).join("");

  $("#tree").querySelectorAll(".group-name").forEach((h) => {
    const toggle = () => {
      const g = h.dataset.group;
      collapsed.has(g) ? collapsed.delete(g) : collapsed.add(g);
      saveCollapsed();
      h.closest(".group").classList.toggle("collapsed");
      h.setAttribute("aria-expanded", String(!collapsed.has(g)));  // caret rotates via CSS
    };
    h.onclick = (e) => { if (!e.target.closest(".group-open")) toggle(); };
    h.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
    };
  });
  $("#tree").querySelectorAll(".group-open").forEach((b) =>
    b.onclick = (e) => { e.stopPropagation(); openGroup(b.dataset.group); });

  $("#tree").querySelectorAll(".conn").forEach((el) => {
    el.onclick = (e) => {
      if (e.target.closest("button")) return;
      // Ctrl/Cmd-click splits into the current tab instead of opening a new one.
      openSession(el.dataset.id, "term", e.ctrlKey || e.metaKey);
    };
    // Enter/Space open it; Ctrl+Enter splits. Without this the tree is
    // mouse-only and the whole app is unusable from the keyboard.
    el.onkeydown = (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      e.preventDefault();
      openSession(el.dataset.id, "term", e.ctrlKey || e.metaKey);
    };
  });
  const on = (cls, fn) => $("#tree").querySelectorAll(cls).forEach((b) =>
    b.onclick = (e) => { e.stopPropagation(); fn(b.dataset.id, e); });
  on(".sftp", (id, e) => openSession(id, "sftp", e.ctrlKey || e.metaKey));
  on(".edit", (id) => openEditor(conns.find((c) => c.id === id)));
  // The clone lands in the same group as "<name>-1" with the credentials copied.
  // Then open it for editing, since you clone a host in order to change something.
  on(".clone", async (id) => {
    try {
      const clone = await api(`/api/connections/${id}/clone`, { method: "POST" });
      await loadTree();
      toast(`Cloned as ${clone.name}`, "ok");
      openEditor(conns.find((c) => c.id === clone.id));
    } catch (err) { toast("Could not clone: " + err.message, "err"); }
  });
  on(".del", async (id) => {
    const c = conns.find((x) => x.id === id);
    if (!await confirmDlg(`Delete ${c ? c.name : "this connection"}?`,
        "This also deletes its stored password or key from the vault.")) return;
    await api("/api/connections/" + id, { method: "DELETE" });
    loadTree();
  });
  wireDragDrop();
}

function wireDragDrop() {
  let dragId = null;
  $("#tree").querySelectorAll(".conn").forEach((el) => {
    el.addEventListener("dragstart", (e) => {
      dragId = el.dataset.id;
      e.dataTransfer.effectAllowed = "move";
      el.classList.add("dragging");
    });
    el.addEventListener("dragend", () => {
      dragId = null;
      $("#tree").querySelectorAll(".drop-into").forEach((g) => g.classList.remove("drop-into"));
      el.classList.remove("dragging");
    });
  });
  $("#tree").querySelectorAll(".group").forEach((g) => {
    g.addEventListener("dragover", (e) => { e.preventDefault(); g.classList.add("drop-into"); });
    g.addEventListener("dragleave", () => g.classList.remove("drop-into"));
    g.addEventListener("drop", async (e) => {
      e.preventDefault();
      g.classList.remove("drop-into");
      const conn = conns.find((c) => c.id === dragId);
      const target = g.dataset.group;
      if (!conn || conn.group === target) return;
      conn.group = target;                 // optimistic: move now, persist next
      renderTree();
      await saveConn(conn);
      loadTree();
    });
  });
}

// Re-save a connection without touching its secrets. Blank secret fields mean
// "unchanged" server-side, so grouping never disturbs a stored key or password.
function saveConn(conn) {
  return api("/api/connections", {
    method: "POST",
    body: JSON.stringify({ ...conn, forwards: (conn.forwards || []).join("\n") }),
  });
}

const nameOf = (id) => (conns.find((c) => c.id === id) || {}).name || "?";

const collapsed = new Set(load("collapsedGroups"));
function load(key) { try { return JSON.parse(localStorage.getItem(key)) || []; } catch { return []; } }
function saveCollapsed() { try { localStorage.setItem("collapsedGroups", JSON.stringify([...collapsed])); } catch {} }
$("#filter").oninput = renderTree;

// --- editor -------------------------------------------------------------

function resetForm(f) {
  f.reset();
  // input[type=hidden] keeps its value in the content attribute, so assigning
  // .value makes it the default and reset() restores it instead of clearing.
  // Without this, editing once then adding a new entry overwrites the edited one.
  f.querySelectorAll("input[type=hidden]").forEach((h) => h.value = "");
}

function openEditor(conn) {
  const f = $("#conn-form");
  resetForm(f);
  f.jump.innerHTML = '<option value="">&mdash; direct &mdash;</option>' +
    conns.filter((c) => c.id !== (conn && conn.id))
         .map((c) => `<option value="${c.id}">${esc(c.name)} (${esc(c.host)})</option>`).join("");
  if (conn) for (const [k, v] of Object.entries(conn)) {
    if (!f[k]) continue;
    if (f[k].type === "checkbox") f[k].checked = !!v;
    else f[k].value = Array.isArray(v) ? v.join("\n") : v;
  }
  syncProtoFields();
  populateAttachMacros(conn);
  $("#editor").showModal();
}

// Attach macros to this connection: checkboxes drive which appear on its ⚡ menu,
// and the "run on connect" dropdown is filled from whatever is ticked.
async function populateAttachMacros(conn) {
  await loadMacros();
  const list = $("#attach-list");
  const attached = new Set((conn && conn.macros) || []);
  if (!macros.length) {
    list.innerHTML = '<div class="hint">No macros yet — create one with the ⚡ button first.</div>';
  } else {
    list.innerHTML = macros.map((m) =>
      `<label><input type="checkbox" class="attach-cb" value="${esc(m.name)}" ${
        attached.has(m.name) ? "checked" : ""}> ⚡ ${esc(m.name)}</label>`).join("");
  }
  const cur = (conn && conn.autorun_macro) || "";
  const refreshAutorun = () => {
    const checked = [...list.querySelectorAll(".attach-cb:checked")].map((c) => c.value);
    const sel = $("#conn-form").autorun_macro;
    sel.innerHTML = '<option value="">— none —</option>' +
      checked.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
    sel.value = checked.includes(cur) ? cur : "";
  };
  list.querySelectorAll(".attach-cb").forEach((cb) => cb.onchange = refreshAutorun);
  refreshAutorun();
}

function syncAuthFields() {
  const mode = $("#conn-form").auth.value;
  document.querySelectorAll(".auth-password").forEach((e) => e.hidden = mode !== "password");
  document.querySelectorAll(".auth-key").forEach((e) => e.hidden = mode !== "key");
}
function syncProtoFields() {
  const p = $("#conn-form").proto.value;
  document.querySelectorAll(".proto-ssh").forEach((e) => e.hidden = p !== "ssh");
  document.querySelectorAll(".proto-net").forEach((e) => e.hidden = p === "serial");
  document.querySelectorAll(".proto-serial").forEach((e) => e.hidden = p !== "serial");
  // host/user aren't required for serial; avoid the browser blocking a hidden field
  const f = $("#conn-form");
  f.host.required = p !== "serial";
  f.user.required = p === "ssh";
  if (p === "ssh") syncAuthFields();
}
$("#conn-form").proto.onchange = syncProtoFields;
$("#conn-form").auth.onchange = syncAuthFields;
$("#new-btn").onclick = () => openEditor(null);

// --- import -------------------------------------------------------------

let importSource = null;

$("#logs-btn").onclick = openLogs;
$("#logs-close").onclick = () => $("#logs-dlg").close();
$("#log-view-close").onclick = () => { stopPlayback(); $("#log-view").close(); };

let logPlayer = null;         // { term, timer, cancelled }

function stopPlayback() {
  if (logPlayer) { logPlayer.cancelled = true; clearTimeout(logPlayer.timer); }
  if (logPlayer?.term) { logPlayer.term.dispose(); logPlayer = null; }
  $("#log-term").hidden = true;
  $("#log-status").textContent = "";
}

async function openLogView(file) {
  stopPlayback();
  $("#log-view-name").textContent = file;
  $("#log-view-text").hidden = false;
  $("#log-term").hidden = true;
  $("#log-toggle").textContent = "Show as text";
  const r = await fetch("/api/logs/" + encodeURIComponent(file),
    { headers: { "Authorization": "Bearer " + TOKEN } });
  $("#log-view-text").textContent = r.ok ? await r.text() : "could not open: " + r.status;
  $("#log-view").dataset.file = file;
  $("#log-view").showModal();
}

$("#log-toggle").onclick = () => {
  const showingText = !$("#log-view-text").hidden;
  stopPlayback();
  $("#log-view-text").hidden = showingText ? true : false;
  $("#log-toggle").textContent = showingText ? "Show as text" : "Show as text";
};

$("#log-play").onclick = async () => {
  const file = $("#log-view").dataset.file;
  const speed = +$("#log-speed").value;
  stopPlayback();
  $("#log-view-text").hidden = true;
  $("#log-term").hidden = false;
  const data = await api("/api/logs/" + encodeURIComponent(file) + "/frames");
  const frames = data.frames.map(([ms, b64]) =>
    [ms, Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))]);
  const term = new Terminal(termOptions());
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($("#log-term"));
  try { fit.fit(); } catch {}
  const player = { term, cancelled: false, timer: null };
  logPlayer = player;

  let i = 0, last = 0;
  const step = () => {
    if (player.cancelled || i >= frames.length) {
      if (!player.cancelled) $("#log-status").textContent = "— end of recording —";
      return;
    }
    const [ms, bytes] = frames[i++];
    term.write(bytes);
    $("#log-status").textContent = `playing… ${i}/${frames.length}`;
    // real gap between frames, capped at 2s so idle stretches don't stall playback
    let gap = Math.min(2000, Math.max(0, ms - last)) / speed;
    last = ms;
    player.timer = setTimeout(step, gap);
  };
  step();
};

async function openLogs() {
  $("#logs-list").innerHTML = "Loading…";
  $("#logs-dlg").showModal();
  let logs;
  try { logs = await api("/api/logs"); }
  catch (e) { $("#logs-list").innerHTML = esc(e.message); return; }
  if (!logs.length) { $("#logs-list").innerHTML = '<div class="hint" style="padding:10px">No session logs yet. Enable "Record an encrypted session log" on a connection.</div>'; return; }
  $("#logs-list").innerHTML = logs.map((l) => `
    <div class="lrow" data-file="${esc(l.file)}">
      <span>${esc(l.file)}</span>
      <span class="lmeta">${human(l.size)}</span>
      <span class="lmeta">${new Date(l.mtime * 1000).toLocaleString()}</span>
      <span><button class="lopen">open</button> <button class="ldel">delete</button></span>
    </div>`).join("");
  $("#logs-list").querySelectorAll(".lrow").forEach((row) => {
    const file = row.dataset.file;
    row.querySelector(".lopen").onclick = () => openLogView(file);
    row.querySelector(".ldel").onclick = async () => {
      if (!await confirmDlg("Delete this session log?", file)) return;
      await api("/api/logs/" + encodeURIComponent(file), { method: "DELETE" });
      openLogs();
    };
  });
}

$("#import-btn").onclick = () => {
  importSource = null;
  $("#import-preview").hidden = true;
  $("#import-go").hidden = true;
  $("#import-dlg").showModal();
};
$("#import-cancel").onclick = () => $("#import-dlg").close();

let importBundle = null;   // parsed contents of a shared export file

async function runImportPreview(source, extra = {}) {
  importSource = source;
  $("#import-summary").innerHTML = "Reading…";
  $("#import-preview").hidden = false;
  $("#import-go").hidden = true;
  try {
    renderPreview(await api(`/api/import/${source}/preview`,
      { method: "POST", body: JSON.stringify(extra) }));
  } catch (err) {
    $("#import-summary").innerHTML = `<span style="color:var(--danger)">${esc(err.message)}</span>`;
    $("#import-list").innerHTML = "";
    $("#import-warn").textContent = "";
  }
}

$("#import-dlg").querySelectorAll(".import-src button[data-src]").forEach((b) => {
  b.onclick = () => { importBundle = null; runImportPreview(b.dataset.src); };
});

// A colleague's exported file. Parsed in the browser, then previewed like any
// other source so nothing is written until it is reviewed.
$("#bundle-file").onchange = async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  try {
    importBundle = JSON.parse(await file.text());
  } catch {
    toast("That file is not valid JSON.", "err");
    return;
  }
  runImportPreview("bundle", { bundle: importBundle });
};
// the label is focusable, so make Enter/Space open the picker too
$("#bundle-pick").onkeydown = (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#bundle-file").click(); }
};

$("#export-btn").onclick = async () => {
  try {
    const r = await fetch("/api/export", { headers: { "Authorization": "Bearer " + TOKEN } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const bundle = await r.json();
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const a = Object.assign(document.createElement("a"), {
      href: URL.createObjectURL(blob),
      download: `shelldeck-connections-${new Date().toISOString().slice(0, 10)}.json`,
    });
    a.click();
    URL.revokeObjectURL(a.href);
    toast(`Exported ${bundle.connections.length} connections — no passwords, keys or VPN profiles.`, "ok");
  } catch (err) { toast("Export failed: " + err.message, "err"); }
};

function renderPreview(p) {
  $("#import-summary").innerHTML =
    `<b>${p.new}</b> new connection${p.new === 1 ? "" : "s"} in ${p.groups.length} group${
      p.groups.length === 1 ? "" : "s"}` +
    (p.duplicates ? ` · <span class="idupe">${p.duplicates} already present, will skip</span>` : "") +
    `<div class="imeta">${esc(p.path)}</div>`;
  $("#import-list").innerHTML = p.connections.map((c) => `
    <div class="irow ${c.dupe ? "idupe" : ""}">
      <span>${esc(c.name)}${c.dupe ? " (already present)" : ""}
        <span class="imeta">${esc(c.group)}${c.via ? " · via " + esc(c.via) : ""}</span></span>
      <span class="imeta">${esc(c.target)} · ${c.auth}</span>
    </div>`).join("");
  const w = [...(p.warnings || [])];
  if (p.key_files_unreadable?.length)
    w.push(`${p.key_files_unreadable.length} key file(s) exist but cannot be read (often root-owned). Fix with: sudo chown $USER <file>`,
           ...p.key_files_unreadable);
  if (p.key_files_missing?.length)
    w.push(`${p.key_files_missing.length} key file(s) not found on disk — those connections import but the key must be re-added:`,
           ...p.key_files_missing);
  $("#import-warn").textContent = w.join("\n");
  $("#import-go").hidden = p.new === 0;
}

$("#import-go").onclick = async () => {
  $("#import-go").disabled = true;
  $("#import-summary").innerHTML = "Importing…";
  try {
    const r = await api(`/api/import/${importSource}/commit`, { method: "POST",
      body: JSON.stringify(importSource === "bundle" ? { bundle: importBundle } : {}) });
    let msg = `Imported ${r.created}, skipped ${r.skipped} duplicate(s), ${r.keys_imported} key file(s) loaded.`;
    if (r.key_failures?.length) msg += "\nKey files that could not be read:\n" + r.key_failures.join("\n");
    $("#import-summary").textContent = msg;
    $("#import-list").innerHTML = "";
    $("#import-warn").textContent = "";
    $("#import-go").hidden = true;
    await loadTree();
  } catch (err) {
    $("#import-summary").innerHTML = `<span style="color:#e5707a">${esc(err.message)}</span>`;
  } finally {
    $("#import-go").disabled = false;
  }
};
$("#keyfile").onchange = async (e) => {
  const file = e.target.files[0];
  if (file) $("#conn-form").key_pem.value = await file.text();
};

$("#editor").onclose = async () => {
  if ($("#editor").returnValue !== "save") return;
  const body = Object.fromEntries(new FormData($("#conn-form")));
  delete body.keyfile;
  body.log = $("#conn-form").log.checked;
  body.macros = [...$("#attach-list").querySelectorAll(".attach-cb:checked")].map((c) => c.value);
  try {
    await api("/api/connections", { method: "POST", body: JSON.stringify(body) });
    loadTree();
  } catch (err) { toast("Could not save: " + err.message, "err"); }
};

// --- vpn ----------------------------------------------------------------

let vpns = [];
let vpnState = { state: "disconnected", log: [] };
let vpnTimer = null;

async function loadVpns() {
  vpns = await api("/api/vpns");
  await pollVpn();
}

async function pollVpn() {
  try { vpnState = await api("/api/vpn/status"); } catch (e) { return; }
  renderVpn();
  // Poll quickly while something is happening, slowly when it is not.
  clearTimeout(vpnTimer);
  const busy = vpnState.state === "connecting" || vpnState.state === "connected";
  if (!$("#app").hidden) vpnTimer = setTimeout(pollVpn, busy ? 1500 : 6000);
  if ($("#vpn-log").open) $("#vpn-log-text").textContent = (vpnState.log || []).join("\n");
}

function renderVpn() {
  $("#vpn-list").innerHTML = vpns.map((v) => {
    const active = vpnState.profile_id === v.id ? vpnState.state : "disconnected";
    const on = active === "connected";
    const detail = vpnState.profile_id === v.id ? vpnState.detail : "";
    return `<div class="vpn" data-id="${v.id}">
      <span class="vpn-name"><span class="dot ${active}"></span>${esc(v.name)}</span>
      <span>
        <button class="vpn-go" data-id="${v.id}">${on || active === "connecting" ? "disconnect" : "connect"}</button>
        <button class="vpn-log" data-id="${v.id}" aria-label="VPN log for ${esc(v.name)}" title="Log">${icon("list")}</button>
        <button class="vpn-edit" data-id="${v.id}" aria-label="Edit ${esc(v.name)}" title="Edit">${icon("edit")}</button>
        <button class="vpn-del" data-id="${v.id}" aria-label="Delete ${esc(v.name)}" title="Delete">${icon("trash")}</button>
      </span>
      ${detail ? `<span class="vpn-detail ${active === "failed" ? "bad" : ""}">${esc(detail)}${
        on && vpnState.ip ? " &middot; " + esc(vpnState.ip) : ""}${
        on && vpnState.uptime ? " &middot; " + fmtUptime(vpnState.uptime) : ""}</span>` : ""}
    </div>`;
  }).join("") || '<div class="hint">No VPN profiles yet</div>';

  const on = (cls, fn) => $("#vpn-list").querySelectorAll(cls).forEach((b) =>
    b.onclick = (e) => { e.stopPropagation(); fn(b.dataset.id); });
  on(".vpn-go", async (id) => {
    const active = vpnState.profile_id === id && vpnState.state !== "disconnected"
      && vpnState.state !== "failed";
    try {
      await api(active ? "/api/vpn/down" : `/api/vpn/${id}/up`, { method: "POST" });
    } catch (err) { toast(err.message, "err"); }
    pollVpn();
  });
  on(".vpn-log", () => {
    $("#vpn-log-text").textContent = (vpnState.log || []).join("\n") || "(nothing logged yet)";
    $("#vpn-log").showModal();
  });
  on(".vpn-edit", (id) => openVpnEditor(vpns.find((v) => v.id === id)));
  on(".vpn-del", async (id) => {
    if (!await confirmDlg("Delete this VPN profile?",
        "Its .ovpn, password and TOTP secret are removed from the vault.")) return;
    await api("/api/vpns/" + id, { method: "DELETE" });
    loadVpns();
  });
}

const fmtUptime = (s) => s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` :
  `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60)}m`;

function openVpnEditor(v) {
  const f = $("#vpn-form");
  resetForm(f);
  $("#ovpn-note").textContent = v
    ? "Leave the file empty to keep the profile already stored. Blank secrets are kept too."
    : "The whole profile, private key included, is stored encrypted in the vault and written to disk only while connected.";
  if (v) for (const [k, val] of Object.entries(v)) if (f[k]) f[k].value = val;
  $("#vpn-editor").showModal();
}

$("#new-vpn-btn").onclick = () => openVpnEditor(null);
$("#ovpnfile").onchange = async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  $("#vpn-form").ovpn.value = await file.text();
  const sc = /^\s*static-challenge/m.test($("#vpn-form").ovpn.value);
  $("#ovpn-note").textContent = `Loaded ${file.name} — second factor: ${
    sc ? "static-challenge (SCRV1)" : "appended to the password"}.`;
};
$("#vpn-editor").onclose = async () => {
  if ($("#vpn-editor").returnValue !== "save") return;
  const body = Object.fromEntries(new FormData($("#vpn-form")));
  try {
    await api("/api/vpns", { method: "POST", body: JSON.stringify(body) });
    loadVpns();
  } catch (err) { toast("Could not save: " + err.message, "err"); }
};
$("#vpn-log-close").onclick = () => $("#vpn-log").close();

// --- tabs and panes -----------------------------------------------------
// ponytail: panes are one flat equal-width row per tab. Nested or resizable
// splits only if a row of 3+ actually gets cramped in daily use.

let tabs = [];
let activeTab = null;

function newTab() {
  const tab = { id: crypto.randomUUID(), panes: [] };
  tabs.push(tab);
  activeTab = tab;
  return tab;
}

function closeTab(tab) { tab.panes.slice().forEach(closePane); }

function closePane(pane) {
  if (pane.ws) pane.ws.close();
  if (pane.term) { liveTerms.delete(pane.term); pane.term.dispose(); }
  const tab = tabs.find((t) => t.panes.includes(pane));
  if (!tab) return;
  tab.panes.splice(tab.panes.indexOf(pane), 1);
  if (!tab.panes.length) {
    tabs.splice(tabs.indexOf(tab), 1);
    if (activeTab === tab) activeTab = tabs[tabs.length - 1] || null;
  }
  render();
}

const termPanes = (tab) => (tab ? tab.panes.filter((p) => p.term) : []);

function render() {
  const bcastN = termPanes(activeTab).length;
  const bcastBtn = activeTab && bcastN >= 2
    ? `<button id="bcast-btn" class="${activeTab.broadcast ? "on" : ""}" aria-pressed="${!!activeTab.broadcast}" title="Send your typing to all ${bcastN} terminals in this tab">${icon("broadcast")}<span>broadcast${activeTab.broadcast ? " ON" : ""}</span></button>`
    : "";
  $("#tabbar").innerHTML = (tabs.map((t) => `
    <div class="tab ${t === activeTab ? "active" : ""} ${t.broadcast ? "bcast" : ""}" data-id="${t.id}">
      <span>${esc(t.panes.map((p) => p.title).join(" | ")) || "empty"}</span>
      <button class="tab-close" data-id="${t.id}" aria-label="Close tab">${icon("x")}</button>
    </div>`).join("") || '<span class="hint">No session open</span>')
    + `<span class="tabbar-spacer"></span>${bcastBtn}`;

  $("#tabbar").querySelectorAll(".tab").forEach((el) => {
    el.onclick = (e) => {
      if (e.target.closest(".tab-close")) return;
      activeTab = tabs.find((t) => t.id === el.dataset.id);
      render();
    };
  });
  $("#tabbar").querySelectorAll(".tab-close").forEach((b) =>
    b.onclick = (e) => { e.stopPropagation(); closeTab(tabs.find((t) => t.id === b.dataset.id)); });
  const bb = $("#bcast-btn");
  if (bb) bb.onclick = () => { activeTab.broadcast = !activeTab.broadcast; render(); };

  const panes = $("#panes");
  panes.innerHTML = "";
  if (activeTab) {
    panes.style.gridTemplateColumns = `repeat(${activeTab.panes.length}, minmax(0, 1fr))`;
    activeTab.panes.forEach((p) => {
      p.el.classList.toggle("broadcasting", !!activeTab.broadcast && !!p.term);
      panes.appendChild(p.el);
    });
    activeTab.panes.forEach((p) => p.resize && p.resize());
  } else {
    panes.style.gridTemplateColumns = "1fr";
    renderPaneEmpty(panes);
  }
}

// Shown whenever no session is open. The features people never find on their
// own -- split panes, whole-group tabs, broadcast -- are named here.
function renderPaneEmpty(panes) {
  const tip = (k, t) => `<div><span class="k">${k}</span><span>${t}</span></div>`;
  panes.innerHTML = `
    <div class="pane-empty">
      ${icon("terminal", "mark")}
      <div>
        <h2>No session open</h2>
        <p>Pick a connection on the left to connect.</p>
      </div>
      <div class="tips">
        ${tip("<kbd>Ctrl</kbd> + click", "open it beside the current one, in a split pane")}
        ${tip(icon("grid"), "on a group heading opens every server in that group, in one tab")}
        ${tip("broadcast", "then sends what you type to every terminal in the tab at once")}
        ${tip(icon("folder"), "on a connection browses its files over SFTP")}
        ${tip("<kbd>F1</kbd>", "the manual, any time")}
      </div>
      <div class="acts">
        <button class="btn primary" id="pe-new">${icon("plus")}<span>New connection</span></button>
        <button class="btn ghost" id="pe-import">${icon("download")}<span>Import</span></button>
        <button class="btn ghost" id="pe-help">${icon("help")}<span>Manual</span></button>
      </div>
    </div>`;
  $("#pe-new").onclick = () => openEditor(null);
  $("#pe-import").onclick = () => $("#import-btn").click();
  $("#pe-help").onclick = () => $("#help-btn").click();
}

// --- terminal appearance ------------------------------------------------

const THEMES = {
  shelldeck:      { background: "#111318", foreground: "#d8dbe2", cursor: "#5aa9e6" },
  black:     { background: "#000000", foreground: "#e0e0e0", cursor: "#ffffff" },
  solarized: { background: "#002b36", foreground: "#93a1a1", cursor: "#b58900" },
  light:     { background: "#fdf6e3", foreground: "#3b4045", cursor: "#268bd2" },
};

function loadPrefs() {
  let p = {};
  try { p = JSON.parse(localStorage.getItem("termPrefs")) || {}; } catch {}
  return { theme: p.theme || "shelldeck", fontSize: p.fontSize || 13,
           fontFamily: p.fontFamily || "ui-monospace, monospace" };
}
let termPrefs = loadPrefs();

function termOptions() {
  return { fontSize: +termPrefs.fontSize, fontFamily: termPrefs.fontFamily,
           cursorBlink: true, theme: THEMES[termPrefs.theme] || THEMES.shelldeck };
}

const liveTerms = new Set();

function applyPrefs() {
  for (const t of liveTerms) {
    t.options.fontSize = +termPrefs.fontSize;
    t.options.fontFamily = termPrefs.fontFamily;
    t.options.theme = THEMES[termPrefs.theme] || THEMES.shelldeck;
  }
  activeTab?.panes.forEach((p) => p.resize?.());
}

let macros = [];
async function loadMacros() { try { macros = await api("/api/macros"); } catch { macros = []; } }

$("#macros-btn").onclick = async () => {
  await loadMacros();
  renderMacros();
  $("#macro-form").reset();
  $("#macros-dlg").showModal();
};
function renderMacros() {
  $("#macros-list").innerHTML = macros.length ? macros.map((m) => `
    <div class="mrow" data-name="${esc(m.name)}">
      <span>&#9889; ${esc(m.name)}</span>
      <button class="medit">edit</button><button class="mdel">delete</button>
    </div>`).join("") : '<div class="hint" style="padding:8px">No macros yet.</div>';
  $("#macros-list").querySelectorAll(".mrow").forEach((row) => {
    const m = macros.find((x) => x.name === row.dataset.name);
    row.querySelector(".medit").onclick = () => {
      $("#macro-form").name.value = m.name; $("#macro-form").body.value = m.body;
    };
    row.querySelector(".mdel").onclick = async () => {
      if (!await confirmDlg(`Delete macro "${m.name}"?`, "")) return;
      await api("/api/macros/" + encodeURIComponent(m.name), { method: "DELETE" });
      await loadMacros(); renderMacros();
    };
  });
}
$("#macros-dlg").onclose = async () => {
  if ($("#macros-dlg").returnValue !== "save") return;
  const f = $("#macro-form");
  if (!f.name.value.trim()) return;
  await api("/api/macros", { method: "POST",
    body: JSON.stringify({ name: f.name.value.trim(), body: f.body.value }) });
  await loadMacros();
};

// Pick a macro and run it in a terminal pane (broadcasts if the tab is in cluster mode).
async function runMacroOn(pane) {
  await loadMacros();
  if (!macros.length) {
    toast("No macros yet — create one with the bolt button in the sidebar.", "err");
    return;
  }
  // Prefer the macros attached to this connection; fall back to all of them.
  const attached = new Set(pane.conn.macros || []);
  const choices = attached.size ? macros.filter((m) => attached.has(m.name)) : macros;
  const tabNow = tabs.find((t) => t.panes.includes(pane));
  const name = await pick(
    `Run a macro on ${pane.conn.name}`,
    tabNow && tabNow.broadcast
      ? "Broadcast is ON — this runs on every terminal in the tab."
      : (attached.size ? "Macros attached to this connection." : "All macros."),
    choices.map((m) => ({ label: m.name, hint: (m.body || "").split("\n")[0].slice(0, 28), value: m.name })));
  if (!name) return;
  const m = choices.find((x) => x.name === name);
  if (!m) return;
  const tab = tabs.find((t) => t.panes.includes(pane));
  const targets = tab?.broadcast ? termPanes(tab) : [pane];
  for (const p of targets) if (p.ws?.readyState === 1)
    p.ws.send(JSON.stringify({ type: "macro", body: m.body }));
}

$("#prefs-btn").onclick = () => {
  const f = $("#prefs-form");
  f.theme.value = termPrefs.theme; f.fontSize.value = termPrefs.fontSize;
  f.fontFamily.value = termPrefs.fontFamily;
  $("#prefs-dlg").showModal();
};
$("#prefs-form").oninput = () => {
  const f = $("#prefs-form");
  termPrefs = { theme: f.theme.value, fontSize: f.fontSize.value, fontFamily: f.fontFamily.value };
  try { localStorage.setItem("termPrefs", JSON.stringify(termPrefs)); } catch {}
  applyPrefs();
};

// --- panes --------------------------------------------------------------

function makePane(conn, title) {
  const el = document.createElement("div");
  el.className = "pane";
  el.innerHTML = `<div class="pane-head"><span class="pane-title"></span>
      <span class="pane-status"></span><button class="pane-close" aria-label="Close pane" title="Close">${icon("x")}</button></div>
    <div class="pane-body"></div>`;
  const pane = { conn, title, el, body: el.querySelector(".pane-body") };
  el.querySelector(".pane-title").textContent = title;
  el.querySelector(".pane-close").onclick = () => closePane(pane);
  pane.setStatus = (t, bad) => {
    const s = el.querySelector(".pane-status");
    s.textContent = t;
    s.classList.toggle("bad", !!bad);
  };
  return pane;
}

function openSession(cid, kind, split) {
  const conn = conns.find((c) => c.id === cid);
  const tab = (split && activeTab) ? activeTab : newTab();
  tab.panes.push(kind === "sftp" ? sftpPane(conn) : termPane(conn));
  activeTab = tab;
  render();
}

// Open every connection in a group as split terminals in one new tab, ready to
// broadcast. A big group makes tiny panes, so confirm past a handful.
async function openGroup(gval) {
  const list = conns.filter((c) => (c.group || "") === gval);
  if (!list.length) return;
  if (list.length > 6 &&
      !await confirmDlg(`Open all ${list.length} connections side by side?`,
        "That is a lot of panes at once — each one gets a narrow column.", "Open all")) return;
  const tab = newTab();
  for (const c of list) tab.panes.push(termPane(c));
  activeTab = tab;
  render();
}

function termPane(conn) {
  const pane = makePane(conn, conn.name);
  const mbtn = document.createElement("button");
  mbtn.className = "pane-macro"; mbtn.innerHTML = icon("zap");
  mbtn.title = "Run a macro"; mbtn.setAttribute("aria-label", "Run a macro on this connection");
  mbtn.onclick = () => runMacroOn(pane);
  pane.el.querySelector(".pane-head").insertBefore(mbtn, pane.el.querySelector(".pane-close"));
  const term = new Terminal(termOptions());
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(pane.body);
  liveTerms.add(term);
  pane.term = term;

  const ws = new WebSocket(`ws://${location.host}/ws/ssh`);
  ws.binaryType = "arraybuffer";
  pane.ws = ws;
  let sawServer = false;
  pane.setStatus("connecting...");

  ws.onopen = () => {
    try { fit.fit(); } catch (e) {}
    ws.send(JSON.stringify({ token: TOKEN, id: conn.id, cols: term.cols, rows: term.rows }));
  };
  ws.onmessage = (ev) => {
    sawServer = true;
    if (ev.data instanceof ArrayBuffer) return term.write(new Uint8Array(ev.data));
    const msg = JSON.parse(ev.data);
    if (msg.type === "ready") {
      pane.setStatus(`${conn.user}@${conn.host}`);
      if (msg.forwards && msg.forwards.length)
        term.writeln(`\x1b[36m${msg.forwards.join("\r\n")}\x1b[0m\r\n`);
      term.focus();
    } else if (msg.type === "warn") term.writeln(`\r\n\x1b[33m${msg.message}\x1b[0m`);
    else if (msg.type === "error") { pane.setStatus("failed", true); term.writeln(`\r\n\x1b[31m${msg.message}\x1b[0m`); }
    else if (msg.type === "hostkey") askHostKey(ws, msg);
    else if (msg.type === "need_key_sudo") askSudoKey(ws, msg, pane);
    else if (msg.type === "macro_status") {
      pane.setStatus(msg.message, msg.error);
      // Make macro progress visible in the terminal, so a stuck expect or a
      // finished run is obvious rather than silent.
      if (pane.term) pane.term.writeln(`\r\n\x1b[${msg.error ? "31" : "90"}m[macro] ${msg.message}\x1b[0m`);
    }
  };
  ws.onclose = (ev) => {
    pane.setStatus("disconnected", true);
    term.writeln(sawServer ? "\r\n\x1b[90m-- disconnected --\x1b[0m"
      : `\r\n\x1b[31mWebSocket closed before the session started (code ${ev.code}).\x1b[0m`);
  };

  term.onData((d) => {
    const bytes = new TextEncoder().encode(d);
    const tab = tabs.find((t) => t.panes.includes(pane));
    // Cluster mode: your typing goes to every terminal in the tab at once.
    const targets = tab?.broadcast ? termPanes(tab) : [pane];
    for (const p of targets) if (p.ws?.readyState === 1) p.ws.send(bytes);
  });
  pane.resize = () => {
    // A pane just re-attached to the DOM can measure 0; never send that.
    try { fit.fit(); } catch (e) { return; }
    if (ws.readyState === 1 && term.cols > 0 && term.rows > 0)
      ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
  };
  return pane;
}

function sftpPane(conn) {
  const pane = makePane(conn, conn.name + " · files");
  pane.body.className = "pane-body sftp";
  pane.body.innerHTML = `<div class="sftp-bar"><button class="up">&#8593; up</button>
      <span class="cwd"></span>
      <input class="find" placeholder="filter here &middot; Enter searches the server">
      <label class="upload">upload<input type="file" hidden multiple></label></div>
    <div class="sftp-list"></div>`;
  const list = pane.body.querySelector(".sftp-list");
  const cwdEl = pane.body.querySelector(".cwd");
  const findEl = pane.body.querySelector(".find");
  let cwd = ".";
  let dl = null;
  let entries = [];

  const ws = new WebSocket(`ws://${location.host}/ws/sftp`);
  ws.binaryType = "arraybuffer";
  pane.ws = ws;
  pane.setStatus("connecting...");

  ws.onopen = () => ws.send(JSON.stringify({ token: TOKEN, id: conn.id, path: "." }));
  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) { if (dl) dl.parts.push(ev.data); return; }
    const msg = JSON.parse(ev.data);
    if (msg.type === "list") {
      cwd = msg.path; cwdEl.textContent = msg.path; pane.setStatus(conn.host);
      entries = msg.entries; findEl.value = ""; draw(entries);
    }
    else if (msg.type === "found") {
      pane.setStatus(`${msg.entries.length} match${msg.entries.length === 1 ? "" : "es"} for "${msg.q}"`);
      draw(msg.entries, true);
    }
    else if (msg.type === "uploaded") pane.setStatus("uploaded " + msg.name);
    else if (msg.type === "download") { dl = { name: msg.name, parts: [] }; pane.setStatus("downloading " + msg.name); }
    else if (msg.type === "download_end") { save(dl); dl = null; pane.setStatus(conn.host); }
    else if (msg.type === "hostkey") askHostKey(ws, msg);
    else if (msg.type === "need_key_sudo") askSudoKey(ws, msg, pane);
    else if (msg.type === "error") pane.setStatus(msg.message, true);
  };
  ws.onclose = () => pane.setStatus("disconnected", true);

  const send = (o) => ws.readyState === 1 && ws.send(JSON.stringify(o));
  const go = (path) => send({ op: "ls", path });

  function draw(rows, absolute) {
    list.innerHTML = rows.map((e, i) => `
      <div class="row" data-i="${i}">
        <span class="fname">${icon(e.dir ? "folder" : "file-text")}${esc(e.name)}</span>
        <span class="fsize">${e.dir ? "" : human(e.size)}</span>
      </div>`).join("") || '<div class="hint">nothing here</div>';
    list.querySelectorAll(".row").forEach((el) => {
      const e = rows[+el.dataset.i];
      const path = absolute ? e.name : cwd + "/" + e.name;
      el.onclick = () => e.dir ? go(path) : send({ op: "get", path });
    });
  }

  // Typing filters what is already listed; Enter asks the server to search below cwd.
  findEl.oninput = () => {
    const q = findEl.value.toLowerCase();
    draw(entries.filter((e) => e.name.toLowerCase().includes(q)));
  };
  findEl.onkeydown = (e) => {
    if (e.key !== "Enter") return;
    pane.setStatus("searching " + cwd + "...");
    send({ op: "find", path: cwd, q: findEl.value });
  };

  function save(d) {
    if (!d) return;
    const url = URL.createObjectURL(new Blob(d.parts));
    const a = Object.assign(document.createElement("a"), { href: url, download: d.name });
    a.click();
    URL.revokeObjectURL(url);
  }

  pane.body.querySelector(".up").onclick = () => go(cwd + "/..");
  const CHUNK = 131072;
  // Queueing a whole file into send() lets bufferedAmount grow without bound,
  // which is how a browser drops the socket mid-upload. Stream it and wait.
  const drain = () => new Promise((res) => {
    const tick = () => (ws.readyState !== 1 || ws.bufferedAmount < 4 * CHUNK) ? res() : setTimeout(tick, 20);
    tick();
  });

  pane.body.querySelector(".upload input").onchange = async (ev) => {
    for (const file of ev.target.files) {
      send({ op: "put", path: cwd + "/" + file.name, size: file.size });
      const reader = file.stream().getReader();
      let sent = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done || ws.readyState !== 1) break;
        for (let o = 0; o < value.byteLength; o += CHUNK) {
          await drain();
          if (ws.readyState !== 1) break;
          ws.send(value.subarray(o, o + CHUNK));
        }
        sent += value.byteLength;
        pane.setStatus(`uploading ${file.name} ${Math.round(100 * sent / (file.size || 1))}%`);
      }
    }
    ev.target.value = "";
  };
  return pane;
}

const human = (n) => n < 1024 ? n + " B"
  : n < 1048576 ? (n / 1024).toFixed(1) + " KB"
  : n < 1073741824 ? (n / 1048576).toFixed(1) + " MB" : (n / 1073741824).toFixed(1) + " GB";

function askSudoKey(ws, msg, pane) {
  $("#sudo-path").textContent = msg.path;
  $("#sudo-form").sudo.value = "";
  const dlg = $("#sudo-dlg");
  dlg.showModal();
  dlg.onclose = () => {
    const pw = dlg.returnValue === "ok" ? $("#sudo-form").sudo.value : "";
    $("#sudo-form").sudo.value = "";
    if (pane) pane.setStatus(pw ? "reading key…" : "cancelled", !pw);
    ws.send(JSON.stringify({ sudo_password: pw }));
  };
}

function askHostKey(ws, msg) {
  $("#hk-host").textContent = `${msg.name} - ${msg.host}`;
  $("#hk-fp").textContent = `${msg.algo}\n${msg.fingerprint}`;
  $("#hostkey").showModal();
  const answer = (accept) => { $("#hostkey").close(); ws.send(JSON.stringify({ accept })); };
  $("#hk-accept").onclick = () => answer(true);
  $("#hk-reject").onclick = () => answer(false);
}

$("#help-btn").onclick = () => $("#help").showModal();
$("#help-close").onclick = () => $("#help").close();
addEventListener("keydown", (e) => {
  if (e.key === "F1") { e.preventDefault(); $("#help").open ? $("#help").close() : $("#help").showModal(); }
});

addEventListener("resize", () => activeTab && activeTab.panes.forEach((p) => p.resize && p.resize()));
addEventListener("keydown", (e) => {
  if (!e.ctrlKey || !e.shiftKey || !tabs.length) return;
  if (e.key === "PageDown" || e.key === "PageUp") {
    const i = tabs.indexOf(activeTab);
    activeTab = tabs[(i + (e.key === "PageDown" ? 1 : -1) + tabs.length) % tabs.length];
    render();
    e.preventDefault();
  }
});

refreshGate();

// --- resizable sidebar --------------------------------------------------

(() => {
  const rz = $("#resizer");
  const root = document.documentElement;
  const setW = (px) => root.style.setProperty("--sidebar-w", Math.min(520, Math.max(170, px)) + "px");
  try { const w = +localStorage.getItem("sidebarW"); if (w) setW(w); } catch {}

  rz.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    rz.setPointerCapture(e.pointerId);
    rz.classList.add("drag");
    const move = (ev) => { setW(ev.clientX); activeTab?.panes.forEach((p) => p.resize?.()); };
    const up = () => {
      rz.classList.remove("drag");
      rz.removeEventListener("pointermove", move);
      rz.removeEventListener("pointerup", up);
      try {
        localStorage.setItem("sidebarW",
          parseInt(getComputedStyle(root).getPropertyValue("--sidebar-w")));
      } catch {}
      activeTab?.panes.forEach((p) => p.resize?.());
    };
    rz.addEventListener("pointermove", move);
    rz.addEventListener("pointerup", up);
  });
  // double-click resets to the default width
  rz.addEventListener("dblclick", () => {
    root.style.removeProperty("--sidebar-w");
    try { localStorage.removeItem("sidebarW"); } catch {}
    activeTab?.panes.forEach((p) => p.resize?.());
  });
})();
