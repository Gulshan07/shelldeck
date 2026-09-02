const TOKEN = location.hash.slice(1);
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));

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

function renderTree() {
  const q = $("#filter").value.toLowerCase();
  const groups = {};
  for (const c of conns.filter((c) => (c.name + c.host + c.group).toLowerCase().includes(q)))
    (groups[c.group || "ungrouped"] ??= []).push(c);

  $("#tree").innerHTML = Object.entries(groups).map(([g, list]) => `
    <div class="group"><div class="group-name">${esc(g)}</div>
      ${list.map((c) => `
        <div class="conn" data-id="${c.id}">
          <span class="conn-name">${esc(c.name)}</span>
          <span class="conn-host">${esc(c.user)}@${esc(c.host)}${c.jump ? " &#8674; via " + esc(nameOf(c.jump)) : ""}${c.forwards && c.forwards.length ? " &middot; " + c.forwards.length + "&#8644;" : ""}</span>
          <button class="sftp" data-id="${c.id}" title="Browse files (SFTP)">&#128449;</button>
          <button class="edit" data-id="${c.id}" title="Edit">&#9998;</button>
          <button class="del" data-id="${c.id}" title="Delete">&#10005;</button>
        </div>`).join("")}
    </div>`).join("");

  $("#tree").querySelectorAll(".conn").forEach((el) => {
    el.onclick = (e) => {
      if (e.target.closest("button")) return;
      // Ctrl/Cmd-click splits into the current tab instead of opening a new one.
      openSession(el.dataset.id, "term", e.ctrlKey || e.metaKey);
    };
  });
  const on = (cls, fn) => $("#tree").querySelectorAll(cls).forEach((b) =>
    b.onclick = (e) => { e.stopPropagation(); fn(b.dataset.id, e); });
  on(".sftp", (id, e) => openSession(id, "sftp", e.ctrlKey || e.metaKey));
  on(".edit", (id) => openEditor(conns.find((c) => c.id === id)));
  on(".del", async (id) => {
    if (!confirm("Delete this connection and its stored secrets?")) return;
    await api("/api/connections/" + id, { method: "DELETE" });
    loadTree();
  });
}

const nameOf = (id) => (conns.find((c) => c.id === id) || {}).name || "?";
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
  if (conn) for (const [k, v] of Object.entries(conn)) if (f[k]) f[k].value = Array.isArray(v) ? v.join("\n") : v;
  syncAuthFields();
  $("#editor").showModal();
}

function syncAuthFields() {
  const mode = $("#conn-form").auth.value;
  document.querySelectorAll(".auth-password").forEach((e) => e.hidden = mode !== "password");
  document.querySelectorAll(".auth-key").forEach((e) => e.hidden = mode !== "key");
}
$("#conn-form").auth.onchange = syncAuthFields;
$("#new-btn").onclick = () => openEditor(null);

// --- import -------------------------------------------------------------

let importSource = null;

$("#import-btn").onclick = () => {
  importSource = null;
  $("#import-preview").hidden = true;
  $("#import-go").hidden = true;
  $("#import-dlg").showModal();
};
$("#import-cancel").onclick = () => $("#import-dlg").close();

$("#import-dlg").querySelectorAll(".import-src button").forEach((b) => {
  b.onclick = async () => {
    importSource = b.dataset.src;
    $("#import-summary").innerHTML = "Reading…";
    $("#import-preview").hidden = false;
    $("#import-go").hidden = true;
    try {
      const p = await api(`/api/import/${importSource}/preview`);
      renderPreview(p);
    } catch (err) {
      $("#import-summary").innerHTML = `<span style="color:#e5707a">${esc(err.message)}</span>`;
      $("#import-list").innerHTML = "";
      $("#import-warn").textContent = "";
    }
  };
});

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
    const r = await api(`/api/import/${importSource}/commit`, { method: "POST", body: "{}" });
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
  try {
    await api("/api/connections", { method: "POST", body: JSON.stringify(body) });
    loadTree();
  } catch (err) { alert("Could not save: " + err.message); }
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
        <button class="vpn-log" data-id="${v.id}" title="Log">&#9776;</button>
        <button class="vpn-edit" data-id="${v.id}" title="Edit">&#9998;</button>
        <button class="vpn-del" data-id="${v.id}" title="Delete">&#10005;</button>
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
    } catch (err) { alert(err.message); }
    pollVpn();
  });
  on(".vpn-log", () => {
    $("#vpn-log-text").textContent = (vpnState.log || []).join("\n") || "(nothing logged yet)";
    $("#vpn-log").showModal();
  });
  on(".vpn-edit", (id) => openVpnEditor(vpns.find((v) => v.id === id)));
  on(".vpn-del", async (id) => {
    if (!confirm("Delete this VPN profile and its stored secrets?")) return;
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
  } catch (err) { alert("Could not save: " + err.message); }
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
  const tab = tabs.find((t) => t.panes.includes(pane));
  if (!tab) return;
  tab.panes.splice(tab.panes.indexOf(pane), 1);
  if (!tab.panes.length) {
    tabs.splice(tabs.indexOf(tab), 1);
    if (activeTab === tab) activeTab = tabs[tabs.length - 1] || null;
  }
  render();
}

function render() {
  $("#tabbar").innerHTML = tabs.map((t) => `
    <div class="tab ${t === activeTab ? "active" : ""}" data-id="${t.id}">
      <span>${esc(t.panes.map((p) => p.title).join(" | ")) || "empty"}</span>
      <button class="tab-close" data-id="${t.id}">&#10005;</button>
    </div>`).join("") || '<span class="hint">Click a connection to open a session &middot; Ctrl-click to split</span>';

  $("#tabbar").querySelectorAll(".tab").forEach((el) => {
    el.onclick = (e) => {
      if (e.target.closest(".tab-close")) return;
      activeTab = tabs.find((t) => t.id === el.dataset.id);
      render();
    };
  });
  $("#tabbar").querySelectorAll(".tab-close").forEach((b) =>
    b.onclick = (e) => { e.stopPropagation(); closeTab(tabs.find((t) => t.id === b.dataset.id)); });

  const panes = $("#panes");
  panes.innerHTML = "";
  if (activeTab) {
    panes.style.gridTemplateColumns = `repeat(${activeTab.panes.length}, minmax(0, 1fr))`;
    activeTab.panes.forEach((p) => panes.appendChild(p.el));
    activeTab.panes.forEach((p) => p.resize && p.resize());
  }
}

// --- panes --------------------------------------------------------------

function makePane(conn, title) {
  const el = document.createElement("div");
  el.className = "pane";
  el.innerHTML = `<div class="pane-head"><span class="pane-title"></span>
      <span class="pane-status"></span><button class="pane-close" title="Close">&#10005;</button></div>
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

function termPane(conn) {
  const pane = makePane(conn, conn.name);
  const term = new Terminal({ fontSize: 13, cursorBlink: true, theme: { background: "#111318" } });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(pane.body);

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
  };
  ws.onclose = (ev) => {
    pane.setStatus("disconnected", true);
    term.writeln(sawServer ? "\r\n\x1b[90m-- disconnected --\x1b[0m"
      : `\r\n\x1b[31mWebSocket closed before the session started (code ${ev.code}).\x1b[0m`);
  };

  term.onData((d) => ws.readyState === 1 && ws.send(new TextEncoder().encode(d)));
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
    else if (msg.type === "error") pane.setStatus(msg.message, true);
  };
  ws.onclose = () => pane.setStatus("disconnected", true);

  const send = (o) => ws.readyState === 1 && ws.send(JSON.stringify(o));
  const go = (path) => send({ op: "ls", path });

  function draw(rows, absolute) {
    list.innerHTML = rows.map((e, i) => `
      <div class="row" data-i="${i}">
        <span class="fname">${e.dir ? "&#128449;" : "&#128462;"} ${esc(e.name)}</span>
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
