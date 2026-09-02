const TOKEN = location.hash.slice(1);
const $ = (s) => document.querySelector(s);

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
  if (v.unlocked) loadTree();
  else $("#master").focus();
}

$("#unlock-form").onsubmit = async (e) => {
  e.preventDefault();
  $("#gate-error").textContent = "";
  try {
    await api("/api/vault/unlock", { method: "POST", body: JSON.stringify({ password: $("#master").value }) });
    $("#master").value = "";
    await refreshGate();
  } catch (err) {
    $("#gate-error").textContent = err.message;
  }
};

$("#lock-btn").onclick = async () => {
  await api("/api/vault/lock", { method: "POST" });
  if (ws) ws.close();
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
  const shown = conns.filter((c) => (c.name + c.host + c.group).toLowerCase().includes(q));
  const groups = {};
  for (const c of shown) (groups[c.group || "ungrouped"] ??= []).push(c);

  $("#tree").innerHTML = Object.entries(groups).map(([g, list]) => `
    <div class="group"><div class="group-name">${esc(g)}</div>
      ${list.map((c) => `
        <div class="conn" data-id="${c.id}">
          <span class="conn-name">${esc(c.name)}</span>
          <span class="conn-host">${esc(c.user)}@${esc(c.host)}</span>
          <button class="edit" data-id="${c.id}" title="Edit">✎</button>
          <button class="del" data-id="${c.id}" title="Delete">✕</button>
        </div>`).join("")}
    </div>`).join("");

  $("#tree").querySelectorAll(".conn").forEach((el) => {
    el.onclick = (e) => { if (!e.target.dataset.id || e.target.classList.contains("conn-name")) connect(el.dataset.id); };
  });
  $("#tree").querySelectorAll(".edit").forEach((b) => b.onclick = (e) => { e.stopPropagation(); openEditor(conns.find((c) => c.id === b.dataset.id)); });
  $("#tree").querySelectorAll(".del").forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    if (!confirm("Delete this connection and its stored secrets?")) return;
    await api("/api/connections/" + b.dataset.id, { method: "DELETE" });
    loadTree();
  });
}

const esc = (s) => String(s ?? "").replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));
$("#filter").oninput = renderTree;

// --- editor -------------------------------------------------------------

function openEditor(conn) {
  const f = $("#conn-form");
  f.reset();
  if (conn) for (const [k, v] of Object.entries(conn)) if (f[k]) f[k].value = v;
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

$("#keyfile").onchange = async (e) => {
  const file = e.target.files[0];
  if (file) $("#conn-form").key_pem.value = await file.text();
};

$("#editor").onclose = async () => {
  if ($("#editor").returnValue !== "save") return;
  const body = Object.fromEntries(new FormData($("#conn-form")));
  delete body.keyfile;
  await api("/api/connections", { method: "POST", body: JSON.stringify(body) });
  loadTree();
};

// --- terminal -----------------------------------------------------------

const term = new Terminal({ fontSize: 13, cursorBlink: true, theme: { background: "#111318" } });
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open($("#term"));
fit.fit();

let ws = null;

function connect(id) {
  const conn = conns.find((c) => c.id === id);
  if (ws) ws.close();
  term.reset();
  $("#status").textContent = `Connecting to ${conn.name}…`;

  ws = new WebSocket(`ws://${location.host}/ws/ssh`);
  ws.binaryType = "arraybuffer";

  ws.onopen = () => {
    fit.fit();
    ws.send(JSON.stringify({ token: TOKEN, id, cols: term.cols, rows: term.rows }));
  };

  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) { term.write(new Uint8Array(ev.data)); return; }
    const msg = JSON.parse(ev.data);
    if (msg.type === "ready") { $("#status").textContent = `${conn.user}@${conn.host}`; term.focus(); }
    else if (msg.type === "error") { $("#status").textContent = "Failed"; term.writeln(`\r\n\x1b[31m${msg.message}\x1b[0m`); }
    else if (msg.type === "hostkey") askHostKey(conn, msg);
  };

  ws.onclose = () => { $("#status").textContent = "Not connected"; term.writeln("\r\n\x1b[90m— disconnected —\x1b[0m"); };
}

function askHostKey(conn, msg) {
  $("#hk-host").textContent = `${conn.host}:${conn.port}`;
  $("#hk-fp").textContent = `${msg.algo}\n${msg.fingerprint}`;
  $("#hostkey").showModal();
  const answer = (accept) => { $("#hostkey").close(); ws.send(JSON.stringify({ accept })); };
  $("#hk-accept").onclick = () => answer(true);
  $("#hk-reject").onclick = () => answer(false);
}

term.onData((d) => ws?.readyState === 1 && ws.send(new TextEncoder().encode(d)));

addEventListener("resize", () => {
  fit.fit();
  if (ws?.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
});

refreshGate();
