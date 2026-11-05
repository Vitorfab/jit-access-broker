# ruff: noqa: E501
"""Read-only local dashboard (lab only).

Static files only: they contain no data. All data comes from the token-protected API, and the
page renders it with textContent (never innerHTML). Every response gets strict security headers.
"""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>jit-access-broker (lab)</title>
<link rel="stylesheet" href="/ui/app.css">
</head>
<body>
<header>
<h1>jit-access-broker</h1>
<p class="badge">Lab dashboard &middot; read-only &middot; simulated users, not real authentication</p>
</header>
<main>
<section id="login">
<form id="login-form" autocomplete="off">
<label for="token">API token (printed by <code>jit-broker serve</code>)</label>
<input id="token" type="password" autocomplete="off" spellcheck="false">
<label for="user">Simulated user id</label>
<input id="user" type="text" autocomplete="off" spellcheck="false" placeholder="for example: alice">
<button type="submit">Connect</button>
<p id="login-error" role="alert"></p>
</form>
</section>
<section id="dashboard" hidden>
<div class="bar"><span id="who"></span><button id="disconnect" type="button">Disconnect</button></div>
<div class="cards">
<div class="card"><h2>Pending requests</h2><p id="stat-pending" class="big">-</p></div>
<div class="card"><h2>Active grants</h2><p id="stat-grants" class="big">-</p></div>
<div class="card"><h2>Audit chain</h2><p id="stat-audit" class="big small">-</p></div>
</div>
<h2>Grants</h2>
<table>
<thead><tr><th>Grant</th><th>User</th><th>Role</th><th>Ends</th><th>Status</th><th>Time left</th></tr></thead>
<tbody id="grants-body"></tbody>
</table>
<h2>Requests</h2>
<table>
<thead><tr><th>Request</th><th>User</th><th>Role</th><th>Minutes</th><th>Status</th><th>Approvals</th></tr></thead>
<tbody id="requests-body"></tbody>
</table>
<p class="muted">The countdown uses your browser clock and is informative only: the server decides access at check time.</p>
</section>
</main>
<script src="/ui/app.js"></script>
</body>
</html>
"""

APP_CSS = r"""
:root { color-scheme: light dark; --bg: #f6f7f9; --fg: #1b1f24; --card: #ffffff; --line: #d0d7de; --muted: #57606a; --ok: #1a7f37; --bad: #cf222e; --warn: #9a6700; }
@media (prefers-color-scheme: dark) { :root { --bg: #0d1117; --fg: #e6edf3; --card: #161b22; --line: #30363d; --muted: #8b949e; --ok: #3fb950; --bad: #f85149; --warn: #d29922; } }
[hidden] { display: none !important; }
body { margin: 0; font-family: system-ui, sans-serif; background: var(--bg); color: var(--fg); }
header, main { max-width: 960px; margin: 0 auto; padding: 16px; }
h1 { margin: 0 0 4px; font-size: 1.4rem; }
h2 { font-size: 1rem; margin: 20px 0 8px; }
.badge, .muted { color: var(--muted); font-size: 0.85rem; }
form { display: grid; gap: 8px; max-width: 360px; }
input, button { font: inherit; padding: 8px; border: 1px solid var(--line); border-radius: 6px; background: var(--card); color: var(--fg); }
button { cursor: pointer; }
#login-error { color: var(--bad); min-height: 1.2em; margin: 0; }
.bar { display: flex; justify-content: space-between; align-items: center; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 12px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
.card h2 { margin: 0 0 6px; color: var(--muted); font-weight: 600; }
.big { font-size: 1.8rem; margin: 0; font-weight: 700; }
.big.small { font-size: 1rem; word-break: break-word; }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); font-size: 0.9rem; }
.active, .approved, .ok { color: var(--ok); }
.revoked, .denied, .bad { color: var(--bad); }
.pending, .ended, .expired { color: var(--warn); }
.countdown { font-variant-numeric: tabular-nums; }
"""

APP_JS = r"""
"use strict";
(function () {
  const state = { token: null, user: null, refreshTimer: null, tickTimer: null };
  const KNOWN_STATUS = ["pending", "approved", "denied", "expired"];
  const $ = (id) => document.getElementById(id);

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    if (cls) { node.className = cls; }
    return node;
  }

  function fmt(iso) {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? "-" : d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
  }

  function remaining(iso) {
    const ms = new Date(iso).getTime() - Date.now();
    if (isNaN(ms) || ms <= 0) { return "ended"; }
    const s = Math.floor(ms / 1000);
    return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m " + (s % 60) + "s";
  }

  function call(path) {
    return fetch(path, {
      headers: { "Authorization": "Bearer " + state.token, "X-Acting-User": state.user },
      cache: "no-store",
      credentials: "omit"
    }).then((response) =>
      response.json().catch(() => ({})).then((body) => ({ status: response.status, body: body }))
    );
  }

  function fill(tbodyId, rows, build) {
    const tbody = $(tbodyId);
    tbody.replaceChildren();
    if (rows.length === 0) {
      const tr = el("tr");
      const td = el("td", "Nothing yet", "muted");
      td.colSpan = 6;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach((row) => {
      const tr = el("tr");
      build(row).forEach((cell) => tr.appendChild(cell));
      tbody.appendChild(tr);
    });
  }

  function grantStatus(g) {
    if (g.revoked_at) { return "revoked"; }
    if (new Date(g.ends_at).getTime() <= Date.now()) { return "ended"; }
    return "active";
  }

  function renderGrants(grants) {
    fill("grants-body", grants, (g) => {
      const status = grantStatus(g);
      const left = el("td", status === "active" ? remaining(g.ends_at) : "-", "countdown");
      if (status === "active") { left.dataset.ends = g.ends_at; }
      return [el("td", "#" + g.id), el("td", g.grantee), el("td", g.role),
        el("td", fmt(g.ends_at)), el("td", status, status), left];
    });
    $("stat-grants").textContent = String(grants.filter((g) => grantStatus(g) === "active").length);
  }

  function renderRequests(requests) {
    fill("requests-body", requests, (r) => {
      const cls = KNOWN_STATUS.indexOf(r.status) >= 0 ? r.status : "";
      return [el("td", "#" + r.id), el("td", r.requester), el("td", r.role),
        el("td", r.duration_minutes), el("td", r.status, cls), el("td", r.approvals)];
    });
    $("stat-pending").textContent = String(requests.filter((r) => r.status === "pending").length);
  }

  function renderAudit(res) {
    const node = $("stat-audit");
    if (res.status === 200) {
      node.textContent = "OK: " + res.body.entries + " entries, head " + String(res.body.head_hash).slice(0, 12);
      node.className = "big small ok";
    } else if (res.status === 409 && String(res.body.detail).indexOf("not found") >= 0) {
      node.textContent = "No log yet";
      node.className = "big small muted";
    } else if (res.status === 409) {
      node.textContent = "BROKEN: " + res.body.detail;
      node.className = "big small bad";
    } else {
      node.textContent = "Unavailable";
      node.className = "big small muted";
    }
  }

  function tick() {
    document.querySelectorAll("td.countdown[data-ends]").forEach((td) => {
      td.textContent = remaining(td.dataset.ends);
    });
  }

  function disconnect(message) {
    clearInterval(state.refreshTimer);
    clearInterval(state.tickTimer);
    state.token = null;
    state.user = null;
    $("dashboard").hidden = true;
    $("login").hidden = false;
    $("login-error").textContent = message;
  }

  function refresh() {
    return Promise.all([call("/requests"), call("/grants"), call("/audit/verify")]).then((res) => {
      if (res.some((r) => r.status === 401)) { disconnect("Invalid token."); return false; }
      if (res[0].status !== 200 || res[1].status !== 200) { disconnect("The API refused the request."); return false; }
      renderRequests(res[0].body);
      renderGrants(res[1].body);
      renderAudit(res[2]);
      return true;
    }).catch(() => { disconnect("Cannot reach the API."); return false; });
  }

  function connect(event) {
    event.preventDefault();
    const token = $("token").value.trim();
    const user = $("user").value.trim();
    $("login-error").textContent = "";
    if (!token || !/^[a-z][a-z0-9-]{1,31}$/.test(user)) {
      $("login-error").textContent = "Enter the token and a valid user id.";
      return;
    }
    state.token = token;
    state.user = user;
    $("token").value = "";
    refresh().then((ok) => {
      if (!ok) { return; }
      $("login").hidden = true;
      $("dashboard").hidden = false;
      $("who").textContent = "Viewing as " + user + " (simulated)";
      state.refreshTimer = setInterval(refresh, 5000);
      state.tickTimer = setInterval(tick, 1000);
    });
  }

  $("login-form").addEventListener("submit", connect);
  $("disconnect").addEventListener("click", () => disconnect(""));
})();
"""


def register_ui(app: FastAPI) -> None:
    """Add the dashboard routes and the security headers to every response."""

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.get("/", include_in_schema=False)
    def index() -> HTMLResponse:
        return HTMLResponse(INDEX_HTML)

    @app.get("/ui/app.js", include_in_schema=False)
    def app_js() -> Response:
        return Response(APP_JS, media_type="text/javascript; charset=utf-8")

    @app.get("/ui/app.css", include_in_schema=False)
    def app_css() -> Response:
        return Response(APP_CSS, media_type="text/css; charset=utf-8")
