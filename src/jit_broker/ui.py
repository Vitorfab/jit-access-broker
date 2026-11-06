# ruff: noqa: E501
"""Local dashboard (lab only).

Static files only: they contain no data. All data comes from the session-protected API, and the
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
<p class="badge">Lab dashboard &middot; local accounts only &middot; no SSO, MFA or TLS</p>
</header>
<main>
<section id="login">
<form id="login-form">
<label for="user">User id</label>
<input id="user" type="text" autocomplete="username" spellcheck="false" placeholder="for example: alice">
<label for="password">Password</label>
<input id="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
<p id="login-error" role="alert"></p>
</form>
<p class="muted">Accounts are created by the operator with <code>jit-broker user create</code>.</p>
</section>
<section id="dashboard" hidden>
<div class="bar"><span id="who"></span><button id="signout" type="button">Sign out</button></div>
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
<p class="muted">You only see what you requested, approve or administer. The countdown uses your browser clock and is informative only: the server decides access at check time.</p>
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
  const state = { csrf: null, caps: [], refreshTimer: null, tickTimer: null };
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

  function call(path, options) {
    const init = { method: "GET", headers: {}, cache: "no-store", credentials: "same-origin" };
    if (options && options.method === "POST") {
      init.method = "POST";
      init.headers["X-CSRF-Token"] = state.csrf || "";
      if (options.body !== undefined) {
        init.headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(options.body);
      }
    }
    return fetch(path, init).then((response) =>
      response.json().catch(() => ({})).then((body) => ({ status: response.status, body: body }))
    );
  }

  function fill(tbodyId, rows, build) {
    const tbody = $(tbodyId);
    tbody.replaceChildren();
    if (rows.length === 0) {
      const tr = el("tr");
      const td = el("td", "Nothing to show", "muted");
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
    if (res.status === 0) {
      node.textContent = "Visible to admins only";
      node.className = "big small muted";
    } else if (res.status === 200) {
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

  function showLogin(message) {
    clearInterval(state.refreshTimer);
    clearInterval(state.tickTimer);
    state.csrf = null;
    state.caps = [];
    $("dashboard").hidden = true;
    $("login").hidden = false;
    $("login-error").textContent = message;
  }

  function refresh() {
    const isAdmin = state.caps.indexOf("admin") >= 0;
    const audit = isAdmin ? call("/audit/verify") : Promise.resolve({ status: 0, body: {} });
    return Promise.all([call("/requests"), call("/grants"), audit]).then((res) => {
      if (res.some((r) => r.status === 401)) { showLogin("Session ended. Sign in again."); return false; }
      if (res[0].status !== 200 || res[1].status !== 200) { showLogin("The API refused the request."); return false; }
      renderRequests(res[0].body);
      renderGrants(res[1].body);
      renderAudit(res[2]);
      return true;
    }).catch(() => { showLogin("Cannot reach the API."); return false; });
  }

  function enter(profile) {
    state.csrf = profile.csrf_token;
    state.caps = profile.capabilities;
    $("who").textContent = "Signed in as " + profile.display_name + " (" + profile.username + ")";
    refresh().then((ok) => {
      if (!ok) { return; }
      $("login").hidden = true;
      $("dashboard").hidden = false;
      clearInterval(state.refreshTimer);
      clearInterval(state.tickTimer);
      state.refreshTimer = setInterval(refresh, 5000);
      state.tickTimer = setInterval(tick, 1000);
    });
  }

  function signIn(event) {
    event.preventDefault();
    const username = $("user").value.trim();
    const password = $("password").value;
    $("login-error").textContent = "";
    if (!/^[a-z][a-z0-9-]{1,31}$/.test(username) || password.length === 0) {
      $("login-error").textContent = "Enter a valid user id and your password.";
      return;
    }
    $("password").value = "";
    call("/auth/login", { method: "POST", body: { username: username, password: password } })
      .then((res) => {
        if (res.status === 200) { enter(res.body); }
        else { $("login-error").textContent = res.status === 401 ? "Invalid credentials." : "Sign-in failed."; }
      })
      .catch(() => { $("login-error").textContent = "Cannot reach the API."; });
  }

  $("login-form").addEventListener("submit", signIn);
  $("signout").addEventListener("click", () => {
    call("/auth/logout", { method: "POST" }).finally(() => showLogin(""));
  });
  call("/auth/me")
    .then((res) => { if (res.status === 200) { enter(res.body); } else { showLogin(""); } })
    .catch(() => showLogin("Cannot reach the API."));
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
