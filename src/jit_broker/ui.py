# ruff: noqa: E501
"""Local dashboard (lab only).

Static files only: they contain no data. All data comes from the session-protected API, and the
page renders it with textContent (never innerHTML). Every response gets strict security headers.
The page only hides controls that do not fit the profile: the server authorizes every action.
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
<p id="action-msg" role="status"></p>
<div id="confirm-box" class="confirm" hidden>
<p id="confirm-text"></p>
<button id="confirm-yes" type="button">Yes, revoke now</button>
<button id="confirm-no" type="button">Cancel</button>
</div>
<div class="cards">
<div class="card"><h2>Pending requests</h2><p id="stat-pending" class="big">-</p></div>
<div class="card"><h2>Active grants</h2><p id="stat-grants" class="big">-</p></div>
<div class="card"><h2>Audit chain</h2><p id="stat-audit" class="big small">-</p></div>
</div>
<section id="panel-request" hidden>
<h2>Request access</h2>
<form id="request-form">
<label for="role">Role</label>
<select id="role"></select>
<p id="role-hint" class="muted"></p>
<label for="minutes">Minutes</label>
<input id="minutes" type="number" min="15" max="1440" value="30">
<label for="justification">Justification (10-500 characters)</label>
<textarea id="justification" maxlength="500" rows="3"></textarea>
<label for="ticket">Ticket (optional)</label>
<input id="ticket" type="text" maxlength="40" autocomplete="off" spellcheck="false">
<button type="submit">Send request</button>
</form>
</section>
<section id="panel-decide" hidden>
<h2>Decisions</h2>
<label for="reason">Reason for Approve or Deny (3-200 characters)</label>
<input id="reason" type="text" maxlength="200" autocomplete="off">
<p class="muted">Use the buttons in the Requests table. The server checks that you are an approver for the role.</p>
</section>
<section id="panel-admin" hidden>
<h2>Administration</h2>
<button id="sweep-btn" type="button">Expire overdue pending requests</button>
<p class="muted">Use the Revoke button in the Grants table (you will be asked to confirm).</p>
</section>
<section id="panel-check">
<h2>Check my access</h2>
<form id="check-form">
<label for="check-role">Role id</label>
<input id="check-role" type="text" autocomplete="off" spellcheck="false">
<button type="submit">Check now</button>
</form>
</section>
<section id="panel-policy" hidden>
<h2>Policy editor (two-person approval)</h2>
<p class="muted">Load the policy, edit the JSON and propose. A different admin must approve before it applies. You cannot give yourself new privileges.</p>
<textarea id="policy-text" rows="14" spellcheck="false"></textarea>
<div><button id="policy-load" type="button">Load current policy</button> <button id="policy-propose" type="button">Propose change</button></div>
<h2>Policy changes</h2>
<table>
<thead><tr><th>Change</th><th>Proposed by</th><th>Summary</th><th>Status</th><th>Actions</th></tr></thead>
<tbody id="policy-body"></tbody>
</table>
</section>
<h2>Grants</h2>
<table>
<thead><tr><th>Grant</th><th>User</th><th>Role</th><th>Ends</th><th>Status</th><th>Time left</th><th>Actions</th></tr></thead>
<tbody id="grants-body"></tbody>
</table>
<h2>Requests</h2>
<table>
<thead><tr><th>Request</th><th>User</th><th>Role</th><th>Minutes</th><th>Status</th><th>Approvals</th><th>Actions</th></tr></thead>
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
input, button, select, textarea { font: inherit; padding: 8px; border: 1px solid var(--line); border-radius: 6px; background: var(--card); color: var(--fg); }
button { cursor: pointer; }
td button { padding: 2px 8px; margin-right: 4px; font-size: 0.85rem; }
#login-error { color: var(--bad); min-height: 1.2em; margin: 0; }
#action-msg { min-height: 1.2em; margin: 8px 0; }
.confirm { border: 2px solid var(--warn); border-radius: 8px; padding: 12px; margin: 8px 0; background: var(--card); }
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
#policy-text { width: 100%; box-sizing: border-box; font-family: ui-monospace, monospace; font-size: 0.85rem; }
"""

APP_JS = r"""
"use strict";
(function () {
  const state = { csrf: null, user: null, caps: [], roles: [], revokeId: null, lastKey: null, refreshTimer: null, tickTimer: null };
  const KNOWN_STATUS = ["pending", "approved", "denied", "expired"];
  const $ = (id) => document.getElementById(id);

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    if (cls) { node.className = cls; }
    return node;
  }

  function button(label, handler) {
    const b = el("button", label);
    b.type = "button";
    b.addEventListener("click", handler);
    return b;
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

  function say(text, ok) {
    const node = $("action-msg");
    node.textContent = text;
    node.className = ok ? "ok" : "bad";
  }

  function failText(res) {
    const detail = res.body && res.body.detail;
    if (typeof detail === "string") { return detail; }
    return "The request was not accepted (status " + res.status + ").";
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

  function act(path, body, okText) {
    return call(path, { method: "POST", body: body }).then((res) => {
      if (res.status === 401) { showLogin("Session ended. Sign in again."); return false; }
      if (res.status >= 200 && res.status < 300) {
        say(okText, true);
        return refresh().then(() => true);
      }
      say(failText(res), false);
      return false;
    }).catch(() => { say("Cannot reach the API.", false); return false; });
  }

  function fill(tbodyId, rows, build) {
    const tbody = $(tbodyId);
    tbody.replaceChildren();
    if (rows.length === 0) {
      const tr = el("tr");
      const td = el("td", "Nothing to show", "muted");
      td.colSpan = 7;
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

  function has(cap) { return state.caps.indexOf(cap) >= 0; }

  function grantStatus(g) {
    if (g.revoked_at) { return "revoked"; }
    if (new Date(g.ends_at).getTime() <= Date.now()) { return "ended"; }
    return "active";
  }

  function decide(kind, id) {
    const reason = $("reason").value.trim();
    if (reason.length < 3 || reason.length > 200) { say("Write a reason (3-200 characters) first.", false); return; }
    act("/requests/" + id + "/" + kind, { reason: reason }, "Decision recorded for request #" + id + ".")
      .then((ok) => { if (ok) { $("reason").value = ""; } });
  }

  function askRevoke(g) {
    state.revokeId = g.id;
    $("confirm-text").textContent = "Revoke grant #" + g.id + " (" + g.grantee + " -> " + g.role + ")? Access ends immediately.";
    $("confirm-box").hidden = false;
  }

  function renderGrants(grants) {
    fill("grants-body", grants, (g) => {
      const status = grantStatus(g);
      const left = el("td", status === "active" ? remaining(g.ends_at) : "-", "countdown");
      if (status === "active") { left.dataset.ends = g.ends_at; }
      const actions = el("td");
      if (has("admin") && status === "active") { actions.appendChild(button("Revoke", () => askRevoke(g))); }
      return [el("td", "#" + g.id), el("td", g.grantee), el("td", g.role),
        el("td", fmt(g.ends_at)), el("td", status, status), left, actions];
    });
    $("stat-grants").textContent = String(grants.filter((g) => grantStatus(g) === "active").length);
  }

  function renderRequests(requests) {
    fill("requests-body", requests, (r) => {
      const cls = KNOWN_STATUS.indexOf(r.status) >= 0 ? r.status : "";
      const actions = el("td");
      if (has("approve") && r.status === "pending" && r.requester !== state.user) {
        actions.appendChild(button("Approve", () => decide("approve", r.id)));
        actions.appendChild(button("Deny", () => decide("deny", r.id)));
      }
      return [el("td", "#" + r.id), el("td", r.requester), el("td", r.role),
        el("td", r.duration_minutes), el("td", r.status, cls), el("td", r.approvals), actions];
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

  function loadPolicyText() {
    call("/policy").then((res) => {
      if (res.status === 200) {
        $("policy-text").value = JSON.stringify(res.body.policy, null, 2);
        say("Current policy loaded.", true);
      } else { say(failText(res), false); }
    }).catch(() => say("Cannot reach the API.", false));
  }

  function proposePolicy() {
    let parsed;
    try { parsed = JSON.parse($("policy-text").value); }
    catch (e) { say("The policy text is not valid JSON.", false); return; }
    act("/policy/changes", { policy: parsed }, "Policy change proposed. Another admin must approve it.")
      .then(() => { state.policyKey = null; loadPolicyChanges(); });
  }

  function renderPolicyChanges(changes) {
    const classes = { pending: "pending", applied: "approved", rejected: "denied", stale: "expired" };
    fill("policy-body", changes, (c) => {
      const actions = el("td");
      if (c.status === "pending") {
        if (c.proposer !== state.user) {
          actions.appendChild(button("Approve", () => act("/policy/changes/" + c.id + "/approve", undefined, "Policy change #" + c.id + " applied.")));
        }
        actions.appendChild(button("Reject", () => act("/policy/changes/" + c.id + "/reject", undefined, "Policy change #" + c.id + " rejected.")));
      }
      return [el("td", "#" + c.id), el("td", c.proposer), el("td", c.summary),
        el("td", c.status, classes[c.status] || ""), actions];
    });
  }

  function loadPolicyChanges() {
    return call("/policy/changes").then((res) => {
      if (res.status !== 200) { return; }
      const key = JSON.stringify(res.body);
      if (key === state.policyKey) { return; }
      state.policyKey = key;
      renderPolicyChanges(res.body);
    }).catch(() => {});
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
    state.user = null;
    state.caps = [];
    state.roles = [];
    state.revokeId = null;
    state.lastKey = null;
    state.policyKey = null;
    $("policy-text").value = "";
    $("dashboard").hidden = true;
    $("confirm-box").hidden = true;
    $("login").hidden = false;
    $("login-error").textContent = message;
  }

  function refresh() {
    const audit = has("admin") ? call("/audit/verify") : Promise.resolve({ status: 0, body: {} });
    return Promise.all([call("/requests"), call("/grants"), audit]).then((res) => {
      if (res.some((r) => r.status === 401)) { showLogin("Session ended. Sign in again."); return false; }
      if (res[0].status !== 200 || res[1].status !== 200) { showLogin("The API refused the request."); return false; }
      const key = JSON.stringify([res[0].body, res[1].body, res[1].body.map(grantStatus)]);
      if (key !== state.lastKey) {
        state.lastKey = key;
        renderRequests(res[0].body);
        renderGrants(res[1].body);
      }
      renderAudit(res[2]);
      if (has("admin")) { loadPolicyChanges(); }
      return true;
    }).catch(() => { showLogin("Cannot reach the API."); return false; });
  }

  function describeRole() {
    const r = state.roles.find((x) => x.name === $("role").value);
    if (!r) { $("role-hint").textContent = "No role available to request."; return; }
    $("minutes").max = String(r.max_duration_minutes);
    $("role-hint").textContent = r.description + " Risk: " + r.risk + ". Max " + r.max_duration_minutes + " min. Approvals needed: " + r.approvals_required + ".";
  }

  function loadRoles() {
    return call("/roles").then((res) => {
      state.roles = res.status === 200 ? res.body : [];
      const select = $("role");
      select.replaceChildren();
      state.roles.forEach((r) => {
        const option = el("option", r.name);
        option.value = r.name;
        select.appendChild(option);
      });
      describeRole();
    }).catch(() => { state.roles = []; });
  }

  function submitRequest(event) {
    event.preventDefault();
    const minutes = parseInt($("minutes").value, 10);
    const body = { role: $("role").value, minutes: minutes, justification: $("justification").value.trim() };
    const ticket = $("ticket").value.trim();
    if (ticket) { body.ticket = ticket; }
    if (!body.role || isNaN(minutes)) { say("Choose a role and the number of minutes.", false); return; }
    act("/requests", body, "Request sent.").then((ok) => {
      if (ok) { $("justification").value = ""; $("ticket").value = ""; }
    });
  }

  function runCheck(event) {
    event.preventDefault();
    const role = $("check-role").value.trim();
    if (!/^[a-z][a-z0-9-]{1,31}$/.test(role)) { say("Enter a valid role id.", false); return; }
    call("/check", { method: "POST", body: { role: role } }).then((res) => {
      if (res.status === 401) { showLogin("Session ended. Sign in again."); return; }
      if (res.status === 200 && res.body.allowed) { say("ALLOWED until " + fmt(res.body.ends_at) + ".", true); }
      else if (res.status === 200) { say("DENIED: no active grant for this role.", false); }
      else { say(failText(res), false); }
    }).catch(() => say("Cannot reach the API.", false));
  }

  function enter(profile) {
    state.csrf = profile.csrf_token;
    state.user = profile.username;
    state.caps = profile.capabilities;
    $("who").textContent = "Signed in as " + profile.display_name + " (" + profile.username + ")";
    $("panel-request").hidden = !has("request");
    $("panel-decide").hidden = !has("approve");
    $("panel-admin").hidden = !has("admin");
    $("panel-policy").hidden = !has("admin");
    if (has("admin")) { loadPolicyChanges(); }
    say("", true);
    Promise.all([refresh(), loadRoles()]).then((results) => {
      if (!results[0]) { return; }
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
  $("request-form").addEventListener("submit", submitRequest);
  $("check-form").addEventListener("submit", runCheck);
  $("policy-load").addEventListener("click", loadPolicyText);
  $("policy-propose").addEventListener("click", proposePolicy);
  $("role").addEventListener("change", describeRole);
  $("sweep-btn").addEventListener("click", () => act("/sweep", undefined, "Sweep finished."));
  $("confirm-no").addEventListener("click", () => { state.revokeId = null; $("confirm-box").hidden = true; });
  $("confirm-yes").addEventListener("click", () => {
    const id = state.revokeId;
    state.revokeId = null;
    $("confirm-box").hidden = true;
    if (id !== null) { act("/grants/" + id + "/revoke", undefined, "Grant #" + id + " revoked."); }
  });
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
