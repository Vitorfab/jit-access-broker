"""Local REST API (lab only) with real login. It reuses the Broker and Auth services.

Safety defaults: the server is started on 127.0.0.1 only (see `serve`); every call except
/health and /auth/login needs the HttpOnly session cookie; state-changing calls also need the
X-CSRF-Token header and a same-origin Origin; foreign Host headers are rejected (DNS rebinding);
there is no CORS and the interactive docs are disabled. Reads are filtered by the user's profile.
The policy is re-read when its file changes; if it cannot be loaded the API answers 503.
"""

import hmac
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi import Path as PathParam
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from jit_broker.audit import AuditError, AuditLog, verify_log
from jit_broker.auth import ABSOLUTE_HOURS, Auth, AuthError
from jit_broker.domain import (
    AccessResult,
    Grant,
    PolicyChange,
    RequestRecord,
    RequestStatus,
    Session,
)
from jit_broker.policy import Capability, Policy, PolicyError, load_policy
from jit_broker.policy_admin import PolicyAdmin
from jit_broker.service import Broker, BrokerError
from jit_broker.store import Store
from jit_broker.ui import register_ui

ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
COOKIE_NAME = "jit_session"


class PolicySource:
    """The current policy. With a file path it reloads whenever the file changes."""

    def __init__(self, policy: Policy, path: Path | None) -> None:
        self._policy = policy
        self._path = path
        self._signature = self._stat()

    def _stat(self) -> tuple[int, int] | None:
        if self._path is None:
            return None
        try:
            info = self._path.stat()
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size)

    def get(self) -> Policy:
        if self._path is not None:
            signature = self._stat()
            if signature != self._signature:
                self._policy = load_policy(self._path)
                self._signature = signature
        return self._policy


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginBody(_Body):
    username: str
    password: str


class RequestBody(_Body):
    role: str = Field(min_length=1, max_length=32)
    minutes: int = Field(ge=1, le=1440)
    justification: str = Field(min_length=1, max_length=500)
    ticket: str | None = Field(default=None, max_length=40)


class ReasonBody(_Body):
    reason: str = Field(min_length=1, max_length=200)


class CheckBody(_Body):
    role: str = Field(min_length=1, max_length=32)


class ProposalBody(_Body):
    policy: dict[str, Any]


class RoleInfo(BaseModel):
    name: str
    description: str
    risk: str
    max_duration_minutes: int
    approvals_required: int


class PolicyView(BaseModel):
    digest: str
    policy: dict[str, Any]


class Profile(BaseModel):
    username: str
    display_name: str
    capabilities: list[Capability]
    csrf_token: str


def create_app(
    policy: Policy, db: Path, audit_path: Path, policy_path: Path | None = None
) -> FastAPI:
    app = FastAPI(title="jit-access-broker (lab)", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
    source = PolicySource(policy, policy_path)

    def current() -> Policy:
        try:
            return source.get()
        except PolicyError as exc:
            raise HTTPException(status_code=503, detail="policy unavailable") from exc

    @contextmanager
    def services() -> Iterator[tuple[Broker, Auth]]:
        active = current()
        # One SQLite connection per call, opened and closed in the same thread.
        store = Store(db)
        log = AuditLog(audit_path)
        try:
            yield Broker(active, store, log), Auth(active, store, log)
        finally:
            store.close()

    @contextmanager
    def editor() -> Iterator[PolicyAdmin]:
        if policy_path is None:
            raise HTTPException(status_code=404, detail="policy editor is disabled")
        current()
        store = Store(db)
        try:
            yield PolicyAdmin(policy_path, store, AuditLog(audit_path))
        finally:
            store.close()

    @contextmanager
    def handled() -> Iterator[None]:
        try:
            yield
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except BrokerError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except AuditError as exc:
            raise HTTPException(status_code=500, detail="audit log error") from exc

    def check_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin is not None and urlsplit(origin).netloc != request.headers.get("host", ""):
            raise HTTPException(status_code=403, detail="cross-origin request refused")

    def load_session(request: Request, touch: bool) -> Session:
        token = request.cookies.get(COOKIE_NAME, "")
        active = current()
        with services() as (_, auth):
            session = auth.authenticate(token, touch=touch)
        if session is None or session.username not in active.users:
            raise HTTPException(status_code=401, detail="not authenticated")
        return session

    def read_session(request: Request) -> Session:
        # Automatic page refreshes must not keep a session alive: only user actions count.
        return load_session(request, touch=False)

    def touching_session(request: Request) -> Session:
        return load_session(request, touch=True)

    def write_session(request: Request) -> Session:
        check_origin(request)
        session = load_session(request, touch=True)
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent.encode("utf-8"), session.csrf.encode("utf-8")):
            raise HTTPException(status_code=403, detail="invalid CSRF token")
        return session

    def profile(username: str, csrf: str) -> Profile:
        person = current().users.get(username)
        if person is None:
            raise HTTPException(status_code=401, detail="not authenticated")
        return Profile(
            username=username,
            display_name=person.display_name,
            capabilities=list(person.capabilities),
            csrf_token=csrf,
        )

    ReadSession = Annotated[Session, Depends(read_session)]
    WriteSession = Annotated[Session, Depends(write_session)]

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/auth/login")
    def login(body: LoginBody, request: Request, response: Response) -> Profile:
        check_origin(request)
        with handled(), services() as (_, auth):
            result = auth.login(body.username, body.password)
        response.set_cookie(
            COOKIE_NAME,
            result.token,
            max_age=ABSOLUTE_HOURS * 3600,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return profile(result.username, result.csrf)

    @app.get("/auth/me")
    def me(session: Annotated[Session, Depends(touching_session)]) -> Profile:
        return profile(session.username, session.csrf)

    @app.post("/auth/logout")
    def logout(request: Request, response: Response, session: WriteSession) -> dict[str, str]:
        token = request.cookies.get(COOKIE_NAME, "")
        with handled(), services() as (_, auth):
            auth.logout(token)
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"status": "logged out"}

    @app.get("/roles")
    def list_roles(session: ReadSession) -> list[RoleInfo]:
        with handled(), services() as (broker, _):
            roles = broker.requestable_roles(session.username)
        return [
            RoleInfo(
                name=name,
                description=role.description,
                risk=role.risk.value,
                max_duration_minutes=role.max_duration_minutes,
                approvals_required=role.approvals_required,
            )
            for name, role in roles
        ]

    @app.post("/requests", status_code=201)
    def create_request(body: RequestBody, session: WriteSession) -> RequestRecord:
        with handled(), services() as (broker, _):
            record = broker.request_access(
                session.username, body.role, body.minutes, body.justification, body.ticket
            )
        return record

    @app.get("/requests")
    def list_requests(
        session: ReadSession, status: RequestStatus | None = None
    ) -> list[RequestRecord]:
        with handled(), services() as (broker, _):
            records = broker.visible_requests(session.username, status)
        return records

    @app.post("/requests/{request_id}/approve")
    def approve(
        request_id: Annotated[int, PathParam(ge=1)], body: ReasonBody, session: WriteSession
    ) -> RequestRecord:
        with handled(), services() as (broker, _):
            record = broker.approve(request_id, session.username, body.reason)
        return record

    @app.post("/requests/{request_id}/deny")
    def deny(
        request_id: Annotated[int, PathParam(ge=1)], body: ReasonBody, session: WriteSession
    ) -> RequestRecord:
        with handled(), services() as (broker, _):
            record = broker.deny(request_id, session.username, body.reason)
        return record

    @app.get("/grants")
    def list_grants(session: ReadSession) -> list[Grant]:
        with handled(), services() as (broker, _):
            grants = broker.visible_grants(session.username)
        return grants

    @app.post("/check")
    def check(body: CheckBody, session: WriteSession) -> AccessResult:
        with handled(), services() as (broker, _):
            result = broker.check_access(session.username, body.role)
        return result

    @app.post("/grants/{grant_id}/revoke")
    def revoke(grant_id: Annotated[int, PathParam(ge=1)], session: WriteSession) -> Grant:
        with handled(), services() as (broker, _):
            grant = broker.revoke_grant(grant_id, session.username)
        return grant

    @app.post("/sweep")
    def sweep(session: WriteSession) -> dict[str, int]:
        with handled(), services() as (broker, _):
            count = broker.sweep_expired(session.username)
        return {"expired": count}

    @app.get("/audit/verify")
    def audit_verify(session: ReadSession) -> dict[str, str | int]:
        person = current().users.get(session.username)
        if person is None or Capability.ADMIN not in person.capabilities:
            raise HTTPException(status_code=403, detail="admin only")
        try:
            result = verify_log(audit_path)
        except AuditError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"entries": result.entries, "head_hash": result.head_hash}

    @app.get("/policy")
    def get_policy(session: ReadSession) -> PolicyView:
        with handled(), editor() as admin:
            data, digest = admin.view_policy(session.username)
        return PolicyView(digest=digest, policy=data)

    @app.get("/policy/changes")
    def list_policy_changes(session: ReadSession) -> list[PolicyChange]:
        with handled(), editor() as admin:
            changes = admin.list_changes(session.username)
        return changes

    @app.post("/policy/changes", status_code=201)
    def propose_policy_change(body: ProposalBody, session: WriteSession) -> PolicyChange:
        with handled(), editor() as admin:
            change = admin.propose(session.username, body.policy)
        return change

    @app.post("/policy/changes/{change_id}/approve")
    def approve_policy_change(
        change_id: Annotated[int, PathParam(ge=1)], session: WriteSession
    ) -> PolicyChange:
        with handled(), editor() as admin:
            change = admin.approve(change_id, session.username)
        return change

    @app.post("/policy/changes/{change_id}/reject")
    def reject_policy_change(
        change_id: Annotated[int, PathParam(ge=1)], session: WriteSession
    ) -> PolicyChange:
        with handled(), editor() as admin:
            change = admin.reject(change_id, session.username)
        return change

    register_ui(app)
    return app
