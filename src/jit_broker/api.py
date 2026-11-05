"""Local REST API (lab only). It reuses the Broker: no rules are duplicated here.

Safety defaults: the server is started on 127.0.0.1 only (see the `serve` command), every call
needs the random bearer token printed at startup, requests with a foreign Host header are
rejected (DNS rebinding), there is no CORS, and the interactive docs are disabled.
`X-Acting-User` selects a simulated user: it is NOT real authentication.
"""

import hmac
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi import Path as PathParam
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from jit_broker.audit import AuditError, AuditLog, verify_log
from jit_broker.domain import AccessResult, Grant, RequestRecord, RequestStatus
from jit_broker.policy import Policy
from jit_broker.service import Broker, BrokerError
from jit_broker.store import Store

ALLOWED_HOSTS = ["127.0.0.1", "localhost"]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RequestBody(_Body):
    role: str = Field(min_length=1, max_length=32)
    minutes: int = Field(ge=1, le=1440)
    justification: str = Field(min_length=1, max_length=500)
    ticket: str | None = Field(default=None, max_length=40)


class ReasonBody(_Body):
    reason: str = Field(min_length=1, max_length=200)


class CheckBody(_Body):
    role: str = Field(min_length=1, max_length=32)


def create_app(policy: Policy, db: Path, audit_path: Path, token: str) -> FastAPI:
    app = FastAPI(title="jit-access-broker (lab)", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

    @contextmanager
    def open_broker() -> Iterator[Broker]:
        # One SQLite connection per call, opened and closed in the same thread.
        store = Store(db)
        try:
            yield Broker(policy, store, AuditLog(audit_path))
        finally:
            store.close()

    @contextmanager
    def handled() -> Iterator[None]:
        try:
            yield
        except BrokerError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except AuditError as exc:
            raise HTTPException(status_code=500, detail="audit log error") from exc

    def acting_user(
        authorization: Annotated[str | None, Header()] = None,
        x_acting_user: Annotated[str | None, Header()] = None,
    ) -> str:
        expected = f"Bearer {token}".encode()
        given = (authorization or "").encode()
        if not hmac.compare_digest(given, expected):
            raise HTTPException(status_code=401, detail="missing or invalid token")
        if not x_acting_user:
            raise HTTPException(status_code=400, detail="X-Acting-User header is required")
        return x_acting_user

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/requests", status_code=201)
    def create_request(
        body: RequestBody, user: Annotated[str, Depends(acting_user)]
    ) -> RequestRecord:
        with handled(), open_broker() as broker:
            record = broker.request_access(
                user, body.role, body.minutes, body.justification, body.ticket
            )
        return record

    @app.get("/requests")
    def list_requests(
        user: Annotated[str, Depends(acting_user)], status: RequestStatus | None = None
    ) -> list[RequestRecord]:
        with handled(), open_broker() as broker:
            records = broker.list_requests(status)
        return records

    @app.post("/requests/{request_id}/approve")
    def approve(
        request_id: Annotated[int, PathParam(ge=1)],
        body: ReasonBody,
        user: Annotated[str, Depends(acting_user)],
    ) -> RequestRecord:
        with handled(), open_broker() as broker:
            record = broker.approve(request_id, user, body.reason)
        return record

    @app.post("/requests/{request_id}/deny")
    def deny(
        request_id: Annotated[int, PathParam(ge=1)],
        body: ReasonBody,
        user: Annotated[str, Depends(acting_user)],
    ) -> RequestRecord:
        with handled(), open_broker() as broker:
            record = broker.deny(request_id, user, body.reason)
        return record

    @app.get("/grants")
    def list_grants(user: Annotated[str, Depends(acting_user)]) -> list[Grant]:
        with handled(), open_broker() as broker:
            grants = broker.list_grants()
        return grants

    @app.post("/check")
    def check(body: CheckBody, user: Annotated[str, Depends(acting_user)]) -> AccessResult:
        with handled(), open_broker() as broker:
            result = broker.check_access(user, body.role)
        return result

    @app.post("/grants/{grant_id}/revoke")
    def revoke(
        grant_id: Annotated[int, PathParam(ge=1)], user: Annotated[str, Depends(acting_user)]
    ) -> Grant:
        with handled(), open_broker() as broker:
            grant = broker.revoke_grant(grant_id, user)
        return grant

    @app.post("/sweep")
    def sweep(user: Annotated[str, Depends(acting_user)]) -> dict[str, int]:
        with handled(), open_broker() as broker:
            count = broker.sweep_expired(user)
        return {"expired": count}

    @app.get("/audit/verify")
    def audit_verify(user: Annotated[str, Depends(acting_user)]) -> dict[str, str | int]:
        try:
            result = verify_log(audit_path)
        except AuditError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"entries": result.entries, "head_hash": result.head_hash}

    return app
