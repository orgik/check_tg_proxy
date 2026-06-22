import hmac
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from pydantic import BaseModel

from app.config import ADMIN_PASSWORD, SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_HOURS
from app.models import AdminLoginRequest
from app import database

router = APIRouter(prefix="/api/admin")

_current_password = ADMIN_PASSWORD


def _create_token() -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode({"sub": "admin", "exp": exp}, SECRET_KEY, algorithm=JWT_ALGORITHM)


def _verify_token(token: str) -> bool:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload.get("sub") == "admin"
    except JWTError:
        return False


def _check_password(password: str) -> bool:
    return hmac.compare_digest(password, _current_password)


async def require_admin(request: Request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        token = request.cookies.get("admin_token", "")
    if not _verify_token(token):
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return None


async def init_password():
    global _current_password
    stored = await database.get_setting("admin_password")
    if stored:
        _current_password = stored


@router.post("/login")
async def admin_login(req: AdminLoginRequest):
    if not _check_password(req.password):
        return JSONResponse(status_code=401, content={"detail": "Invalid password"})
    token = _create_token()
    response = JSONResponse(content={"token": token})
    response.set_cookie("admin_token", token, httponly=True, max_age=JWT_EXPIRE_HOURS * 3600, samesite="strict")
    return response


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
async def change_password(req: ChangePasswordRequest, request: Request):
    auth_err = await require_admin(request)
    if auth_err:
        return auth_err
    if not _check_password(req.current_password):
        return JSONResponse(status_code=400, content={"detail": "Wrong current password"})
    if len(req.new_password) < 4:
        return JSONResponse(status_code=400, content={"detail": "Password too short (min 4)"})

    global _current_password
    _current_password = req.new_password
    await database.set_setting("admin_password", req.new_password)
    return {"ok": True}


@router.get("/checks")
async def list_checks(request: Request, page: int = 1, per_page: int = 20,
                      status: str = "", search: str = ""):
    auth_err = await require_admin(request)
    if auth_err:
        return auth_err
    checks, total = await database.get_checks(page, per_page, status, search)
    return {
        "checks": checks,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


@router.get("/stats")
async def admin_stats(request: Request):
    auth_err = await require_admin(request)
    if auth_err:
        return auth_err
    return await database.get_stats()
