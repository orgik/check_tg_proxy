from pydantic import BaseModel
from typing import Optional


class CheckRequest(BaseModel):
    proxy_link: str


class CheckResponse(BaseModel):
    task_id: str
    status: str


class TcpCheckResult(BaseModel):
    success: bool
    rtt_ms: float = 0
    error: Optional[str] = None


class TlsCheckResult(BaseModel):
    success: Optional[bool] = None
    rtt_ms: float = 0
    error: Optional[str] = None


class FingerprintResult(BaseModel):
    client_name: str
    mode: str
    success: bool
    duration_ms: float = 0
    error: Optional[str] = None


class ServerInfo(BaseModel):
    ip: Optional[str] = None
    reverse_dns: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    as_number: Optional[str] = None
    hosting: Optional[bool] = None
    proxy: Optional[bool] = None
    error: Optional[str] = None


class CheckerInfo(BaseModel):
    ip: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    as_number: Optional[str] = None


class CheckResults(BaseModel):
    server: str
    port: int
    sni: str
    tcp: TcpCheckResult
    tls: TlsCheckResult
    fingerprints: list[FingerprintResult]
    server_info: Optional[ServerInfo] = None
    checker_info: Optional[CheckerInfo] = None
    tls_cert: Optional[dict] = None
    stability: Optional[dict] = None
    dpi: Optional[dict] = None
    dns: Optional[dict] = None
    overall_status: str


class TaskStatus(BaseModel):
    task_id: str
    status: str
    proxy_link: str
    queue_position: Optional[int] = None
    results: Optional[CheckResults] = None
    error: Optional[str] = None


class AdminLoginRequest(BaseModel):
    password: str


class AdminLoginResponse(BaseModel):
    token: str
