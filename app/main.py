import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app import database
from app.checks.fingerprint_check import load_client_hellos
from app.checks.runner import cleanup_old_tasks
from app.routers import api, admin, ws, agent_ws, agent_api

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.init_db()
    from app.routers.admin import init_password
    await init_password()
    load_client_hellos()
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    yield
    cleanup_task.cancel()
    await database.close_db()


async def _periodic_cleanup():
    while True:
        await asyncio.sleep(600)
        await cleanup_old_tasks()


app = FastAPI(title="Telegram Proxy Checker", lifespan=lifespan)

app.include_router(api.router)
app.include_router(admin.router)
app.include_router(ws.router)
app.include_router(agent_ws.router)
app.include_router(agent_api.router)

app.mount("/static/agent", StaticFiles(directory=str(BASE_DIR / "agent")), name="agent_files")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
async def index():
    return FileResponse(str(BASE_DIR / "templates" / "index.html"))


@app.get("/admin")
async def admin_page():
    return FileResponse(str(BASE_DIR / "templates" / "admin.html"))


@app.get("/result/{check_id}")
async def result_page(check_id: str):
    return FileResponse(str(BASE_DIR / "templates" / "index.html"))
