import secrets
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app import database
from app.agent_manager import manager
from app.routers.admin import require_admin

router = APIRouter(prefix="/api/agent")


async def _auth_agent(request: Request) -> dict | None:
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        return None
    agent = await database.get_agent_by_token(token)
    if not agent:
        return None
    return agent


@router.post("/register")
async def register_agent(request: Request):
    auth_err = await require_admin(request)
    if auth_err:
        return auth_err

    body = await request.json()
    name = body.get("name", "").strip()
    agent_type = body.get("type", "datacenter")

    if not name:
        return JSONResponse(status_code=400, content={"detail": "Name required"})
    if agent_type not in ("datacenter", "residential"):
        return JSONResponse(status_code=400, content={"detail": "Type must be 'datacenter' or 'residential'"})

    agent_id = str(uuid4())[:8]
    token = secrets.token_hex(24)

    await database.save_agent(agent_id, name, token, agent_type)

    return {
        "agent_id": agent_id,
        "name": name,
        "token": token,
        "type": agent_type,
    }


@router.get("/token/{agent_id}")
async def get_agent_token(agent_id: str, request: Request):
    auth_err = await require_admin(request)
    if auth_err:
        return auth_err
    agent = await database.get_agent(agent_id)
    if not agent:
        return JSONResponse(status_code=404, content={"detail": "Agent not found"})
    return {"agent_id": agent["id"], "name": agent["name"], "token": agent["token"]}


@router.delete("/remove/{agent_id}")
async def remove_agent(agent_id: str, request: Request):
    auth_err = await require_admin(request)
    if auth_err:
        return auth_err
    await database.delete_agent(agent_id)
    return {"ok": True}


@router.get("/list")
async def list_agents(request: Request):
    auth_err = await require_admin(request)
    if auth_err:
        return auth_err

    db_agents = await database.get_all_agents()
    online = {a["id"]: a for a in manager.get_online_agents()}

    result = []
    for a in db_agents:
        info = online.get(a["id"], {})
        result.append({
            **a,
            "online": info.get("online", False),
            "mode": info.get("mode", ""),
            "busy": info.get("busy", False),
        })

    return result


@router.get("/task")
async def poll_task(request: Request):
    agent = await _auth_agent(request)
    if not agent:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    info = {
        "name": agent["name"],
        "agent_type": agent["agent_type"],
        "ip": request.headers.get("X-Agent-IP", ""),
        "country": request.headers.get("X-Agent-Country", ""),
        "city": request.headers.get("X-Agent-City", ""),
        "isp": request.headers.get("X-Agent-ISP", ""),
    }
    manager.register_poll(agent["id"], info)
    await database.update_agent_status(agent["id"], "online", ip=info.get("ip", ""))

    task = await manager.get_poll_task(agent["id"])
    if task:
        return {"task": task}
    return {"task": None}


@router.post("/result")
async def submit_result(request: Request):
    agent = await _auth_agent(request)
    if not agent:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    body = await request.json()
    task_id = body.get("task_id", "")
    result = body.get("result", {})

    manager.receive_result(agent["id"], task_id, result)
    return {"ok": True}


@router.get("/online")
async def online_agents():
    agents = manager.get_online_agents()
    return [
        {"id": a["id"], "name": a["name"], "type": a["type"],
         "ip": a["ip"], "country": a["country"], "city": a["city"], "isp": a.get("isp", ""), "online": a["online"]}
        for a in agents if a["online"]
    ]
