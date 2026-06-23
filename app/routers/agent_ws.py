import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app import database
from app.agent_manager import manager

router = APIRouter()


@router.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket):
    await websocket.accept()

    try:
        auth_msg = await asyncio.wait_for(websocket.receive_json(), timeout=10)
    except Exception:
        await websocket.close(code=4001, reason="Auth timeout")
        return

    token = auth_msg.get("token", "")
    agent = await database.get_agent_by_token(token)
    if not agent:
        await websocket.close(code=4003, reason="Invalid token")
        return

    agent_id = agent["id"]
    agent_info = {
        "name": agent["name"],
        "agent_type": agent["agent_type"],
        "ip": auth_msg.get("ip", ""),
        "country": auth_msg.get("country", ""),
        "city": auth_msg.get("city", ""),
        "isp": auth_msg.get("isp", ""),
    }

    await manager.register_ws(agent_id, agent_info, websocket)
    await websocket.send_json({"type": "auth_ok", "agent_id": agent_id})

    try:
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_json(), timeout=60)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue

            if msg.get("type") == "pong":
                continue
            elif msg.get("type") == "result":
                task_id = msg.get("task_id", "")
                result = msg.get("result", {})
                manager.receive_result(agent_id, task_id, result)
            elif msg.get("type") == "heartbeat":
                info = msg.get("info", {})
                if info:
                    await database.update_agent_status(
                        agent_id, "online",
                        ip=info.get("ip", ""),
                        country=info.get("country", ""),
                        city=info.get("city", ""),
                    )

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.unregister_ws(agent_id)
        await database.update_agent_status(agent_id, "offline")
