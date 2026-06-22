import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.checks.runner import subscribe, unsubscribe

router = APIRouter()


@router.websocket("/ws/check/{task_id}")
async def ws_check(websocket: WebSocket, task_id: str):
    await websocket.accept()
    q = subscribe(task_id)
    try:
        while True:
            try:
                update = await asyncio.wait_for(q.get(), timeout=60)
                safe = {
                    "task_id": update.get("task_id"),
                    "status": update.get("status"),
                    "results": update.get("results"),
                    "error": update.get("error"),
                }
                await websocket.send_json(safe)
                if update.get("status") in ("completed", "failed"):
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        unsubscribe(task_id, q)
