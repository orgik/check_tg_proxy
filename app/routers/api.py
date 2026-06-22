from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.models import CheckRequest, CheckResponse, TaskStatus
from app.checks.runner import submit_check, get_task, get_queue_position

router = APIRouter(prefix="/api")


@router.post("/check", response_model=CheckResponse)
async def create_check(req: CheckRequest, request: Request):
    ip = request.client.host if request.client else ""
    try:
        task_id, info = await submit_check(req.proxy_link, ip)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"detail": str(e)})

    return CheckResponse(task_id=task_id, status="queued")


@router.get("/status/{task_id}")
async def get_status(task_id: str):
    task = get_task(task_id)
    if not task:
        return JSONResponse(status_code=404, content={"detail": "Task not found"})

    return TaskStatus(
        task_id=task["task_id"],
        status=task["status"],
        proxy_link=task["proxy_link"],
        queue_position=get_queue_position(task_id),
        results=task.get("results"),
        error=task.get("error"),
    )
