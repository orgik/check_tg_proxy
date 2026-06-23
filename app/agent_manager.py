import asyncio
import json
import time
from uuid import uuid4
from fastapi import WebSocket

from app import database


class AgentConnection:
    def __init__(self, agent_id: str, agent_info: dict, ws: WebSocket | None = None):
        self.agent_id = agent_id
        self.info = agent_info
        self.ws = ws
        self.last_seen = time.time()
        self.busy = False
        self.pending_tasks: dict[str, asyncio.Future] = {}

    @property
    def online(self):
        return self.ws is not None or (time.time() - self.last_seen < 30)

    @property
    def mode(self):
        return "ws" if self.ws else "polling"


class AgentManager:
    def __init__(self):
        self._agents: dict[str, AgentConnection] = {}
        self._task_queue: dict[str, dict] = {}
        self._poll_queues: dict[str, asyncio.Queue] = {}

    def get_online_agents(self) -> list[dict]:
        result = []
        for aid, conn in self._agents.items():
            result.append({
                "id": aid,
                "name": conn.info.get("name", ""),
                "type": conn.info.get("agent_type", "datacenter"),
                "ip": conn.info.get("ip", ""),
                "country": conn.info.get("country", ""),
                "city": conn.info.get("city", ""),
                "isp": conn.info.get("isp", ""),
                "online": conn.online,
                "mode": conn.mode,
                "busy": conn.busy,
            })
        return result

    async def register_ws(self, agent_id: str, agent_info: dict, ws: WebSocket):
        if agent_id in self._agents:
            self._agents[agent_id].ws = ws
            self._agents[agent_id].info = agent_info
            self._agents[agent_id].last_seen = time.time()
        else:
            self._agents[agent_id] = AgentConnection(agent_id, agent_info, ws)
        await database.update_agent_status(
            agent_id, "online",
            ip=agent_info.get("ip", ""),
            country=agent_info.get("country", ""),
            city=agent_info.get("city", ""),
            isp=agent_info.get("isp", ""),
        )

    def unregister_ws(self, agent_id: str):
        conn = self._agents.get(agent_id)
        if conn:
            conn.ws = None
            for fut in conn.pending_tasks.values():
                if not fut.done():
                    fut.set_result(None)
            conn.pending_tasks.clear()

    def register_poll(self, agent_id: str, agent_info: dict):
        if agent_id in self._agents:
            self._agents[agent_id].info = agent_info
            self._agents[agent_id].last_seen = time.time()
        else:
            self._agents[agent_id] = AgentConnection(agent_id, agent_info)
        if agent_id not in self._poll_queues:
            self._poll_queues[agent_id] = asyncio.Queue(maxsize=10)

    async def submit_task(self, task: dict, agent_id: str | None = None) -> asyncio.Future | None:
        target = None
        if agent_id:
            target = self._agents.get(agent_id)
            if not target or not target.online:
                return None
        else:
            for conn in self._agents.values():
                if conn.online and not conn.busy:
                    target = conn
                    break

        if not target:
            return None

        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        task_id = task["task_id"]
        target.pending_tasks[task_id] = fut
        target.busy = True

        if target.ws:
            try:
                await target.ws.send_json({"type": "task", "task": task})
            except Exception:
                target.ws = None
                target.busy = False
                del target.pending_tasks[task_id]
                return None
        else:
            q = self._poll_queues.get(target.agent_id)
            if q:
                await q.put(task)

        return fut

    async def get_poll_task(self, agent_id: str) -> dict | None:
        q = self._poll_queues.get(agent_id)
        if not q:
            return None
        conn = self._agents.get(agent_id)
        if conn:
            conn.last_seen = time.time()
        try:
            return q.get_nowait()
        except asyncio.QueueEmpty:
            return None

    def receive_result(self, agent_id: str, task_id: str, result: dict):
        conn = self._agents.get(agent_id)
        if not conn:
            return
        conn.busy = False
        conn.last_seen = time.time()
        fut = conn.pending_tasks.pop(task_id, None)
        if fut and not fut.done():
            fut.set_result(result)

    async def submit_to_all(self, task: dict) -> dict[str, asyncio.Future]:
        futures = {}
        for aid, conn in self._agents.items():
            if conn.online:
                task_copy = {**task, "task_id": task["task_id"] + f"_{aid}"}
                fut = await self.submit_task(task_copy, agent_id=aid)
                if fut:
                    futures[aid] = fut
        return futures


manager = AgentManager()
