"""Event bus.
1) One bounded asyncio.Queue shared by all producers and the ingester (backpressure: normal events are
   dropped and counted when full; events published with droppable=False wait for space instead).
2) WebSocket broadcast: every connected dashboard has its own small queue; broadcast() never blocks."""
import asyncio
import json

from app import config

queue: asyncio.Queue = asyncio.Queue(maxsize=config.QUEUE_MAXSIZE)
stats = {"dropped": 0}
clients: set = set()  # one asyncio.Queue of ready-to-send JSON strings per connected WebSocket


async def publish(event: dict, droppable: bool = True) -> None:
    if droppable:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            stats["dropped"] += 1  # shed normal load, never block the producer
    else:
        await queue.put(event)  # important events: wait, never drop


def register() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    clients.add(q)
    return q


def unregister(q: asyncio.Queue) -> None:
    clients.discard(q)


def broadcast(type_: str, data) -> None:
    """Push {type, data} to every dashboard. Synchronous and non-blocking, so it can be called from anywhere.
    A slow client sheds live-feed events first; for other messages the oldest queued message makes room."""
    if not clients:
        return
    msg = json.dumps({"type": type_, "data": data}, default=str)
    for q in list(clients):
        if q.full():
            if type_ == "event":
                continue
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                pass
        q.put_nowait(msg)
