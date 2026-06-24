"""
Operation Broadcaster Module

Provides in-memory pub/sub for operation progress messages,
allowing multiple clients to follow a running operation.
"""

import asyncio
from typing import Dict, List, Tuple, Optional


class OperationBroadcaster:
    """
    In-memory broadcaster for operation progress messages.

    When an operation starts, it registers with the broadcaster.
    Each progress message is buffered and pushed to all subscriber queues.
    New subscribers receive the full history before streaming live updates.
    """

    def __init__(self):
        self._buffers: Dict[str, List[dict]] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._cleanup_tasks: Dict[str, asyncio.Task] = {}

    def start_operation(self, operation_id: str):
        """Register a new operation for broadcasting."""
        # Cancel any pending cleanup for this ID (e.g. quick restart)
        if operation_id in self._cleanup_tasks:
            self._cleanup_tasks[operation_id].cancel()
            del self._cleanup_tasks[operation_id]

        self._buffers[operation_id] = []
        self._subscribers[operation_id] = []

    def broadcast(self, operation_id: str, message: dict):
        """Buffer a message and push it to all subscribers."""
        if operation_id not in self._buffers:
            return

        self._buffers[operation_id].append(message)

        for queue in self._subscribers.get(operation_id, []):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                pass  # Drop message for slow consumers

    def subscribe(self, operation_id: str) -> Tuple[List[dict], asyncio.Queue]:
        """
        Subscribe to an operation's messages.

        Returns:
            Tuple of (history_list, queue) where history_list is all messages
            sent so far, and queue will receive future messages.
        """
        history = list(self._buffers.get(operation_id, []))
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        if operation_id in self._subscribers:
            self._subscribers[operation_id].append(queue)
        return history, queue

    def unsubscribe(self, operation_id: str, queue: asyncio.Queue):
        """Remove a subscriber queue."""
        if operation_id in self._subscribers:
            try:
                self._subscribers[operation_id].remove(queue)
            except ValueError:
                pass

    def end_operation(self, operation_id: str):
        """
        Mark an operation as ended.

        Sends a sentinel to remaining subscribers and schedules
        buffer cleanup after 5 minutes.
        """
        # Notify remaining subscribers that the operation ended
        for queue in self._subscribers.get(operation_id, []):
            try:
                queue.put_nowait(None)  # sentinel
            except asyncio.QueueFull:
                pass

        # Remove subscriber list
        self._subscribers.pop(operation_id, None)

        # Schedule buffer cleanup
        async def _cleanup():
            await asyncio.sleep(300)  # 5 minutes
            self._buffers.pop(operation_id, None)
            self._cleanup_tasks.pop(operation_id, None)

        try:
            loop = asyncio.get_running_loop()
            self._cleanup_tasks[operation_id] = loop.create_task(_cleanup())
        except RuntimeError:
            # No running loop, just clean up immediately
            self._buffers.pop(operation_id, None)

    def is_active(self, operation_id: str) -> bool:
        """Check if an operation is currently being broadcast."""
        return operation_id in self._subscribers


# Singleton instance
broadcaster = OperationBroadcaster()
