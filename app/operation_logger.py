"""
Operation Logger Module

Handles logging of backup, restore, and transfer operations to files
and maintains an operation history database.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
import uuid


class OperationLogger:
    """Logger for database operations (backup, restore, transfer)"""

    def __init__(self, logs_dir: str = "./logs", history_file: str = "./logs/operation_history.json"):
        """
        Initialize the operation logger.

        Args:
            logs_dir: Directory to store operation log files
            history_file: JSON file to store operation history
        """
        self.logs_dir = Path(logs_dir)
        self.history_file = Path(history_file)

        # Create logs directory if it doesn't exist
        self.logs_dir.mkdir(exist_ok=True, parents=True)

        # Initialize history file if it doesn't exist
        if not self.history_file.exists():
            self._save_history([])

    def start_operation(
        self,
        operation_type: str,
        endpoint: str,
        database: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Start a new operation and create a log file.

        Args:
            operation_type: Type of operation (backup, restore, transfer)
            endpoint: Database endpoint name
            database: Database name
            metadata: Additional metadata (e.g., filename, schemas, etc.)

        Returns:
            Operation ID (UUID)
        """
        operation_id = str(uuid.uuid4())
        timestamp = datetime.now()

        # Create log file
        log_filename = f"{operation_id}.log"
        log_path = self.logs_dir / log_filename

        # Write header to log file
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"Operation ID: {operation_id}\n")
            f.write(f"Type: {operation_type.upper()}\n")
            f.write(f"Endpoint: {endpoint}\n")
            f.write(f"Database: {database}\n")
            f.write(f"Started: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            if metadata:
                f.write(f"Metadata: {json.dumps(metadata, indent=2)}\n")
            f.write("=" * 80 + "\n\n")

        # Add to history
        history = self._load_history()
        history.insert(0, {
            "operation_id": operation_id,
            "type": operation_type,
            "endpoint": endpoint,
            "database": database,
            "started_at": timestamp.isoformat(),
            "status": "running",
            "log_file": log_filename,
            "metadata": metadata or {}
        })
        self._save_history(history)

        return operation_id

    def log_message(self, operation_id: str, message: str):
        """
        Append a message to the operation log file.

        Args:
            operation_id: Operation ID
            message: Message to log
        """
        log_path = self.logs_dir / f"{operation_id}.log"

        if log_path.exists():
            with open(log_path, 'a', encoding='utf-8') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"[{timestamp}] {message}\n")

    def complete_operation(
        self,
        operation_id: str,
        status: str = "completed",
        error: Optional[str] = None
    ):
        """
        Mark an operation as completed and update history.

        Args:
            operation_id: Operation ID
            status: Final status (completed, failed, cancelled)
            error: Error message if operation failed
        """
        log_path = self.logs_dir / f"{operation_id}.log"
        timestamp = datetime.now()

        # Write footer to log file
        if log_path.exists():
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Status: {status.upper()}\n")
                f.write(f"Completed: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
                if error:
                    f.write(f"Error: {error}\n")
                f.write("=" * 80 + "\n")

        # Update history
        history = self._load_history()
        for operation in history:
            if operation["operation_id"] == operation_id:
                operation["status"] = status
                operation["completed_at"] = timestamp.isoformat()
                if error:
                    operation["error"] = error
                break
        self._save_history(history)

    def get_operation_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent operation history.

        Args:
            limit: Maximum number of operations to return

        Returns:
            List of operation records
        """
        history = self._load_history()
        return history[:limit]

    def get_operation(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get details of a specific operation.

        Args:
            operation_id: Operation ID

        Returns:
            Operation record or None if not found
        """
        history = self._load_history()
        for operation in history:
            if operation["operation_id"] == operation_id:
                return operation
        return None

    def get_log_file_path(self, operation_id: str) -> Optional[Path]:
        """
        Get the path to an operation's log file.

        Args:
            operation_id: Operation ID

        Returns:
            Path to log file or None if not found
        """
        log_path = self.logs_dir / f"{operation_id}.log"
        return log_path if log_path.exists() else None

    def clear_history(self, keep_running: bool = True) -> int:
        """
        Clear operation history and delete associated log files.

        Args:
            keep_running: If True, preserve operations with status "running"

        Returns:
            Number of operations removed
        """
        history = self._load_history()
        if keep_running:
            kept = [op for op in history if op.get("status") == "running"]
            removed = len(history) - len(kept)
        else:
            kept = []
            removed = len(history)

        # Delete log files for removed operations
        for op in history:
            if op not in kept:
                log_path = self.logs_dir / op.get("log_file", "")
                if log_path.exists():
                    try:
                        log_path.unlink()
                    except OSError:
                        pass

        self._save_history(kept)
        return removed

    def _load_history(self) -> List[Dict[str, Any]]:
        """Load operation history from JSON file."""
        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_history(self, history: List[Dict[str, Any]]):
        """Save operation history to JSON file."""
        # Keep only the last 100 operations to avoid file growing too large
        history = history[:100]

        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)


# Global logger instance
_logger: Optional[OperationLogger] = None


def get_logger() -> OperationLogger:
    """Get the global operation logger instance."""
    global _logger
    if _logger is None:
        _logger = OperationLogger()
    return _logger
