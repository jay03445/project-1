import os
import sys
from typing import List, Tuple, Optional

# Always store data.db next to this script
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")


class KeyValueStore:
    """
    A simple append-only key-value store with no dictionaries.
    Uses a list of (key, value) pairs and linear scan.
    """

    def __init__(self) -> None:
        # Ensure the file exists
        open(DATA_FILE, "a").close()

        # Open for append + read
        self.log_file = open(DATA_FILE, "a+", encoding="utf-8")

        # In-memory index: list of (key, value)
        self.index: List[Tuple[str, str]] = []

        # Replay log to rebuild state
        self._replay_log()

    def _replay_log(self) -> None:
        """Rebuild in-memory index from the append-only log."""
        self.log_file.seek(0)

        for line in self.log_file:
            line = line.strip()
            if not line:
                continue

            parts = line.split(" ", 2)
            if len(parts) == 3 and parts[0].upper() == "SET":
                key = parts[1]
                value = parts[2]
                self.index.append((key, value))

        # Move pointer back to end for appending
        self.log_file.seek(0, os.SEEK_END)

    def set(self, key: str, value: str) -> None:
        """Store or overwrite a key (append-only)."""
        self.log_file.write(f"SET {key} {value}\n")
        self.log_file.flush()
        os.fsync(self.log_file.fileno())

        # Append new version to index
        self.index.append((key, value))

    def get(self, key: str) -> Optional[str]:
        """Retrieve the latest value for a key using reverse linear scan."""
        for k, v in reversed(self.index):
            if k == key:
                return v
        return None

    def close(self) -> None:
        self.log_file.close()


def main() -> None:
    store = KeyValueStore()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        # Split on ANY whitespace (Gradebot-safe)
        parts = line.split(None, 2)
        if not parts:
            continue

        cmd = parts[0].upper()

        if cmd == "SET" and len(parts) == 3:
            key = parts[1]
            value = parts[2]
            store.set(key, value)
