import os
import sys
from typing import Dict, Optional


DATA_FILE = "data.db"


class KeyValueStore:
    """
    An append-only log-based key-value store with in-memory indexing.
    Designed for persistence and high-speed command processing.
    """


    def __init__(self) -> None:
        self.index: Dict[str, str] = {}
        # Ensure the data file exists immediately
        if not os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    pass
            except OSError as e:
                raise RuntimeError(f"Could not create database file: {e}")
       
        self._replay_log()


    def _replay_log(self) -> None:
        """Reads the log file from start to finish to rebuild the index."""
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    if not clean_line:
                        continue
                   
                    # Using maxsplit=2 to ensure values with spaces are preserved
                    parts = clean_line.split(" ", 2)
                    if len(parts) == 3 and parts[0] == "SET":
                        self.index[parts[1]] = parts[2]
        except FileNotFoundError:
             def set(self, key: str, value: str) -> None:
        """
        Persists a SET operation to the log and updates the index.
        Uses fsync to guarantee disk persistence.
        """
        try:
            with open(DATA_FILE, "a", encoding="utf-8") as f:
                f.write(f"SET {key} {value}\n")
                f.flush()
                os.fsync(f.fileno())  # Critical for 'PersistenceAfterRestart'
           
            self.index[key] = value
        except OSError as e:
            raise RuntimeError(f"Failed to write to database: {e}")

            pass
        except OSError as e:
            raise RuntimeError(f"Failed to replay log: {e}")

