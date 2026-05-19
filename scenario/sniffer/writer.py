from __future__ import annotations

import csv
import json
from pathlib import Path


class CsvAppender:
    def __init__(self, path: str | None, columns: list[str]):
        self.path = Path(path) if path else None
        self.columns = columns

    def is_enabled(self) -> bool:
        return self.path is not None

    def append(self, row: dict) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        write_header = not self.path.exists() or self.path.stat().st_size == 0
        with self.path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.columns, extrasaction="ignore")
            if write_header:
                writer.writeheader()
            writer.writerow({column: row.get(column) for column in self.columns})


class JsonlAppender:
    def __init__(self, path: str | None):
        self.path = Path(path) if path else None

    def is_enabled(self) -> bool:
        return self.path is not None

    def append(self, row: dict) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
