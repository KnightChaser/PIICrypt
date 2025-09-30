# src/piicrypt/utils.py
from __future__ import annotations
from typing import Optional, Any
from pathlib import Path
import os
import sys
import json
import typer


def resolve_key(key: Optional[str]) -> str:
    """
    Resolve the AES key from the command line or environment variable.
    """
    k = key or os.getenv("PII_CRYPT_KEY")
    if not k:
        raise typer.BadParameter("Provide --key or set PII_CRYPT_KEY.")
    return k


def read_text(path: str | None) -> str:
    """
    Read text from a file or stdin.
    """
    if not path or path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def write_text(path: str | None, data: str) -> None:
    """
    Write text to a file or stdout.
    """
    if not path or path == "-":
        sys.stdout.write(data)
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data, encoding="utf-8")


def write_json(path: str, obj: Any) -> None:
    """
    Write JSON to a file.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
