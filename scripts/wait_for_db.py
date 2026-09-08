"""Espera o MySQL aceitar conexões antes de subir a aplicação (uso no Docker)."""
from __future__ import annotations

import sys
import time

from sqlalchemy import text

from app.database import engine


def main(timeout: int = 60) -> int:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("Banco disponível.")
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"Aguardando banco... ({exc.__class__.__name__})")
            time.sleep(2)
    print("Timeout esperando o banco.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
