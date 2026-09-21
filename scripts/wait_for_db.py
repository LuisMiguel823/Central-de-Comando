"""Espera o MySQL aceitar conexões antes de subir a aplicação (uso no Docker)."""
from __future__ import annotations

import sys
import time

from sqlalchemy import text

from app.database import engine


def main(timeout: int = 60) -> int:
    from app.config import settings

    print(f"Conectando em {settings.db_host}:{settings.db_port}/{settings.db_name} como {settings.db_user!r}...")
    deadline = time.time() + timeout
    last_msg = ""
    while time.time() < deadline:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("Banco disponível.")
            return 0
        except Exception as exc:  # noqa: BLE001
            # Mensagem completa (não só o tipo) — é ela que diz se é rede,
            # senha errada ou banco inexistente. Só reimprime quando muda,
            # pra não poluir o log com a mesma linha repetida a cada 2s.
            msg = f"{exc.__class__.__name__}: {exc}"
            if msg != last_msg:
                print(f"Aguardando banco... {msg}")
                last_msg = msg
            time.sleep(2)
    print(f"Timeout esperando o banco. Último erro: {last_msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
