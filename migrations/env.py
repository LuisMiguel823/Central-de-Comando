from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from app.config import settings
from app.database import Base
import app.models  # noqa: F401  (registra todas as tabelas no metadata)

config = context.config
# NÃO usar config.set_main_option("sqlalchemy.url", ...) aqui: o ConfigParser
# do Alembic trata "%" como caractere de interpolação, e uma senha com "!"/"["
# vira "%21"/"%5B" na URL (quote_plus) — o set_main_option quebra com
# "ValueError: invalid interpolation syntax" nesse caso. run_migrations_online
# abaixo cria a engine direto de settings.database_url, sem passar pelo
# ConfigParser, então nunca esbarra nisso.

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(settings.database_url, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
