FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /code

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential default-libmysqlclient-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Produção: espera o banco, aplica migrations (Alembic é a fonte da verdade do
# schema aqui — AUTO_CREATE_TABLES fica desligado), garante o admin bootstrap
# (idempotente, não recria se já existir) e só então sobe o servidor. Sem
# --reload e sem seed de dados demo. O docker-compose.yml de dev sobrescreve
# este CMD com sua própria receita (com --reload e seed completo).
CMD ["sh", "-c", "python -m scripts.wait_for_db && alembic upgrade head && python -m scripts.seed --if-empty --admin-only && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
