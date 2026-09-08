from __future__ import annotations

from functools import lru_cache
from urllib.parse import quote_plus

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- App ---
    app_name: str = "Central de Comando"
    app_env: str = "dev"
    debug: bool = True
    base_url: str = "http://localhost:8000"
    secret_key: str = "dev-secret-change-me"
    session_max_age: int = 43_200

    # --- Banco ---
    db_host: str = "127.0.0.1"
    db_port: int = 3306
    db_name: str = "central_comando"
    db_user: str = "central"
    db_password: str = "central"
    db_root_password: str = "root"
    auto_create_tables: bool = True
    # Sobrescreve a URL do banco por completo (usado em testes: sqlite).
    database_url_override: str | None = None

    # --- JWT / OIDC provider ---
    jwt_private_key_path: str = "./keys/jwt_private.pem"
    jwt_public_key_path: str = "./keys/jwt_public.pem"
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 2_592_000
    auth_code_ttl: int = 120

    # --- gov.br ---
    govbr_enabled: bool = False
    govbr_issuer: str = "https://sso.staging.acesso.gov.br"
    govbr_client_id: str = ""
    govbr_client_secret: str = ""
    govbr_redirect_uri: str = "http://localhost:8000/auth/govbr/callback"
    govbr_scopes: str = "openid email profile"
    govbr_auto_provision: bool = True
    govbr_provision_active: bool = False

    # --- Login Único municipal (Neomind Fusion WSAuth: WSAuthInit/WSAuthVerify) ---
    loginunico_enabled: bool = False
    loginunico_base_url: str = "https://loginunico.cabofrio.rj.gov.br/loginunico"
    loginunico_sys: str = "SLU"
    loginunico_callback_url: str = "http://localhost:8000/auth/loginunico/callback"
    loginunico_auto_provision: bool = True
    loginunico_provision_active: bool = False
    loginunico_min_level: int = 1  # nível mínimo da conta (1, 2 ou 3)
    loginunico_verify_ssl: bool = True
    loginunico_timeout: int = 15

    # --- SSO Microsoft (Entra ID / Azure AD) — Authorization Code, sem lib ---
    microsoft_client_id: str = ""
    microsoft_client_secret: str = ""
    microsoft_tenant_id: str = ""
    # DEVE ser fixo e bater EXATO (esquema incluso) com o App Registration
    microsoft_redirect_uri: str = "http://localhost:8000/auth/microsoft/callback"
    microsoft_scopes: str = "openid profile email User.Read"
    microsoft_timeout: int = 15

    # --- Bootstrap ---
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_email: str = "admin@local"
    bootstrap_admin_password: str = "admin123"

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            return self.database_url_override
        return (
            f"mysql+pymysql://{self.db_user}:{quote_plus(self.db_password)}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}?charset=utf8mb4"
        )

    @property
    def govbr_metadata_url(self) -> str:
        return f"{self.govbr_issuer.rstrip('/')}/.well-known/openid-configuration"

    @property
    def issuer(self) -> str:
        return self.base_url.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
