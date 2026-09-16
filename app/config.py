from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuracion del servicio. Todo se puede sobreescribir por variables de entorno."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    service_name: str = "identity-service"
    api_port: int = 8001

    database_url: str = (
        "postgresql+psycopg2://banklite:banklite@identity-db:5432/identity_db"
    )

    rabbitmq_url: str = "amqp://banklite:banklite@rabbitmq:5672/"
    events_exchange: str = "banklite.events"
    enable_events: bool = True


settings = Settings()
