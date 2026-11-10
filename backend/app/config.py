

from pydantic_settings import BaseSettings, SettingsConfigDict
from urllib.parse import quote_plus


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )

    mongo_root_username: str = "ctiadmin"
    mongo_root_password: str = "ChangeMongoPassword123!"
    mongo_database: str = "cti_platform"

    @property
    def mongo_uri(self):
        username = quote_plus(self.mongo_root_username)
        password = quote_plus(self.mongo_root_password)

        return (
            f"mongodb://{username}:{password}"
            f"@mongodb:27017/?authSource=admin"
        )

    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: str = "password"

    redis_url: str = "redis://redis:6379/0"

    jwt_secret: str = "development-only-change-me-please-32-chars"
    jwt_expire_minutes: int = 60

    admin_email: str = "admin@example.com"
    admin_password: str = "ChangeThisAdminPassword123!"

    cors_origins: str = "http://localhost:5173"

    nvd_api_key: str = ""
    otx_api_key: str = ""
    max_upload_mb: int = 5


settings = Settings()
