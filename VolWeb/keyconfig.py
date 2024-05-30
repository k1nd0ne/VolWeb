import os


class Database:
    NAME = os.getenv("POSTGRES_DB", None)
    USER = os.getenv("POSTGRES_USER", None)
    PASSWORD = os.getenv("POSTGRES_PASSWORD", None)
    HOST = os.getenv("DATABASE_HOST", None)
    PORT = os.getenv("DATABASE_PORT", None)


class Secrets:
    SECRET_KEY = os.getenv("DJANGO_SECRET", None)
    BROKER_HOST = os.getenv("BROKER_HOST", "127.0.0.1")
    BROKER_PORT = os.getenv("BROKER_PORT", "6379")
    WEBSOCKET_URL = os.getenv("WEBSOCKET_URL", None)
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", None)
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", None)
    AWS_ENDPOINT_URL = os.getenv("AWS_ENDPOINT_URL", None)
    AWS_ENDPOINT_HOST = os.getenv("AWS_ENDPOINT_HOST", None)
    AWS_REGION = os.getenv("AWS_REGION", None)
