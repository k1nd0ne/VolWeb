import os

class Database:
    NAME = os.getenv('POSTGRES_DB','volweb')
    USER = os.getenv('POSTGRES_USER','volweb')
    PASSWORD = os.getenv('POSTGRES_PASSWORD','volweb')
    HOST = os.getenv('DATABASE_HOST',"localhost")
    PORT = os.getenv('DATABASE_PORT',5432)

class Secrets:
    SECRET_KEY = os.getenv('DJANGO_SECRET','DevSecretKey')
    BROKER_URL = os.getenv('BROKER_URL','amqp://admin:mypass@localhost:5672')
    VT_API_KEY = os.getenv('VT_API_KEY',"DEV_API_KEY")
    AWS_ACCESS_KEY_ID=os.getenv('AWS_ACCESS_KEY_ID',"user")
    AWS_SECRET_ACCESS_KEY=os.getenv('AWS_SECRET_ACCESS_KEY',"password")
    AWS_ENDPOINT_URL=os.getenv('AWS_ENDPOINT_URL',"http://127.0.0.1:9000")


class Debug:
    DEBUG_MODE = os.getenv('DEBUG_MODE','True')