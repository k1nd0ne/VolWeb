import os

class Database:
    NAME = os.getenv('POSTGRES_DB')
    USER = os.getenv('POSTGRES_USER')
    PASSWORD = os.getenv('POSTGRES_PASSWORD')
    HOST = os.getenv('DATABASE_HOST')
    PORT = os.getenv('DATABASE_PORT')

class Secrets:
    SECRET_KEY = os.getenv('DJANGO_SECRET','DevSecretKey')
    BROKER_URL = os.getenv('BROKER_URL','amqp://admin:mypass@localhost:5672')

class Debug:
    DEBUG_MODE = os.getenv('DEBUG_MODE','True')
