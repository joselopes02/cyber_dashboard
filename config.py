# config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = 'caladinho'  
    SQLALCHEMY_DATABASE_URI = 'sqlite:////home/user1/processor/db/pandora.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
        # Celery configuration
    CELERY_BROKER_URL = 'redis://localhost:8889/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:8889/0'