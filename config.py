# config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = 'caladinho'  
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'processor','db', 'pandora.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False