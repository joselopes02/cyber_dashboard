# config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = 'caladinho'  
    SQLALCHEMY_DATABASE_URI = os.path.join('home','user1', 'processor','db', 'pandora.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False