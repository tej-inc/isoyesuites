from os import environ,path,urandom
import os

SECRET_KEY= os.urandom(32)

SQLALCHEMY_DATABASE_URI= 'mysql+mysqlconnector://root@localhost/isoye'
SQLALCHEMY_TRACK_MODIFICATIONS=True
    