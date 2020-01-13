import os
import secrets

class Config(object):
    SECRET_KEY = os.environ.get('MUSERS_SECRET_KEY') or secrets.token_urlsafe(16)

    SQLALCHEMY_DATABASE_URI = os.environ.get('MUSERS_DATABASE_URL') or \
    'mssql+pyodbc://(local)/MidaxUsers?driver=ODBC+Driver+17+for+SQL+Server'
    #'oracle://MIDAX_USERS:midax_users@192.168.102.80:1521/MIDAX12C'
    #'mssql+pyodbc://(local)/MidaxUsers?driver=ODBC+Driver+17+for+SQL+Server'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False