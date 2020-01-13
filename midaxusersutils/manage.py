from midaxusers import create_app
from midaxusers.models import db
#from myapp.database import database_manager #sub manager for creating/dropping db
from flask_migrate import Migrate, MigrateCommand
import uuid
import base64
import os
from midaxusers.models import db, User, UserAttributes, UserLogin
import pkg_resources
from flask_migrate import upgrade
from sqlalchemy import create_engine

MIGRATIONS_PATH = pkg_resources.resource_filename('midaxusersutils', 'migrations/')

def create_db():
    os.environ['FLASK_APP'] = 'midaxusers'
    app = create_app()  

    # create the database and load test data
    with app.app_context():
        
        master_url = str(db.engine.url).replace('MidaxUsers', 'master')
        print(master_url)
        with create_engine(master_url, isolation_level='AUTOCOMMIT').connect() as connection:
            connection.execute('CREATE DATABASE MidaxUsers')     

        upgrade(directory = MIGRATIONS_PATH) 

def mupgrade():
    os.environ['FLASK_APP'] = 'midaxusers'
    app = create_app()  

    # create the database and load test data
    with app.app_context():
        upgrade(directory = MIGRATIONS_PATH) 

def create_test_user():
    app = create_app()

    with app.app_context():          
        test_user = User()
        test_user.domain = 'midax'
        test_user.email = 'test@midax.com'
        test_user.password = 'm1dax'
        test_user.role = 1     

        db.session.add(test_user)
        db.session.commit()

        #dbuser = UserLogin.get_user({'login_type': 'WEBSITE', 'login_key': 'test@midax.com'})

        loginws = UserLogin()
        loginws.login_type = 'WEBSITE'
        loginws.login_key= 'test@midax.com'
        loginws.password = 'm1dax'
        loginws.user = test_user
        logintm = UserLogin()
        logintm.login_type = 'TERMINAL'
        logintm.login_key= 'HONOLULU^1'
        logintm.password = '123'
        logintm.user = test_user

        db.session.add(loginws)
        db.session.add(logintm)

        newuser_attributes = UserAttributes()

        newuser_attributes.user = test_user
        newuser_attributes.name = 'test'
        newuser_attributes.value = 'attr'
        db.session.add(newuser_attributes)

        db.session.commit()     

if __name__ == "__main__":
    pass