from flask import Flask
from itsdangerous import TimedJSONWebSignatureSerializer as JWS
import pkg_resources

MIGRATIONS_PATH = pkg_resources.resource_filename('midaxusersutils', 'migrations/')



def create_app(test_config=None):
    app = Flask(__name__)

    from midaxusers.config import Config

    if (test_config is None):
        app.config.from_object(Config)
    else:
        app.config.from_object(test_config)
     #   from config_test import Config as TestConfig
      #  app.config.from_object(TestConfig)
   
    from midaxusers import models    
    
    models.db.init_app(app)
    models.migrate.init_app(app, models.db, directory = MIGRATIONS_PATH)

    from midaxusers.routes import api

    app.register_blueprint(api)
    app.jws = JWS(app.config['SECRET_KEY'], expires_in=3600)  

    return app

if __name__ == '__main__':
    pass