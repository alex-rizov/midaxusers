import os

import pytest
import json
import uuid
import secrets

import base64
from midaxusers import create_app
from midaxusers.models import db, User, UserAttributes, UserLogin

class Config_mssql(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(16)

    SQLALCHEMY_DATABASE_URI = 'mssql+pyodbc://(local)/MidaxUsersTest?driver=ODBC+Driver+17+for+SQL+Server'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class Config_oracle(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(16)

    SQLALCHEMY_DATABASE_URI = 'oracle://MIDAX_USERS_TEST:midax_users_test@192.168.102.80:1521/MIDAX12C'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


@pytest.fixture(params=[Config_mssql])
def app(request):
    """Create and configure a new app instance for each test."""  
    

    # create the app with common test config
    app = create_app(request.param)  



    # create the database and load test data
    with app.app_context():
        db.drop_all()        
        db.create_all()         
        test_user = User()
        test_user.domain = 'midax'      
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

        admin_user = User()
        admin_user.domain = '*'        
        admin_user.role = 1 
       
        
        db.session.add(admin_user)
        db.session.commit()

        loginadws = UserLogin()
        loginadws.login_type = 'WEBSITE'
        loginadws.login_key= 'admin@midax.com'
        loginadws.password = 'adm1n'
        loginadws.user = admin_user
        loginadtm = UserLogin()
        loginadtm.login_type = 'TERMINAL'
        loginadtm.login_key= 'ADMIN^1'
        loginadtm.password = '1111'
        loginadtm.user = admin_user

        db.session.add(loginadws)
        db.session.add(loginadtm)

        db.session.commit()           
        

    

    app.testing = True 

    yield app      


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()

valid_credentials_array = [ {'login_type': 'TERMINAL',
    'login_credentials':  base64.b64encode(b'HONOLULU^1:123').decode('utf-8'),
    'new_password' : '789',
    'new_login_credentials' : base64.b64encode(b'HONOLULU^1:789').decode('utf-8')},
 {  'login_type': 'WEBSITE',
    'login_credentials': base64.b64encode(b'test@midax.com:m1dax').decode('utf-8'),
    'new_password' : 'n3wp4sSw0rd',
    'new_login_credentials' : base64.b64encode(b'test@midax.com:n3wp4sSw0rd').decode('utf-8')}]

new_valid_credentials_array = [ {'login_type': 'TERMINAL',
'login_credentials':  base64.b64encode(b'HONOLULU^21:432').decode('utf-8'),    
    'new_password' : '987',
    'new_login_credentials' : base64.b64encode(b'HONOLULU^21:987').decode('utf-8'),
    'new_username' : 'HONOLULU^21'},
 {  'login_type': 'WEBSITE',
    'login_credentials': base64.b64encode(b'test2@midax.com:m2dax').decode('utf-8'),    
    'new_password' : 'n3wp4sSw1rd',
    'new_login_credentials' : base64.b64encode(b'test2@midax.com:n3wp4sSw1rd').decode('utf-8'),
    'new_username' : 'test2@midax.com'}]

admin_credentials_array = [ {'login_type': 'TERMINAL',
    'login_credentials':  base64.b64encode(b'ADMIN^1:1111').decode('utf-8')},
 {  'login_type': 'WEBSITE',
    'login_credentials': base64.b64encode(b'admin@midax.com:adm1n').decode('utf-8')}]

@pytest.fixture(params = valid_credentials_array)
def valid_credentials(request):
    return request.param

@pytest.fixture(params = new_valid_credentials_array)
def new_valid_credentials(request):
    return request.param

@pytest.fixture(params = admin_credentials_array)
def admin_credentials(request):
    return request.param

#@pytest.fixture
#def new_valid_credentials():
#    return base64.b64encode(b'midax^vendors^attendants^test2:P@rol@123$').decode('utf-8')

@pytest.fixture
def malformed_credentials():
    return base64.b64encode(b'mmima:k8as(das*@321DWWA21eesadz').decode('utf-8')


@pytest.mark.parametrize('path', (
    '/api/v1.0/users/midax^invalid^domain^test/attributes',
    '/dmaodmasopmAWSDAZX',
))
def test_not_found(client, valid_credentials, path):    
    response = client.get(path, headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 404


def test_auth_required(client):
    response = client.get('/api/v1.0/user/attributes')
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Basic realm="Authentication Required"'
    assert 'Basic' in response.headers['WWW-Authenticate']


@pytest.mark.parametrize('path', (
    '/api/v1.0/user/attributes',
    '/api/v1.0/users/midax^test/attributes',
))
def test_malformed_auth(client, malformed_credentials, path):    
    response = client.get(path, headers={'Authorization': 'Basic ' + malformed_credentials})
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Basic realm="Authentication Required"'
    assert 'Basic' in response.headers['WWW-Authenticate']

    response = client.get(path, headers={'Authorization': 'Basic ' + malformed_credentials, 'Login-Type': 'WEBSITE'})
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Basic realm="Authentication Required"'
    assert 'Basic' in response.headers['WWW-Authenticate']

    response = client.get(path, headers={'Authorization': 'Basic ' + malformed_credentials, 'Login-Type': 'TERMINAL'})
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Basic realm="Authentication Required"'
    assert 'Basic' in response.headers['WWW-Authenticate']

    response = client.get(path, headers={'Authorization': 'Basic ' + malformed_credentials, 'Login-Type': 'IJDAIOSJas#@%'})
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Basic realm="Authentication Required"'
    assert 'Basic' in response.headers['WWW-Authenticate']

    response = client.get(path, headers={'Authorization': 'Basic ' + malformed_credentials, 'Login-Type': ''})
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Basic realm="Authentication Required"'
    assert 'Basic' in response.headers['WWW-Authenticate']

@pytest.mark.parametrize('path', (
    '/api/v1.0/user',    
))
def test_attributes(client, valid_credentials, path): 
    response = client.get(path, headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200
    
    json_data = response.get_json()
    print(json_data)
    print(json_data['user_attributes'])
    print(type(json_data['user_attributes']))
    assert json_data['user_attributes']['test'] == 'attr'

def test_user_creation_deletion(client, valid_credentials, new_valid_credentials):
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200    

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test3@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 409

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^29', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 409

    user = {'domain':'mid^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test3@midax.com', 'password':'m3dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^31', 'password':'433'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 403
    
    response = client.post('/api/v1.0/users/'+ str(uuid.uuid4()) + '/deactivate', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 404

    response = client.post('/api/v1.0/users/'+ new_uuid_str + '/deactivate', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401    

def test_user_creation_deletion_via_update(client, valid_credentials, new_valid_credentials):
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200    

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test3@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 409

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^29', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 409

    user = {'domain':'mid^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test3@midax.com', 'password':'m3dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^31', 'password':'433'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 403
    
    user = {'active':False, 'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.put('/api/v1.0/users/'+ new_uuid_str, data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'active':True, 'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.put('/api/v1.0/users/'+ new_uuid_str, data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200


def test_get_domain_users(client, valid_credentials, admin_credentials):
    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    
    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200

    response = client.get('/api/v1.0/domains/midax/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200    

    response = client.get('/api/v1.0/domains/midax^vendors/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200
  
    response = client.get('/api/v1.0/domains/midfx/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 403

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + admin_credentials['login_credentials'], 'Login-Type': admin_credentials['login_type']})
    assert response.status_code == 200

    response = client.get('/api/v1.0/domains/midax/users', headers={'Authorization': 'Basic ' + admin_credentials['login_credentials'], 'Login-Type': admin_credentials['login_type']})
    assert response.status_code == 200    

    response = client.get('/api/v1.0/domains/midax^vendors/users', headers={'Authorization': 'Basic ' + admin_credentials['login_credentials'], 'Login-Type': admin_credentials['login_type']})
    assert response.status_code == 200
  
    response = client.get('/api/v1.0/domains/midfx/users', headers={'Authorization': 'Basic ' + admin_credentials['login_credentials'], 'Login-Type': admin_credentials['login_type']})
    assert response.status_code == 200

@pytest.mark.parametrize('path', (
    '/api/v1.0/user',  
))
def test_user_creation_pw_update(client, valid_credentials, path):
    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax', 'force_password_change':True}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + base64.b64encode(b'test2@midax.com:m2dax').decode('utf-8'), 'Login-Type': 'WEBSITE'})
    assert response.status_code == 423

    password = {'password':'m3dax'}
    response = client.post('/api/v1.0/user/password', data = json.dumps(password), headers={'Authorization': 'Basic ' + base64.b64encode(b'test2@midax.com:m2dax').decode('utf-8'), 'Login-Type': 'WEBSITE'}, content_type='application/json')    
    assert response.status_code == 200

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + base64.b64encode(b'test2@midax.com:m2dax').decode('utf-8'), 'Login-Type': 'WEBSITE'})
    assert response.status_code == 401

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + base64.b64encode(b'test2@midax.com:m3dax').decode('utf-8'), 'Login-Type': 'WEBSITE'})
    assert response.status_code == 200

@pytest.mark.parametrize('path', (
    '/api/v1.0/user',  
))
def test_user_creation_pw_update_admin(client, admin_credentials, path):
    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax', 'force_password_change':True}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + admin_credentials['login_credentials'], 'Login-Type': admin_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + base64.b64encode(b'test2@midax.com:m2dax').decode('utf-8'), 'Login-Type': 'WEBSITE'})
    assert response.status_code == 423

    password = {'password':'m3dax'}
    response = client.post('/api/v1.0/user/password', data = json.dumps(password), headers={'Authorization': 'Basic ' + base64.b64encode(b'test2@midax.com:m2dax').decode('utf-8'), 'Login-Type': 'WEBSITE'}, content_type='application/json')    
    assert response.status_code == 200

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + base64.b64encode(b'test2@midax.com:m2dax').decode('utf-8'), 'Login-Type': 'WEBSITE'})
    assert response.status_code == 401

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + base64.b64encode(b'test2@midax.com:m3dax').decode('utf-8'), 'Login-Type': 'WEBSITE'})
    assert response.status_code == 200

@pytest.mark.parametrize('path', (
    '/api/v1.0/user',  
))
def test_logins_update(client, valid_credentials, new_valid_credentials, path): 
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401 

    credentials = {new_valid_credentials['login_type']: { 'login_key' : new_valid_credentials['new_username'], 'password': new_valid_credentials['new_password']}}
    response = client.post('/api/v1.0/users/'+ new_uuid_str + '/logins', data = json.dumps(credentials), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200 

    credentials = {new_valid_credentials['login_type']: { 'login_key' : 'changetonewkey@new.key', 'password': 'novaparola'}}
    response = client.post('/api/v1.0/users/'+ new_uuid_str + '/logins', data = json.dumps(credentials), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + base64.b64encode(b'changetonewkey@new.key:novaparola').decode('utf-8'), 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200



@pytest.mark.parametrize('path', (
    '/api/v1.0/user',  
))
def test_user_update(client, valid_credentials, new_valid_credentials, path): 
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401 

    
    user = {'domain':'midax^vendors^newdomain', 'role':5}
    response = client.put('/api/v1.0/users/'+ new_uuid_str, data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200
    assert response.get_json()['domain'] == 'midax^vendors^newdomain'
    assert response.get_json()['role'] ==  '5'

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200
    assert response.get_json()['domain'] == 'midax^vendors^newdomain'
    assert response.get_json()['role'] ==  '5'    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401 

    credentials = {new_valid_credentials['login_type']: { 'login_key' : new_valid_credentials['new_username'], 'password': new_valid_credentials['new_password']}}
    user = {'domain':'midax^vendors^newdomain2', 'role':6, 'logins': credentials}
    response = client.put('/api/v1.0/users/'+ new_uuid_str, data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200
    assert response.get_json()['domain'] == 'midax^vendors^newdomain2'
    assert response.get_json()['role'] ==  '6'

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200 
    assert response.get_json()['domain'] == 'midax^vendors^newdomain2'
    assert response.get_json()['role'] ==  '6'


    credentials = {new_valid_credentials['login_type']: { 'login_key' : 'changetonewkey@new.key', 'password': 'novaparola'}}    
    user = {'logins': credentials}
    response = client.put('/api/v1.0/users/'+ new_uuid_str, data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200
    assert response.get_json()['domain'] == 'midax^vendors^newdomain2'
    assert response.get_json()['role'] ==  '6'

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + base64.b64encode(b'changetonewkey@new.key:novaparola').decode('utf-8'), 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200
    assert response.get_json()['domain'] == 'midax^vendors^newdomain2'
    assert response.get_json()['role'] ==  '6'
    


def test_user_creation_none_rights(client, valid_credentials, new_valid_credentials):
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4,  'user_manage_rights':'none', 'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 403

    user = {'domain':'midax^vendors^attendants^subdomain', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 403   

def test_user_creation_subdomain_rights(client, valid_credentials, new_valid_credentials):
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4,  'user_manage_rights':'subdomain', 'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 403  

    user = {'domain':'midax^vendors^attendants^subdomain', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201 

def test_user_creation_domain_rights(client, valid_credentials, new_valid_credentials):
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4,  'user_manage_rights':'domain', 'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201 

    user = {'domain':'midax^vendors^attendants^subdomain', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test6@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^26', 'password':'475'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201 


@pytest.mark.parametrize('rights', (
    'none',  
    'subdomain'
))
def test_user_update_no_rights(client, valid_credentials, new_valid_credentials, rights): 
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4, 'user_manage_rights':rights, 'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401 

    
    user = {'domain':'midax^vendors^newdomain', 'role':5}
    response = client.put('/api/v1.0/users/'+ new_uuid_str, data = json.dumps(user), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 403   

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200
    assert response.get_json()['domain'] == 'midax^vendors^attendants'
    assert response.get_json()['role'] ==  '4'    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401 

    credentials = {new_valid_credentials['login_type']: { 'login_key' : new_valid_credentials['new_username'], 'password': new_valid_credentials['new_password']}}
    user = {'logins': credentials}
    response = client.put('/api/v1.0/users/'+ new_uuid_str, data = json.dumps(user), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 403    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401    


 
@pytest.mark.parametrize('rights', (
    'none',  
    'subdomain'
))
def test_logins_update_no_rights(client, valid_credentials, new_valid_credentials, rights): 
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4, 'user_manage_rights':rights, 'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401 

    credentials = {new_valid_credentials['login_type']: { 'login_key' : new_valid_credentials['new_username'], 'password': new_valid_credentials['new_password']}}
    response = client.post('/api/v1.0/users/'+ new_uuid_str + '/logins', data = json.dumps(credentials), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200 

    credentials = {new_valid_credentials['login_type']: { 'login_key' : 'changetonewkey@new.key', 'password': 'novaparola'}}
    response = client.post('/api/v1.0/users/'+ new_uuid_str + '/logins', data = json.dumps(credentials), headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['new_login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + base64.b64encode(b'changetonewkey@new.key:novaparola').decode('utf-8'), 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200   


def test_user_creation_deletion_token(client, valid_credentials, new_valid_credentials):
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401    

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    assert response.headers['Users-Access-Token'] is not None
    token = response.headers['Users-Access-Token']
    new_uuid_str = response.get_json()['uuid']
    assert new_uuid_str is not None

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Bearer ' + token}, content_type='application/json')    
    assert response.status_code == 201
    assert response.headers['Users-Access-Token'] is not None
    token = response.headers['Users-Access-Token']

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200  
    assert response.headers['Users-Access-Token'] is not None
    new_user_token = response.headers['Users-Access-Token']

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Bearer ' + new_user_token})
    assert response.status_code == 200  

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Bearer ' + new_user_token + 'bjRmGs'})
    assert response.status_code == 401  

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test3@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Bearer ' + token}, content_type='application/json')    
    assert response.status_code == 409
    assert response.headers['Users-Access-Token'] is not None
    token = response.headers['Users-Access-Token']

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^29', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Bearer ' + token}, content_type='application/json')    
    assert response.status_code == 409
    assert response.headers['Users-Access-Token'] is not None
    token = response.headers['Users-Access-Token']

    user = {'domain':'mid^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test3@midax.com', 'password':'m3dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^31', 'password':'433'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Bearer ' + token}, content_type='application/json')    
    assert response.status_code == 403
    assert response.headers['Users-Access-Token'] is not None
    token = response.headers['Users-Access-Token']
    
    response = client.post('/api/v1.0/users/'+ str(uuid.uuid4()) + '/deactivate', headers={'Authorization': 'Bearer ' + token})
    assert response.status_code == 404
    assert response.headers['Users-Access-Token'] is not None
    token = response.headers['Users-Access-Token']

    response = client.post('/api/v1.0/users/'+ new_uuid_str + '/deactivate', headers={'Authorization': 'Bearer ' + token})
    assert response.status_code == 200
    assert response.headers['Users-Access-Token'] is not None
    token = response.headers['Users-Access-Token']

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401    

    response = client.get('/api/v1.0/user', headers={'Authorization': 'Bearer ' + new_user_token})
    assert response.status_code == 401

def test_get_migrate_domain_users(client, valid_credentials, admin_credentials):
    user = {'domain':'midax^vendor1^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    
    user = {'domain':'midax^vendor1^attendants', 'role':4, 'first_name': 'Adam', 'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201

    response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200

    response = client.get('/api/v1.0/domains/midax/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200    

    response = client.get('/api/v1.0/domains/midax^vendor1/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200
    assert len(response.get_json()) == 2  

    response = client.get('/api/v1.0/domains/midax^vendor2/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200
    assert len(response.get_json()) == 0    

    new_domain = {'new-domain': 'midax^vendor2'}
    response = client.put('/api/v1.0/domains/midax^vendor1/migrate', data = json.dumps(new_domain), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 200
    for e in response.get_json():
        assert 'midax^vendor2' in e['domain']
        
    
    response = client.get('/api/v1.0/domains/midax^vendor1/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200
    assert len(response.get_json()) == 0  

    response = client.get('/api/v1.0/domains/midax^vendor2/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
    assert response.status_code == 200
    assert len(response.get_json()) == 2  
    for e in response.get_json():
        assert 'midax^vendor2' in e['domain']        
        assert '@midax.com' in e['logins']['WEBSITE']['login_key']  

    new_domain = {'new-dmain': 'midax^vendor2'}
    response = client.put('/api/v1.0/domains/midax^vendor1/migrate', data = json.dumps(new_domain), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
    assert response.status_code == 500

def test_deactivate_domain_users(client, valid_credentials, admin_credentials):
        user = {'domain':'midax^vendor1^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
        response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
        assert response.status_code == 201
        
        user = {'domain':'midax^vendor1^attendants', 'role':4, 'first_name': 'Adam', 'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
        response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
        assert response.status_code == 201
    
        response = client.get('/api/v1.0/domain/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
        assert response.status_code == 200
    
        response = client.get('/api/v1.0/domains/midax/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
        assert response.status_code == 200    
    
        response = client.get('/api/v1.0/domains/midax^vendor1/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
        assert response.status_code == 200
        assert len(response.get_json()) == 2  
            
        response = client.put('/api/v1.0/domains/midax^vendor1/deactivate', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')
        assert response.status_code == 200
        assert len(response.get_json()) == 2  
        
        response = client.get('/api/v1.0/domains/midax^vendor1/users', headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']})
        assert response.status_code == 200
        assert len(response.get_json()) == 0      
        

def test_user_list(client, valid_credentials, new_valid_credentials):
    response = client.get('/api/v1.0/user', headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 401

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test2@midax.com', 'password':'m2dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^21', 'password':'432'}}}
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str1 = response.get_json()['uuid']
    assert new_uuid_str1 is not None

    user = {'domain':'midax^vendors^attendants', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test5@midax.com', 'password':'m5dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^22', 'password':'435'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str2 = response.get_json()['uuid']
    assert new_uuid_str2 is not None    

    user = {'domain':'midax^vendors2^attendants4', 'role':4,  'logins': {'WEBSITE' : {'login_key': 'test6@midax.com', 'password':'m6dax'}, 'TERMINAL' : {'login_key': 'HONOLULU^26', 'password':'436'}}}    
    response = client.post('/api/v1.0/users/', data = json.dumps(user), headers={'Authorization': 'Basic ' + valid_credentials['login_credentials'], 'Login-Type': valid_credentials['login_type']}, content_type='application/json')    
    assert response.status_code == 201
    new_uuid_str3 = response.get_json()['uuid']
    assert new_uuid_str3 is not None    

    response = client.get('/api/v1.0/users?uuids={},{},{}'.format(new_uuid_str1, new_uuid_str2, new_uuid_str3), headers={'Authorization': 'Basic ' + new_valid_credentials['login_credentials'], 'Login-Type': new_valid_credentials['login_type']})
    assert response.status_code == 200    
    for e in response.get_json():
        assert new_uuid_str1 in e['uuid'] or new_uuid_str2 in e['uuid'] or new_uuid_str3 in e['uuid']

   