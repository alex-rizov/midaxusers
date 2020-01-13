from .models import db, User, UserAttributes, UserLogin, PasswordNeedsResetError, ManagerTypesEnum, domain_separator
from .domains import domain_cleanup, verify_domain_rights, can_user_see_user, verify_user_manage_rights, domain_filter
from flask import Flask, jsonify, make_response, abort, request, current_app, Blueprint, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from sqlalchemy import types, and_, or_
from sqlalchemy.orm.session import Session
from collections import namedtuple
import sys

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()
auth = MultiAuth(basic_auth, token_auth)
api = Blueprint('api', __name__, url_prefix='/api/v1.0')

@api.route('/', methods=['GET'])
@api.route('/index', methods=['GET'])
@api.route('/user/attributes', methods=['GET'])
@api.route('/user', methods=['GET'])
@auth.login_required
def index():
    return get_user(uuid = request.loggeduser.uuid)

@api.route('/users/<string:uuid>', methods=['GET'])
@api.route('/users/<string:uuid>/attributes', methods=['GET'])
@auth.login_required
def get_user(uuid):    
    try:
        user = User.search(uuid)
    except:
        abort(404)
    
    return jsonify(user.serialize()), 200

@api.route('/domain/users/inactive', methods=['GET'])
@auth.login_required
def get_current_domain_users_inactive():
    return get_domain_users_inactive(request.loggeduser.domain)

@api.route('/domains/<string:domain>/users/inactive', methods=['GET'])
@auth.login_required
def get_domain_users_inactive(domain):
    return get_domain_users_int(domain, active = False)

@api.route('/domain/users', methods=['GET'])
@auth.login_required
def get_current_domain_users():
    return get_domain_users(request.loggeduser.domain)

@api.route('/domains/<string:domain>/users', methods=['GET'])
@auth.login_required
def get_domain_users(domain):
    return get_domain_users_int(domain, active = True)


@api.route('/domains/<string:domain>/users', methods=['GET'])
@auth.login_required
def get_domain_users_int(domain, active = True):
    loggeduser = request.loggeduser      

    verify_domain_rights(loggeduser, targetdomain = domain)    

    current_domain = domain_cleanup(domain)
    users = User.query.filter(domain_filter(current_domain)).filter_by(active = active)

    if users is not None:
        return jsonify([e.serialize() for e in users])

    abort(404)

@api.route('/users', methods=['GET'])
@auth.login_required
def get_users_list():    
    loggeduser = request.loggeduser          
    users = User.query.filter(User.uuid.in_(request.args.get('uuids').split(',')))

    if users is not None:
        return jsonify([e.serialize() for e in users if can_user_see_user(loggeduser, e)])

    abort(404)

@api.route('/domains/<string:domain>/migrate', methods=['PUT'])
@auth.login_required
def migrate_domain_users(domain):
    loggeduser = request.loggeduser      

    verify_domain_rights(loggeduser, targetdomain = domain)    
    verify_domain_rights(loggeduser, targetdomain = request.json['new-domain'])    

    current_domain = domain_cleanup(domain)
    new_domain = domain_cleanup(request.json['new-domain'])

    try:
        for user in User.query.filter(domain_filter(current_domain)).filter_by(active = True).all():
            new_user = user.migrate()
            new_user.domain = new_user.domain.replace(current_domain, new_domain)
        
        db.session.commit()
    except:
        abort(409)

    return get_domain_users_int(request.json['new-domain'], active = True)

    
@api.route('/domains/<string:domain>/deactivate', methods=['PUT'])
@auth.login_required
def deactivate_domain_users(domain):
    loggeduser = request.loggeduser      

    verify_domain_rights(loggeduser, targetdomain = domain)           

    current_domain = domain_cleanup(domain)    

    try:
        for user in User.query.filter(domain_filter(current_domain)).filter_by(active = True).all():
            user.active = False
        
        db.session.commit()
    except:
        abort(409)

    return get_domain_users_int(current_domain, active = False)
    

@api.route('/users/', methods=['POST'])
@auth.login_required
def create_user():
    loggeduser = request.loggeduser
    
    verify_user_manage_rights(loggeduser, targetdomain = request.json['domain'])    

    try:
        newuser = User(namedtuple("User", request.json.keys())(*request.json.values()))
    except Exception as e:        
        print(str(e), file=sys.stderr)
        abort(400)

    try:
        db.session.add(newuser)
        db.session.commit()
    except Exception as e:        
        print(str(e), file=sys.stderr)
        return jsonify({'error': "Duplicate user"}), 409

    return jsonify(newuser.serialize()), 201

@api.route('/users/<string:uuid>', methods=['PUT'])
@auth.login_required
def update_user(uuid):    
    try:
        targetuser = User.search(uuid)
    except:
        abort(404)

    verify_user_manage_rights(request.loggeduser, targetuser = targetuser)  

    #this allows domain changing as well so we need to check the new domain too if present
    try:
        verify_user_manage_rights(request.loggeduser, targetdomain = request.json['domain'])  
    except KeyError:
        pass 

    try:
        targetuser.update_from_named_tuple(namedtuple("User", request.json.keys())(*request.json.values()))
        db.session.commit()
    except Exception as e:
        print(str(e), file=sys.stderr)
        return jsonify({'error': "Cannot update user"}), 400
    
    return jsonify(targetuser.serialize()), 200


@api.route('/users/<string:uuid>/logins', methods=['POST'])
@auth.login_required
def change_user_logins(uuid):
    try:
        loggeduser = request.loggeduser
        targetuser = User.search(uuid)
    except Exception as e:
        print(str(e), file=sys.stderr)
        abort(404)

    verify_user_manage_rights(loggeduser, targetuser = targetuser, self_update_force_allowed = True)    

    
    try:                   
        for key, value in request.json.items():
            value['login_type'] = key
            if value['login_key'] is None or len(value['login_key']) == 0:
                targetuser.logins.pop(key, None)
            else:
                a_login = targetuser.logins.get(key, None)
                if a_login is None:
                    a_login = UserLogin()
                    
                a_login.update_from_dict(value)
                targetuser.logins[key] = a_login
        
        db.session.commit()
    except Exception as e:
        print(str(e), file=sys.stderr)
        abort(400)

    return jsonify({'result' : 'Logins Updated'}), 200


@api.route('/user/password', methods=['POST'])
def reset_password():
    try:                   
        verify_identity_internal(username = request.authorization.username, password = request.authorization.password)
    except PasswordNeedsResetError as exc:
        request.loggeduser = exc.user
    except Exception as e:
        print(str(e), file=sys.stderr)
        abort(401)    

    try:
        request.loggeduser.logins[request.login_type].password = request.json['password']
        request.loggeduser.logins[request.login_type].force_password_change = False    
        db.session.commit()
    except:
        abort(400)

    return jsonify({'result' : 'Password Reset'}), 200


@api.route('/users/<string:uuid>/deactivate', methods=['POST'])
@auth.login_required
def deactivate_user(uuid):
    try:
        targetuser = User.search(uuid)
    except Exception as e:
        print(str(e), file=sys.stderr)
        abort(404)

    verify_user_manage_rights(request.loggeduser, targetuser = targetuser, self_update_force_allowed = True)
    
    try:  
        targetuser.active = False          
        db.session.commit()
    except Exception as e:
        print(str(e), file=sys.stderr)
        return jsonify({'error': "Cannot deactivate user"}), 409

    return jsonify({'status': "SUCCESS"}), 200





#need to be the last routes
@api.route("/<path:missing>", methods=['PUT', 'PATCH', 'DELETE'])
@auth.login_required
def method_not_allowed_on_unknown_path(missing):
    abort(405)

@api.route("/<path:missing>")
@auth.login_required
def path_did_not_match(missing):
    abort(404)


@basic_auth.verify_password
def verify_pw(username, password):
    try:
        return verify_identity_internal(username = username, password = password)
    except PasswordNeedsResetError:
        abort(423)
    except Exception as e:   
        print(str(e), file=sys.stderr)
        return False

@token_auth.verify_token
def verify_token(token):
    try:
        return verify_identity_internal(token = token, check_password = False)
    except PasswordNeedsResetError:
        abort(423)
    except Exception as e:   
        print(str(e), file=sys.stderr)
        return False

def verify_identity_internal(username= None, password = None, token = None, check_password = True):
    if (username is None or password is None) and token is None:
        return False
    
    if username is not None and password is not None:
        try:
            request.login_type = request.headers['Login-Type']
        except KeyError:
            request.login_type = 'WEBSITE'
    else:        
        try:
            data = current_app.jws.loads(token)
            username = data['login_key']
            request.login_type = data['login_type']            
        except:
            return False
    
    request.loggeduser = UserLogin.get_user({'login_type': request.login_type, 'login_key': username, 'password': password}, check_password=check_password)
    g.access_token = current_app.jws.dumps({'login_key': username, 'login_type': request.login_type})
    
    return True

@api.after_request
def add_header(response):
    try:
        response.headers['Users-Access-Token'] = g.access_token
    except:
        pass
    return response

@api.errorhandler(405)
def not_allowed(error):
    return make_response(jsonify({'error': 'Method not allowed'}), 405)

@api.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

@api.errorhandler(403)
def forbidden(error):
    return make_response(jsonify({'error': 'Access forbidden for user'}), 403)

@api.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Bad request'}), 400)

@api.errorhandler(423)
def locked(error):
    return make_response(jsonify({'error': 'User has been locked, change password.'}), 423)

@api.errorhandler(401)
def unauthorized(error):
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

@api.errorhandler(Exception)
def all_exception_handler(error):
    print(str(error), file=sys.stderr)
    return make_response(jsonify({'error': 'System or Format error'}), 500)

@basic_auth.error_handler
def unauthorized_auth_basic():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

@token_auth.error_handler
def unauthorized_auth_token():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

