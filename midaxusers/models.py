from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import PrimaryKeyConstraint, UniqueConstraint, String, Integer, DateTime, Column, Boolean, CHAR, Sequence, ForeignKey, Index, MetaData
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import func, expression
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.dialects.oracle import RAW
from sqlalchemy.types import PickleType
from sqlalchemy.orm import relationship
from sqlalchemy.orm.session import Session, make_transient
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.collections import attribute_mapped_collection
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask import abort, jsonify
from sqlalchemy import types, and_, or_, TypeDecorator, event, DDL, Enum
from sqlalchemy.dialects.mysql.base import MSBinary
from sqlalchemy.ext.hybrid import hybrid_property
#from sqlalchemy.schema import Column
import uuid
import binascii
import json
from collections import namedtuple
import collections
import enum


convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name).1s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention= convention)

db = SQLAlchemy(metadata=metadata)
migrate = Migrate()

class HybridUniqueIdentifier(TypeDecorator):
    impl = CHAR

    def load_dialect_impl(self, dialect):
        if dialect.name == 'mssql':
            return dialect.type_descriptor(UNIQUEIDENTIFIER)
        elif dialect.name == 'oracle':
            return dialect.type_descriptor(RAW(16))
        else:
            return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'mssql':
            if not isinstance(value, uuid.UUID):
                return str(uuid.UUID(value))
            else:
                return str(value)
        elif dialect.name == 'oracle':
            if not isinstance(value, uuid.UUID):
                return uuid.UUID(value).bytes
            else:
                return value.bytes
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value).int
            else:
                # hexstring
                return "%.32x" % value.int

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'mssql':
            if not isinstance(value, uuid.UUID):                
                value = uuid.UUID(value)
            return value
        elif dialect.name == 'oracle':
            if not isinstance(value, uuid.UUID):                
                value = uuid.UUID(bytes = value)
            return value
        else:            
            if not isinstance(value, uuid.UUID):
                value = uuid.UUID(value)
            return value

domain_separator = '^'

def clone_model(model, **kwargs):
    """Clone an arbitrary sqlalchemy model object without its primary key values."""
    # Ensure the model’s data is loaded before copying.
    model.id

    table = model.__table__
    non_pk_columns = [k for k in table.columns.keys() if k not in table.primary_key]
    data = {c: getattr(model, c) for c in non_pk_columns}
    data.update(kwargs)

    clone = model.__class__(**data)
    db.session.add(clone)   
    return clone

def generate_uuid():
   return str(uuid.uuid4())   

class ManagerTypesEnum(enum.Enum):
    none = 'none'
    subdomain = 'subdomain'
    domain = 'domain'

class User(db.Model):
    __tablename__ = 'USERS'
    id = Column(Integer, Sequence('USERS_ID_SEQ'), primary_key=True)
    uuid = Column(HybridUniqueIdentifier(), default=uuid.uuid4, nullable = False)
    _domain = Column('domain', String(64), index=True)    
    role = Column(Integer)        
    _active = Column('active', Boolean(name='bl_U_active'), server_default=expression.true())
    user_manage_rights = Column(Enum(ManagerTypesEnum), server_default=('subdomain'), nullable = False)
    first_name = Column(String(64))
    middle_name = Column(String(64))
    last_name = Column(String(64))
    phone = Column(String(64))
    position = Column(String(20))
    time_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())    
    logins = relationship('UserLogin', backref = 'user', collection_class=attribute_mapped_collection('login_type'),
                cascade="all, delete-orphan")
    attributes = relationship('UserAttributes', backref = 'user', collection_class=attribute_mapped_collection('name'),
                cascade="all, delete-orphan")

    __table_args__ = (       
        UniqueConstraint('uuid', name='user_uuid_uq'),
        {'implicit_returning':False}
                     )

    @hybrid_property
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, value):
        self._domain = value.casefold().strip(domain_separator + ' ')

    @hybrid_property
    def active(self):   # pylint: disable=E0202
        return self._active

    @active.setter
    def active(self, value):
        self._active = value
        if value == False:  
            self.logins = {}

    def clone(self):
        new_user = clone_model(self, uuid = uuid.uuid4())        
        return new_user

    def migrate(self):
        new_user = self.clone()
        for key, value in list(self.logins.items()):
            value.user = new_user
        for key, value in list(self.attributes.items()):
            value.user = new_user

        self.active = False
        return new_user


    def update_from_named_tuple(self, named_tuple_user):
        gen = (x for x in dir(named_tuple_user) if not x.startswith('__'))

        for a in gen: 
            if a not in dir(self):
                pass
            elif a == 'logins': 
                for key, value in getattr(named_tuple_user, a).items():                        
                    value['login_type'] = key
                    if value['login_key'] is None or len(value['login_key']) == 0:
                        self.logins.pop(key, None)
                    else:
                        a_login = self.logins.get(key, None)
                        if a_login is None:
                            a_login = UserLogin()
                            
                        a_login.update_from_dict(value)
                        self.logins[key] = a_login
            elif a == 'user_manage_rights':
                self.user_manage_rights = ManagerTypesEnum[getattr(named_tuple_user, a)]            
            else:
                setattr(self, a, getattr(named_tuple_user, a))
        
        #we need to make sure we set active last in order to have no remaining logins
        try:
            self.active = named_tuple_user.active
        except AttributeError:
            self.active = self.active

    def __init__(self, named_tuple_user = None, **kwargs):
        super(User, self).__init__(**kwargs)

        if named_tuple_user is not None:
            self.update_from_named_tuple(named_tuple_user)


    def serialize(self):
        return {            
            'uuid': str(self.uuid),
            'active': str(self.active),
            'domain': self.domain,
            'role':str(self.role),
            'first_name':self.first_name,
            'middle_name':self.middle_name,
            'last_name':self.last_name,
            'phone':self.phone,
            'position':self.position,
            'user_manage_rights':self.user_manage_rights.value,
            'logins': { key : value.serialize() for key, value in self.logins.items()},
            'user_attributes': {key : value.value for key, value in self.attributes.items()}
        }
    
    
    @classmethod
    def search(cls, searched_uuid, active = True):        
        if not isinstance(searched_uuid, uuid.UUID):
            searched_uuid = uuid.UUID(searched_uuid)

        user = cls.query.filter_by(uuid = searched_uuid).first()

        if user is None:
            raise NoResultFound("User Not Found")

        return user
   

    #def __repr__(self):
    #    return '<Domain {} User {}>'.format(self.domain, self.username)
    
    #def __str__(self):
    #      return '<{}@{}>'.format(self.username, self.domain)  

class PasswordNeedsResetError(Exception):
    def __init__(self, user, msg=None):
        if msg is None:            
            msg = 'Your Password Needs To Be Reset'
        super(PasswordNeedsResetError, self).__init__(msg)
        self.user = user

class UserLogin(db.Model):
    __tablename__ = 'USER_LOGINS'
    id = Column(Integer, Sequence('LOGINS_ID_SEQ'), primary_key=True)
    user_uuid = Column(HybridUniqueIdentifier(), ForeignKey('USERS.uuid', onupdate='CASCADE', ondelete ='CASCADE'), index = True, nullable = False)
    login_type = Column(String(40), nullable = False)
    login_key = Column(String(120), nullable = False)
    password_hash = Column(String(256), nullable = False)
    force_password_change = Column(Boolean(name='bl_UL_fpc'), server_default=expression.false())
    time_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    __table_args__ = (        
        UniqueConstraint('login_type', 'login_key', name='login_user_uq'),
        {'implicit_returning':False}
                     )

    def password_set(self, value):
        self.password_hash = generate_password_hash(value, method='pbkdf2:sha512', salt_length=16)               

    password = property()
    password = password.setter(password_set)  

    def __init__(self, *initial_data, **kwargs):
        super(UserLogin, self).__init__(**kwargs)

        for dictionary in initial_data:
            self.update_from_dict(dictionary)            

    def update_from_dict(self, dictionary):
        for key in dictionary:
            setattr(self, key, dictionary[key])


    def serialize(self):
        return {
            'login_type' : self.login_type,
            'login_key' : self.login_key,
            'force_password_change' : str(self.force_password_change)
        }
        
              

    def check_password(self, value):        
        if self.password_hash is not None and value is not None:
            return check_password_hash(self.password_hash, value)
        return False

    @staticmethod
    def get_user(credentials, check_password = False):
        login = UserLogin.query.filter_by(login_type = credentials['login_type'], login_key = credentials['login_key']).first()

        if login is None:
            raise NoResultFound("No Login Found")

        if check_password is True:
            if login.check_password(credentials['password']) is False:
                raise ValueError("Wrong password")   

            if login.force_password_change is True:
                raise PasswordNeedsResetError(login.user)     

        user = login.user

        if user is None:
            raise NoResultFound("No User Found")

        return user

class UserAttributes(db.Model):
    __tablename__ = 'USER_ATTRIBUTES'

    user_uuid = Column(HybridUniqueIdentifier(), ForeignKey('USERS.uuid', onupdate='CASCADE', ondelete ='CASCADE'), index = True, nullable = False)
    name = Column(String(64))
    value = Column(String(64))
    time_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (PrimaryKeyConstraint('user_uuid', 'name', name='userattributes_pk'),
    {'implicit_returning':False}
                     )
    
                
    def __repr__(self):
        return '<{}:{}>'.format(self.name, self.value)  


#TRIGGERS for auto-generating the values in Oracle
trigger_users = DDL(
    "create or replace trigger USERS_id_trigger "
    "before insert on USERS "
    "for each row "
    "WHEN (new.id IS NULL) "
    "begin "
    "SELECT USERS_ID_SEQ.nextval "
    "INTO :new.id "
    "from dual; "    
    "end; " 
)

event.listen(
    User.__table__,
    'after_create',
    trigger_users.execute_if(dialect='oracle')
)

trigger_logins = DDL(
    "create or replace trigger logins_id_trigger "
    "before insert on USER_LOGINS "
    "for each row "
    "WHEN (new.id IS NULL) "
    "begin "
    "SELECT LOGINS_ID_SEQ.nextval "
    "INTO :new.id "
    "from dual; "    
    "end; " 
)

event.listen(
    UserLogin.__table__,
    'after_create',
    trigger_logins.execute_if(dialect='oracle')
)

