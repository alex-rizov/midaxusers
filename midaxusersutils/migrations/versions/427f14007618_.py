"""empty message

Revision ID: 427f14007618
Revises: 
Create Date: 2018-11-01 17:29:30.867193

"""
from alembic import op
import sqlalchemy as sa
import midaxusers.migration_types
from midaxusers.models import User, UserLogin
from sqlalchemy.schema import Sequence, CreateSequence, DropSequence


# revision identifiers, used by Alembic.
revision = '427f14007618'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    
#TRIGGERS for auto-generating the values in Oracle
    trigger_users = sa.DDL(
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

    tusers_callable = trigger_users.execute_if(dialect="oracle")
    
    trigger_logins = sa.DDL(
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

    tlogins_callable = trigger_logins.execute_if(dialect="oracle")    

    op.create_table('USERS',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', midaxusers.migration_types.HybridUniqueIdentifier(), nullable=False),
    sa.Column('domain', sa.String(length=64), nullable=True),
    sa.Column('role', sa.Integer(), nullable=True),
    sa.Column('active', sa.Boolean(name='bl_U_active'), server_default=sa.text('1'), nullable=True),
    sa.Column('first_name', sa.String(length=64), nullable=True),
    sa.Column('middle_name', sa.String(length=64), nullable=True),
    sa.Column('last_name', sa.String(length=64), nullable=True),
    sa.Column('phone', sa.String(length=64), nullable=True),
    sa.Column('position', sa.String(length=20), nullable=True),
    sa.Column('time_updated', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_USERS')),
    sa.UniqueConstraint('uuid', name='user_uuid_uq')
    )
    op.create_index(op.f('ix_USERS_domain'), 'USERS', ['domain'], unique=False)  
    op.execute(CreateSequence(Sequence('USERS_ID_SEQ'))) 
    tusers_callable(target=None, bind=op.get_bind())
  
    op.create_table('USER_ATTRIBUTES',
    sa.Column('user_uuid', midaxusers.migration_types.HybridUniqueIdentifier(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('value', sa.String(length=64), nullable=True),
    sa.Column('time_updated', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
    sa.ForeignKeyConstraint(['user_uuid'], ['USERS.uuid'], name=op.f('fk_USER_ATTRIBUTES_user_uuid_U'), onupdate='CASCADE', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_uuid', 'name', name='userattributes_pk')
    )
    op.create_index(op.f('ix_USER_ATTRIBUTES_user_uuid'), 'USER_ATTRIBUTES', ['user_uuid'], unique=False)
    op.create_table('USER_LOGINS',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_uuid', midaxusers.migration_types.HybridUniqueIdentifier(), nullable=False),
    sa.Column('login_type', sa.String(length=40), nullable=False),
    sa.Column('login_key', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=256), nullable=False),
    sa.Column('force_password_change', sa.Boolean(name='bl_UL_fpc'), server_default=sa.text('0'), nullable=True),
    sa.Column('time_updated', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
    sa.ForeignKeyConstraint(['user_uuid'], ['USERS.uuid'], name=op.f('fk_USER_LOGINS_user_uuid_U'), onupdate='CASCADE', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_USER_LOGINS')),
    sa.UniqueConstraint('login_type', 'login_key', name='login_user_uq')
    )
    op.create_index(op.f('ix_USER_LOGINS_user_uuid'), 'USER_LOGINS', ['user_uuid'], unique=False)
    op.execute(CreateSequence(Sequence('LOGINS_ID_SEQ'))) 
    tlogins_callable(target=None, bind=op.get_bind())
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.execute(DropSequence(Sequence('LOGINS_ID_SEQ')))
    op.execute(DropSequence(Sequence('USERS_ID_SEQ')))
    op.drop_index(op.f('ix_USER_LOGINS_user_uuid'), table_name='USER_LOGINS')
    op.drop_table('USER_LOGINS')
    op.drop_index(op.f('ix_USER_ATTRIBUTES_user_uuid'), table_name='USER_ATTRIBUTES')
    op.drop_table('USER_ATTRIBUTES')
    op.drop_index(op.f('ix_USERS_domain'), table_name='USERS')
    op.drop_table('USERS')
    # ### end Alembic commands ###
