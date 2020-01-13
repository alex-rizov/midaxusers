import io

from setuptools import find_packages, setup

setup(
    name='midaxusers',
    version='2.0.38',
    url='http://www.midax.com',
    license='BSD',
    maintainer='Midax',
    maintainer_email='alex.r@midax.com',
    description='Midax Users API',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'muserscreate = midaxusersutils.manage:create_db',
            'muserstestuser = midaxusersutils.manage:create_test_user',
            'musersupgrade = midaxusersutils.manage:mupgrade'
        ]
    },
    install_requires=[
        'flask',
        'alembic==1.0.0',
        'astroid',
        'attrs',
        'click',
        'colorama',
        'Flask',
        'Flask-HTTPAuth',
        'Flask-Migrate',
        'Flask-SQLAlchemy',
        'isort',
        'itsdangerous',
        'Jinja2',
        'lazy-object-proxy',
        'Mako',
        'MarkupSafe',
        'mccabe',
        'pluggy',
        'py',
        'pylint',
        'pyodbc',
        'python-dateutil',
        'python-editor',
        'six',
        'SQLAlchemy',
        'Werkzeug',
        'wrapt',
        'cx_Oracle',
    ]  
)