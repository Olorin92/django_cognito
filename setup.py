from setuptools import setup, find_packages
from django_cognito import __version__ as version

setup(
    name='django_cognito',
    version=version,
    packages=find_packages(),
    url='https://github.com/Olorin92/django_cognito',
    license='',
    author='Alex Plant',
    author_email='alex.c.plant@gmail.com',
    description='Library for allowing the use of AWS Cognito security in Django projects',
    install_requires=[
        "PyJWT>=1.6.4",
        "boto3>=1.4.0"
    ]
)
