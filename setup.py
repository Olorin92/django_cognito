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
        "asn1crypto==0.23.0",
        "boto3==1.8.2",
        "botocore==1.11.2",
        "cryptography>=2.3",
        "Django==1.10.0",
        "djangorestframework==3.6.4",
        "idna==2.6",
        "PyJWT==1.6.4",
        "python-dateutil==2.6.1",
        "urllib3==1.22",
    ]
)
