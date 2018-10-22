from django.conf import settings
import boto3


class CognitoClient:
    client = boto3.client('cognito-idp', aws_access_key_id=settings.AWS_ACCESS_KEY,
                          aws_secret_access_key=settings.AWS_SECRET_KEY)


class CognitoException(Exception):
    def __init__(self, message, status):
        super(CognitoException, self).__init__(message)

        self.status = status

    @staticmethod
    def create_from_exception(ex):
        return CognitoException({'error': ex.response['Error']['Message']},
                                ex.response['ResponseMetadata']['HTTPStatusCode'])
