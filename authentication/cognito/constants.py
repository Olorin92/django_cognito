import boto3
from django.conf import settings

USER_PASSWORD_FLOW = 'USER_PASSWORD_AUTH'
REFRESH_TOKEN_FLOW = 'REFRESH_TOKEN'
REFRESH_TOKEN_AUTH_FLOW = 'REFRESH_TOKEN_AUTH'

SMS_CHALLENGE = 'SMS_MFA'
SOFTWARE_CHALLENGE = 'SOFTWARE_TOKEN_MFA'
NEW_PASSWORD_CHALLENGE = 'NEW_PASSWORD_REQUIRED'

CLIENT_ID = settings.APP_CLIENT_ID
CLIENT_SECRET = settings.APP_SECRET_KEY
POOL_ID = settings.COGNITO_POOL_ID
AWS_ACCESS_KEY = settings.AWS_ACCESS_KEY
AWS_SECRET_KEY = settings.AWS_SECRET_KEY

try:
    CLIENT = boto3.client('cognito-idp', aws_access_key=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
except Exception as ex:
    pass

AWS_EXCEPTIONS = (
    CLIENT.exceptions.AliasExistsException,
    CLIENT.exceptions.CodeDeliveryFailureException,
    CLIENT.exceptions.CodeMismatchException,
    CLIENT.exceptions.ExpiredCodeException,
    CLIENT.exceptions.InternalErrorException,
    CLIENT.exceptions.InvalidEmailRoleAccessPolicyException,
    CLIENT.exceptions.InvalidLambdaResponseException,
    CLIENT.exceptions.InvalidParameterException,
    CLIENT.exceptions.InvalidPasswordException,
    CLIENT.exceptions.InvalidSmsRoleAccessPolicyException,
    CLIENT.exceptions.InvalidSmsRoleTrustRelationshipException,
    CLIENT.exceptions.InvalidUserPoolConfigurationException,
    CLIENT.exceptions.LimitExceededException,
    CLIENT.exceptions.MFAMethodNotFoundException,
    CLIENT.exceptions.NotAuthorizedException,
    CLIENT.exceptions.PasswordResetRequiredException,
    CLIENT.exceptions.ResourceNotFoundException,
    CLIENT.exceptions.SoftwareTokenMFANotFoundException,
    CLIENT.exceptions.TooManyRequestsException,
    CLIENT.exceptions.UnexpectedLambdaException,
    CLIENT.exceptions.UserLambdaValidationException,
    CLIENT.exceptions.UserNotConfirmedException,
    CLIENT.exceptions.UserNotFoundException,
    CLIENT.exceptions.UsernameExistsException
)
