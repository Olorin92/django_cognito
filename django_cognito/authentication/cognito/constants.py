from django.conf import settings
from django_cognito.authentication.cognito.base import CognitoClient

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

AWS_EXCEPTIONS = (
    CognitoClient.client.exceptions.AliasExistsException,
    CognitoClient.client.exceptions.CodeDeliveryFailureException,
    CognitoClient.client.exceptions.CodeMismatchException,
    CognitoClient.client.exceptions.ExpiredCodeException,
    CognitoClient.client.exceptions.InternalErrorException,
    CognitoClient.client.exceptions.InvalidEmailRoleAccessPolicyException,
    CognitoClient.client.exceptions.InvalidLambdaResponseException,
    CognitoClient.client.exceptions.InvalidParameterException,
    CognitoClient.client.exceptions.InvalidPasswordException,
    CognitoClient.client.exceptions.InvalidSmsRoleAccessPolicyException,
    CognitoClient.client.exceptions.InvalidSmsRoleTrustRelationshipException,
    CognitoClient.client.exceptions.InvalidUserPoolConfigurationException,
    CognitoClient.client.exceptions.LimitExceededException,
    CognitoClient.client.exceptions.MFAMethodNotFoundException,
    CognitoClient.client.exceptions.NotAuthorizedException,
    CognitoClient.client.exceptions.PasswordResetRequiredException,
    CognitoClient.client.exceptions.ResourceNotFoundException,
    CognitoClient.client.exceptions.SoftwareTokenMFANotFoundException,
    CognitoClient.client.exceptions.TooManyRequestsException,
    CognitoClient.client.exceptions.UnexpectedLambdaException,
    CognitoClient.client.exceptions.UserLambdaValidationException,
    CognitoClient.client.exceptions.UserNotConfirmedException,
    CognitoClient.client.exceptions.UserNotFoundException,
    CognitoClient.client.exceptions.UsernameExistsException
)
