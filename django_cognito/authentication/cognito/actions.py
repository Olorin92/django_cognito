import json
from urllib.request import urlopen

from django_cognito.authentication import utils
from django_cognito.authentication.cognito import constants
from django_cognito.authentication.cognito.base import CognitoClient, CognitoException


# Should return an AccessToken and a RefreshToken (with those keys) if successful,
# otherwise return challenge information if a challenge is required
#
# AccessToken and RefreshToken will both be keys in the AuthenticationResult key
def initiate_auth(username, auth_flow, password=None, refresh_token=None, srp_a=None):
    auth_parameters = {'SECRET_HASH': utils.get_cognito_secret_hash(username)}

    if auth_flow == constants.USER_PASSWORD_FLOW:
        auth_parameters['USERNAME'] = username
        auth_parameters['PASSWORD'] = password
    elif auth_flow == constants.REFRESH_TOKEN_AUTH_FLOW or auth_flow == constants.REFRESH_TOKEN_FLOW:
        if refresh_token is None:
            raise Exception("To use the refresh token flow you must provide a refresh token")
        else:
            auth_parameters['REFRESH_TOKEN'] = refresh_token
    else:
        raise Exception("Provided auth flow is not supported")

    try:
        return CognitoClient.client.initiate_auth(AuthFlow=auth_flow, ClientId=constants.CLIENT_ID,
                                                  AuthParameters=auth_parameters)

    except constants.AWS_EXCEPTIONS as ex:
        raise CognitoException.create_from_exception(ex)


def respond_to_auth_challenge(username, challenge_name, responses, session=None):
    responses['USERNAME'] = username
    responses['SECRET_HASH'] = utils.get_cognito_secret_hash(username)

    try:
        return CognitoClient.client.respond_to_auth_challenge(ClientId=constants.CLIENT_ID,
                                                              ChallengeName=challenge_name,
                                                              ChallengeResponses=responses,
                                                              Session=session)

    except constants.AWS_EXCEPTIONS as ex:
        raise CognitoException.create_from_exception(ex)


def sign_up(username, password, user_attributes, validation_data=None):
    secret_hash = utils.get_cognito_secret_hash(username)
    kwargs = {"ClientId": constants.CLIENT_ID, "SecretHash": secret_hash,
              "Username": username, "Password": password,
              "UserAttributes": user_attributes}

    if validation_data:
        kwargs['ValidationData'] = validation_data

    try:
        return CognitoClient.client.sign_up(**kwargs)

    except constants.AWS_EXCEPTIONS as ex:
        raise CognitoException.create_from_exception(ex)


def confirm_sign_up(username, confirmation_code, force_alias_creation=False):
    secret_hash = utils.get_cognito_secret_hash(username)

    try:
        return CognitoClient.client.confirm_sign_up(ClientId=constants.CLIENT_ID, SecretHash=secret_hash,
                                                    Username=username, ForceAliasCreation=force_alias_creation,
                                                    ConfirmationCode=confirmation_code)
    except constants.AWS_EXCEPTIONS as ex:
        raise CognitoException.create_from_exception(ex)


def forgot_password(username):
    secret_hash = utils.get_cognito_secret_hash(username)

    try:
        return CognitoClient.client.forgot_password(ClientId=constants.CLIENT_ID, SecretHash=secret_hash,
                                                    Username=username)
    except constants.AWS_EXCEPTIONS as ex:
        raise CognitoException.create_from_exception(ex)


def confirm_forgot_password(username, code, new_password):
    secret_hash = utils.get_cognito_secret_hash(username)

    try:
        return CognitoClient.client.confirm_forgot_password(ClientId=constants.CLIENT_ID, SecretHash=secret_hash,
                                                            Username=username,
                                                            Password=new_password,
                                                            ConfirmationCode=code)
    except constants.AWS_EXCEPTIONS as ex:
        raise CognitoException.create_from_exception(ex)


def admin_get_user(username):
    try:
        return CognitoClient.client.admin_get_user(UserPoolId=constants.POOL_ID, Username=username)
    except constants.AWS_EXCEPTIONS as ex:
        raise CognitoException.create_from_exception(ex)


def admin_disable_user(username):
    result = CognitoClient.client.admin_disable_user(UserPoolId=constants.POOL_ID, Username=username)

    return result


def admin_delete_user(username):
    result = CognitoClient.client.admin_delete_user(UserPoolId=constants.POOL_ID, Username=username)

    return result


def admin_confirm_sign_up(username):
    result = CognitoClient.client.admin_confirm_sign_up(UserPoolId=constants.POOL_ID, Username=username)

    return result


def get_public_keys():
    public_keys_url = urlopen("https://cognito-idp." + constants.POOL_ID.split("_", 1)[0] + ".amazonaws.com/"
                              + constants.POOL_ID + "/.well-known/jwks.json")
    public_keys = json.loads(public_keys_url.read().decode('utf-8'))

    return public_keys


def admin_create_user(username, user_attributes, temporary_password, suppress=False):
    message_action = 'SUPPRESS' if suppress else 'RESEND'

    result = CognitoClient.client.admin_create_user(UserPoolId=constants.POOL_ID, Username=username,
                                                    TemporaryPassword=temporary_password, MessageAction=message_action,
                                                    UserAttributes=user_attributes)

    return result


def admin_update_user_attributes(username, user_attributes):
    try:
        return CognitoClient.client.admin_update_user_attributes(UserPoolId=constants.POOL_ID, Username=username,
                                                                 UserAttributes=user_attributes)
    except constants.AWS_EXCEPTIONS as ex:
        raise CognitoException.create_from_exception(ex)


def resend_confirmation_code(username):
    result = CognitoClient.client.resend_confirmation_code(ClientId=constants.CLIENT_ID, Username=username,
                                                           SecretHash=utils.get_cognito_secret_hash(username))

    return result


def admin_list_users(attributes_to_get=None, pagination_token=None):
    args = {'UserPoolId': constants.POOL_ID}

    if attributes_to_get:
        args['AttributesToGet'] = attributes_to_get
    if pagination_token:
        args['PaginationToken'] = pagination_token

    result = CognitoClient.client.list_users(**args)

    return result
