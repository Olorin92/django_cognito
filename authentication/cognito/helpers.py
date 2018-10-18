from authentication.cognito import constants, actions
from authentication.cognito.base import CognitoException


def initiate_auth(data, param_mapping=None):
    username = None
    auth_flow = None
    password = None

    try:
        auth_flow = data['auth_flow']
        username = data['username']

        if auth_flow == constants.USER_PASSWORD_FLOW:
            password = data['password']

    except Exception as Ex:
        pass

    try:
        result = actions.initiate_auth(username, auth_flow, password)
        return result
    except CognitoException as ex:
        pass


def respond_to_auth_challenge(data, param_mapping=None):
    username = None
    challenge_name = None
    responses = None
    session = None

    try:
        username = data['username']
        challenge_name = data['challenge_name']
        responses = data['responses']
        session = data['session']
    except Exception as Ex:
        pass

    try:
        result = actions.respond_to_auth_challenge(username=username, challenge_name=challenge_name,
                                                   responses=responses, session=session)
    except CognitoException as ex:
        pass


def sign_up(data, param_mapping):
    username = None
    password = None
    user_attributes = None

    try:
        username = data['username']
        password = data['password']
        user_attributes= data['user_attributes']
    except Exception as Ex:
        pass

    try:
        result = actions.sign_up(username, password, user_attributes)
    except CognitoException as ex:
        pass


def confirm_sign_up(data, param_mapping):
    username = None
    confirmation_code = None
    force_alias_creation = None

    try:
        username = data['username']
        password = data['password']
        force_alias_creation = data['force_alias_creation']
    except Exception as Ex:
        pass

    try:
        result = actions.confirm_sign_up(username, confirmation_code, force_alias_creation)
    except CognitoException as ex:
        pass


def validate_request_params(data, required_params):
    invalid_params = []

    for param in required_params:
        if param not in data or not data[param]:
            invalid_params.append(param)

    return invalid_params if len(invalid_params) > 0 else None
