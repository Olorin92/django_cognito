from django_cognito.authentication.cognito import constants, actions

# Collection of methods intended to make the calling of AWS Cognito methods a bit easier. Each method expects both a
# data parameter (which will be a dictionary of values) and an optional param_mapping parameter - another dictionary
# which can be used to override the name of expected values in the data dictionary

BAD_DATA_EXCEPTION = "The required parameters were not passed through in the data dictionary"


# TODO: Possibly change some of these methods to just accept one parameter where appropriate (i.e. just a username)


def initiate_auth(data, param_mapping=None):
    password = None

    try:
        auth_flow = parse_parameter(data, param_mapping, 'auth_flow')
        username = parse_parameter(data, param_mapping, 'username')

        if auth_flow == constants.USER_PASSWORD_FLOW:
            password = parse_parameter(data, param_mapping, 'password')

    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.initiate_auth(username, auth_flow, password)


def respond_to_auth_challenge(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')
        challenge_name = parse_parameter(data, param_mapping, 'challenge_name')
        responses = parse_parameter(data, param_mapping, 'responses')
        session = parse_parameter(data, param_mapping, 'session')

    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.respond_to_auth_challenge(username=username, challenge_name=challenge_name,
                                             responses=responses, session=session)


def sign_up(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')
        password = parse_parameter(data, param_mapping, 'password')
        user_attributes= parse_parameter(data, param_mapping, 'user_attributes')

    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.sign_up(username, password, user_attributes)


def confirm_sign_up(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')
        confirmation_code = parse_parameter(data, param_mapping, 'password')
        force_alias_creation = parse_parameter(data, param_mapping, 'force_alias_creation')

    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.confirm_sign_up(username, confirmation_code, force_alias_creation)


def forgot_password(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')

    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.forgot_password(username)


def confirm_forgot_password(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')
        new_password = parse_parameter(data, param_mapping, 'new_password')
        code = parse_parameter(data, param_mapping, 'code')

    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.confirm_forgot_password(username, code, new_password)


def admin_get_user(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')

    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.admin_get_user(username)


def admin_update_user_attributes(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')
        user_attributes = parse_parameter(data, param_mapping, 'user_attributes')
    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.admin_update_user_attributes(username, user_attributes)


def admin_disable_user(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')
    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.admin_disable_user(username)


def admin_delete_user(data, param_mapping=None):
    try:
        username = parse_parameter(data, param_mapping, 'username')
    except Exception as ex:
        raise ValueError(BAD_DATA_EXCEPTION)

    return actions.admin_delete_user(username)


def parse_parameter(data, param_mapping, param=None):
    if param_mapping is not None:
        if param in param_mapping:
            return data[param_mapping[param]]
    else:
        return data[param]
