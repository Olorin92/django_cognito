import datetime
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.models import User
import json
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework.decorators import api_view, authentication_classes, permission_classes

from authentication.base import base_auth
from authentication.base.base_auth import AWSAuthMethods, BaseAuth, AWSException


@csrf_exempt
@require_http_methods(['POST'])
def initiate_auth(request):
    # We need to inspect the request body and pull out the required fields:
    # Username, Password
    try:
        data = json.loads(request.body.decode('utf-8'))
        username = None
        auth_flow = None
        password = None

        try:
            auth_flow = data['auth_flow']
            username = data['username']

            if auth_flow == base_auth.USER_PASSWORD_FLOW:
                password = data['password']

        except Exception as Ex:
            # Couldn't get the required parameters from the request body
            pass

        try:
            result = AWSAuthMethods.initiate_auth(username, auth_flow, password)
            return result
        except AWSException as ex:
            pass

        if validate_request_params(data, ('username', 'password')):
            # We haven't received all of the data we require, go back to the user
            return JsonResponse({"error": "The required parameters were not provided"}, status=400)
        else:
            try:
                auth_flow = "USER_PASSWORD_AUTH"

                try:
                    result = AWSAuthMethods.initiate_auth(data['email'].lower(), auth_flow,
                                                          password=data['password'])

                except (BaseAuth.client.exceptions.UserNotFoundException,
                        BaseAuth.client.exceptions.UserNotConfirmedException,
                        BaseAuth.client.exceptions.PasswordResetRequiredException,
                        BaseAuth.client.exceptions.NotAuthorizedException) as ex:
                    return JsonResponse({'error': ex.response['Error']['Message']},
                                        status=ex.response['ResponseMetadata']['HTTPStatusCode'])
                except Exception as Ex:
                    return JsonResponse({'error': 'Invalid username or password'}, status=401)

                if result['ChallengeParameters']:
                    # We need to do an auth challenge, don't set token cookies
                    return JsonResponse(json.dumps(result), status=200)
                else:
                    response = JsonResponse(result, status=200)

                    http_only = settings.HTTP_ONLY_COOKIE
                    secure = settings.SECURE_COOKIE

                    response.set_cookie(key='AccessToken', value=result['AuthenticationResult']['AccessToken'],
                                        secure=secure, httponly=http_only,
                                        expires=datetime.datetime.now() + datetime.timedelta(days=30))
                    response.set_cookie(key="RefreshToken", value=result['AuthenticationResult']['RefreshToken'],
                                        secure=secure, httponly=http_only,
                                        expires=datetime.datetime.now() + datetime.timedelta(days=30))

                    return response
            except Exception as ex:
                return JsonResponse({'error': 'An error occurred while attempting to log you in. Please contact support'},
                                    status=500)
            pass
        pass
    except Exception as ex:
        return JsonResponse({'error': 'The request sent was not properly formed'}, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def respond_to_auth_challenge(request):
    try:
        data = json.loads(request.body.decode('utf-8'))

        if validate_request_params(data, ('username', 'challenge_name', 'challenge_responses')):
            # Don't have the required fields, error out
            return JsonResponse({'error': "The required parameters were not provided"}, status=400)
        else:
            try:
                try:
                    result = AWSAuthMethods.respond_to_auth_challenge(data['username'].lower(), data['challenge_name'],
                                                                      json.loads(data['challenge_responses']),
                                                                      session=data['session'])
                except (BaseAuth.client.exceptions.CodeMismatchException,
                        BaseAuth.client.exceptions.ExpireCodeException,
                        BaseAuth.client.exceptions.PasswordResetRequiredException,
                        BaseAuth.client.exceptions.UserNotFoundException,
                        BaseAuth.client.exceptions.UserNotConfirmedException) as ex:
                    return JsonResponse({'error': ex.response['Error']['Message']},
                                        status=ex.response['ResponseMetadata']['HTTPStatusCode'])

                response = HttpResponse()

                http_only = settings.HTTP_ONLY_COOKIE
                secure = settings.SECURE_COOKIE

                response.set_cookie(key='AccessToken', value=result['AuthenticationResult']['AccessToken'],
                                    secure=secure, httponly=http_only,
                                    expires=datetime.datetime.now() + datetime.timedelta(days=30))
                response.set_cookie(key="RefreshToken", value=result['AuthenticationResult']['RefreshToken'],
                                    secure=secure, httponly=http_only,
                                    expires=datetime.datetime.now() + datetime.timedelta(days=30))

                response.content = result

                return JsonResponse(result)
            except Exception as ex:
                return JsonResponse({'error': 'We couldn\'t validate the challenge response.'}, status=400)
        pass
    except Exception as ex:
        return JsonResponse({'error': 'The request was not properly formed'})


@csrf_exempt
@require_http_methods(['POST'])
def sign_up(request):
    # TODO: Possibly allow SMS or email, not just email?

    # TODO: BLOCK EMAIL IF NOT VALID
    try:
        data = json.loads(request.body.decode('utf-8'))

        if validate_request_params(data, ('password', 'email', 'given_name', 'family_name', 'role_type',
                                          'business_type', 'accepted_terms')):
            # We don't have the required fields, fail
            return JsonResponse({'error': 'The required parameters were not provided'}, status=400)
        else:
            if not data['accepted_terms'] or (data['accepted_terms'] != 1 and data['accepted_terms'].upper() != 'TRUE'):
                return JsonResponse({"error": "You must accept the terms and conditions"}, status=400)

            try:
                email = data['email'].lower()
                # TODO: Ensure phone number verification works properly (really should only be a mobile)
                user_attributes = [{'Name': 'email', 'Value': email},
                                   {'Name': 'given_name', 'Value': data['given_name']},
                                   {'Name': 'family_name', 'Value': data['family_name']},
                                   {'Name': 'custom:role_type', 'Value': data['role_type']},
                                   {'Name': 'custom:business_type', 'Value': data['business_type']},
                                   {'Name': 'custom:accepted_terms', 'Value': '1'},
                                   {'Name': 'custom:subscribed',
                                    'Value': '1' if data['subscribed'] == 'true' else '0'}
                                   ]

                result = AWSAuthMethods.sign_up(email, data['password'], user_attributes)

                return JsonResponse(result)

            except (BaseAuth.client.exceptions.InvalidPasswordException,
                    BaseAuth.client.exceptions.UsernameExistsException,
                    BaseAuth.client.exceptions.CodeDeliveryFailureException,
                    BaseAuth.client.exceptions.NotAuthorizedException) as ex:
                return JsonResponse({'error': ex.response['Error']['Message']},
                                    status=ex.response['ResponseMetadata']['HTTPStatusCode'])
            except Exception as ex:
                return JsonResponse({'error': 'An error occurred while attempting to sign you up. Please contact support'},
                                    status=400)
    except Exception as ex:
        return JsonResponse({'error': 'The request was not properly formed'}, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def confirm_sign_up(request):
    # TODO: Use the username to register, not the email that is currently being grabbed from the user. We should assume
    # that the caller is giving us the username (be that the email, sub, or actual username)
    try:
        data = json.loads(request.body.decode('utf-8'))

        if validate_request_params(data, ('username', 'code')):
            # We haven't gotten the required parameters for this method, return an error
            return JsonResponse({'error': 'The required parameters were not provided'}, status=400)
        else:
            try:
                matching_domain = VerifiedDomain.objects.get(domain=data['username'].split('@')[1])
            except Exception as ex:
                return JsonResponse({'error': 'Unverified domain'})
            try:
                username = data['username'].lower()
                result = AWSAuthMethods.confirm_sign_up(username, data['code'])

                try:
                    aws_user = AWSAuthMethods.admin_get_user(username)
                except BaseAuth.client.exceptions.UserNotFoundException as ex:
                    result = JsonResponse({'error': ex.response['Error']['Message']},
                                          status=ex.response['ResponseMetadata']['HTTPStatusCode'])

                # This needs to be specific to the user model being created. Should the views be sitting in another
                # project or have their own custom setup for each project they're imported to?
                #
                # Could also potentially allow a setting key to be used in order to indicate the extra fields that need
                # to be applied to the user - but this might be a bit clunky, as if they forget to override the user
                # model, it'll crash
                try:
                    django_user = User.objects.get(email=username)
                    django_user.username = aws_user.username

                    django_user.save()
                except Exception as Ex:
                    # If we get here, the user either already existed in Django, or some other weird thing happened
                    django_user = User.objects.create_user(username=aws_user.username, email=username)

                django_user.save()

                return JsonResponse(result)

            except (BaseAuth.client.exceptions.ExpireCodeException,
                    BaseAuth.client.exceptions.CodeMismatchException,
                    BaseAuth.client.exceptions.UserNotFoundException) as ex:
                return JsonResponse({'error': ex.response['Error']['Message']},
                                    status=ex.response['ResponseMetadata']['HTTPStatusCode'])
            except Exception as ex:
                return JsonResponse({'data': 'An error occurred while attempting to confirm your sign up. '
                                             'Please contact support'},
                                    status=500)
            pass
    except Exception as ex:
        return JsonResponse({'error': 'The request was not properly formed'}, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def forgot_password(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        if validate_request_params(data, ['username']):
            # We haven't got the required parameters, error out
            return JsonResponse({'error': "The required parameters were not provided"}, status=400)
        else:
            username = data['username'].lower()

            try:
                result = AWSAuthMethods.forgot_password(username)

                return JsonResponse(result, status=200)

            except (BaseAuth.client.exceptions.UserNotConfirmedException,
                    BaseAuth.client.exceptions.UserNotFoundException,
                    BaseAuth.client.exceptions.CodeDeliveryFailureException,
                    BaseAuth.client.exceptions.NotAuthorizedException,
                    BaseAuth.client.exceptions.LimitExceededException) as ex:
                return JsonResponse({'error': ex.response['Error']['Message']},
                                    status=ex.response['ResponseMetadata']['HTTPStatusCode'])
            except Exception as ex:
                return JsonResponse({'error': 'Invalid username'},
                                    status=400)
        pass
    except Exception as ex:
        return JsonResponse({'error': 'The request was not properly formed'}, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def confirm_forgot_password(request):
    try:
        data = json.loads(request.body.decode('utf-8'))

        if validate_request_params(data, ('username', 'confirmation_code', 'password')):
            return JsonResponse({'error': "The required parameters were not provided"}, status=400)
        else:
            try:
                username = data['username'].lower()

                result = AWSAuthMethods.confirm_forgot_password(username, data['confirmation_code'],
                                                                data['password'])

                return JsonResponse(result, status=200)

            except (BaseAuth.client.exceptions.UserNotConfirmedException,
                    BaseAuth.client.exceptions.UserNotFoundException,
                    BaseAuth.client.exceptions.CodeMismatchException,
                    BaseAuth.client.exceptions.InvalidPasswordException,
                    BaseAuth.client.exceptions.ExpiredCodeException) as ex:
                return JsonResponse({'error': ex.response['Error']['Message']},
                                    status=ex.response['ResponseMetadata']['HTTPStatusCode'])
            except Exception as ex:
                return JsonResponse({'error': 'We couldn\'t reset your password. Please ensure the code is correct '
                                              'and passwords conform to policy'},
                                    status=400)
        pass
    except Exception as Ex:
        return JsonResponse({'error': 'The request was not properly formed'}, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def logout(request):
    try:
        response = JsonResponse({})

        http_only = settings.HTTP_ONLY_COOKIE
        secure = settings.SECURE_COOKIE

        response.set_cookie(key='AccessToken', value=None, expires=datetime.datetime.now(),
                            secure=secure, httponly=http_only)
        response.set_cookie(key='RefreshToken', value=None, expires=datetime.datetime.now(),
                            secure=secure, httponly=http_only)

        return response
    except Exception as ex:
        return JsonResponse({'error': 'An error occurred while trying to log you out. Please contact support'},
                            status=500)


def validate_request_params(data, required_params):
    invalid_params = []

    for param in required_params:
        if param not in data or not data[param]:
            invalid_params.append(param)

    return invalid_params if len(invalid_params) > 0 else None
