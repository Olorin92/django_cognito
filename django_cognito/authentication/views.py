from datetime import timedelta
from django.conf import settings
from django.utils.datetime_safe import datetime
import json
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django_cognito.authentication.cognito import helpers
from django_cognito.authentication.cognito.base import CognitoException
from django_cognito.authentication.middleware.helpers import generate_csrf


@require_http_methods(['POST'])
def initiate_auth(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.initiate_auth(data)

        return JsonResponse(result)
    except CognitoException as ex:
        return JsonResponse(ex.args[0], status=ex.status)
    except ValueError as ex:
        return JsonResponse({"error": ex.args[0]}, status=400)


@require_http_methods(['POST'])
def respond_to_auth_challenge(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.respond_to_auth_challenge(data)

        return JsonResponse(result)
    except CognitoException as ex:
        return JsonResponse(ex.args[0], status=ex.status)
    except ValueError as ex:
        return JsonResponse({"error": ex.args[0]}, status=400)
    pass


@require_http_methods(['POST'])
def forgot_password(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.forgot_password(data)

        return JsonResponse(result)
    except CognitoException as ex:
        return JsonResponse(ex.args[0], status=ex.status)
    except ValueError as ex:
        return JsonResponse({"error": ex.args[0]}, status=400)
    pass


@require_http_methods(['POST'])
def confirm_forgot_password(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.confirm_forgot_password(data)

        return JsonResponse(result)
    except CognitoException as ex:
        return JsonResponse(ex.args[0], status=ex.status)
    except ValueError as ex:
        return JsonResponse({"error": ex.args[0]}, status=400)
    pass


@require_http_methods(['POST'])
def sign_up(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.sign_up(data)

        return JsonResponse(result)
    except CognitoException as ex:
        return JsonResponse(ex.args[0], status=ex.status)
    except ValueError as ex:
        return JsonResponse({"error": ex.args[0]}, status=400)
    pass


@require_http_methods(['POST'])
def confirm_sign_up(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.confirm_sign_up(data)

        return JsonResponse(result)
    except CognitoException as ex:
        return JsonResponse(ex.args[0], status=ex.status)
    except ValueError as ex:
        return JsonResponse({"error": ex.args[0]}, status=400)
    pass


@require_http_methods(['GET'])
def get_csrf(request):
    csrf_token = generate_csrf()

    http_only = settings.HTTP_ONLY_COOKIE

    response = JsonResponse({"csrftoken": csrf_token})
    response.set_cookie(key='csrftoken', value=csrf_token,
                        secure=False, httponly=http_only, domain="localhost",
                        expires=datetime.now() + timedelta(days=30))

    return response
