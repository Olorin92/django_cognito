import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_cognito.authentication.cognito import helpers
from django_cognito.authentication.cognito.base import CognitoException


@csrf_exempt
@require_http_methods(['POST'])
def initiate_auth(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.initiate_auth(data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)


@require_http_methods(['POST'])
def respond_to_auth_challenge(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.respond_to_auth_challenge(data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass


@csrf_exempt
@require_http_methods(['POST'])
def forgot_password(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.forgot_password(data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass


@csrf_exempt
@require_http_methods(['POST'])
def confirm_forgot_password(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.confirm_forgot_password(data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass


@csrf_exempt
@require_http_methods(['POST'])
def sign_up(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.sign_up(data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass


@csrf_exempt
@require_http_methods(['POST'])
def confirm_sign_up(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.confirm_sign_up(data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass
