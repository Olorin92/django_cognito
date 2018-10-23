from django.conf import settings
from django_cognito.authentication.middleware import helpers


# This is utilised from normal Django views. Currently used for anything that requires authentication but isn't
# already utilising rest framework
class AwsDjangoMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Get the user and a new token if required
        user, token, refresh_token = helpers.process_request(request)

        request.user = user

        response = self.get_response(request)

        if token:
            # TODO: Set the token in the response here as well? If the user hits here, they're still active
            http_only = settings.HTTP_ONLY_COOKIE
            secure = settings.SECURE_COOKIE

            response.set_cookie(key='AccessToken', value=token,
                                secure=secure, httponly=http_only)
            response.set_cookie(key="RefreshToken", value=refresh_token,
                                secure=secure, httponly=http_only)
            pass

        return response
