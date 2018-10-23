from rest_framework.authentication import BaseAuthentication
from django_cognito.authentication.middleware import helpers


# This is utilised by any of the django rest framework views. Currently this is all of the base AWS auth views.
# We probably want to make those views use the default django library to reduce needless dependencies
class AwsRestAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # This is where we will extract information about the incoming access token from the user,
        # and decide whether or not they are authenticated

        user, access_token, refresh_token = helpers.process_request(request)

        # TODO: Potentially create a mixin for views overriding the .finalise_response method to ensure if we
        # end up with a new access token as part of this process, we are able to set it in the response
        #
        # Need some way of setting a new access token or refresh token in the final response
        return user, access_token
