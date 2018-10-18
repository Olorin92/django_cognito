from django.core.management import BaseCommand
from authentication.base.base_auth import AWSAuthMethods, USER_PASSWORD_FLOW

class Command(BaseCommand):
    def handle(self, *args, **options):
        username = 'testuser'
        password = 'Jana_Pass01'
        user_attributes = [{'Name': 'email', 'Value': "alex.plant@jana.com.au"},
                           {'Name': 'phone_number', 'Value': "+61420927187"},
                           {'Name': 'given_name', 'Value': "Alex"},
                           {'Name': 'family_name', 'Value': "Plant"},
                           {'Name': 'email_verified', 'Value': 'False'},
                           {'Name': 'phone_number_verified', 'Value': 'False'}
                           ]

        result = AWSAuthMethods.admin_create_user(username, user_attributes, password, True)

        result = AWSAuthMethods.initiate_auth(username, USER_PASSWORD_FLOW, password=password)

        challenge_responses = {"NEW_PASSWORD": "Jana_Pass02"}
        session = result['Session']
        challenge_name = result['ChallengeName']

        result = AWSAuthMethods.respond_to_auth_challenge(username, challenge_name, challenge_responses, session=session)

        result = AWSAuthMethods.admin_update_user_attributes(username, [{'Name': 'email_verified', 'Value': 'True'}])

        result = AWSAuthMethods.admin_get_user("testuser")

        pass
