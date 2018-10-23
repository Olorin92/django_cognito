from unittest import TestCase

from django_cognito.authentication.cognito.actions import admin_disable_user, admin_delete_user, admin_confirm_sign_up, \
    admin_update_user_attributes
from django_cognito.authentication.cognito.helpers import initiate_auth, sign_up, forgot_password


class LoginTestCase(TestCase):
    def setUp(self):
        # Ensure this user doesn't already exist before running the rest of the tests
        try:
            result = admin_disable_user("testuser@test.com")
            result = admin_delete_user("testuser@test.com")
        except Exception as ex:
            pass

        self.username = "testuser@test.com"
        self.password = "testpass123"

        self.initialise_test_user()

    def initialise_test_user(self):
        try:
            data = {"username": self.username, "password": self.password,
                    "user_attributes": [{"Name": "given_name", "Value": "Test"},
                                        {"Name": "family_name", "Value": "User"},
                                        {"Name": "email", "Value": "testuser@test.com"}]}

            result = sign_up(data)

            result = admin_confirm_sign_up("testuser@test.com")

            result = admin_update_user_attributes(self.username, [{"Name": "email_verified", "Value": "true"}])
        except Exception as ex:
            self.fail("Could not create a test user for use with other test methods")

    def test_login(self):
        initiate_auth({"username": self.username, "password": self.password, "auth_flow": "USER_PASSWORD_AUTH"})

    def test_password_reset(self):
        forgot_password({"username": self.username})
