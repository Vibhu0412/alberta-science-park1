from django.contrib.auth.tokens import PasswordResetTokenGenerator


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, email, timestamp):
        return f"{email}{timestamp}"


account_activation_token = AccountActivationTokenGenerator()
