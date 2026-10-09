from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework_simplejwt.tokens import AccessToken

from reNgine.middleware import get_user_from_token

User = get_user_model()

# database_sync_to_async closes "old" connections around each call, which would
# drop the test transaction; call the wrapped sync function directly instead.
_resolve = get_user_from_token.func


class WebSocketTokenAuthTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='ws-user', password='x')

    def test_valid_token_resolves_active_user(self):
        self.assertEqual(_resolve(str(AccessToken.for_user(self.user))), self.user)

    def test_deactivated_user_stays_anonymous(self):
        token = str(AccessToken.for_user(self.user))
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        self.assertFalse(_resolve(token).is_authenticated)

    def test_deleted_user_stays_anonymous(self):
        token = str(AccessToken.for_user(self.user))
        self.user.delete()
        self.assertFalse(_resolve(token).is_authenticated)

    def test_malformed_token_stays_anonymous(self):
        self.assertFalse(_resolve('not-a-jwt').is_authenticated)

    def test_expired_token_stays_anonymous(self):
        token = AccessToken.for_user(self.user)
        token.set_exp(lifetime=-token.lifetime)
        self.assertFalse(_resolve(str(token)).is_authenticated)
