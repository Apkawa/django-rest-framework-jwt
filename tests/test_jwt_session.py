from django.contrib.auth import get_user_model
from django.test import TestCase

from rest_framework_jwt.session.session import SessionStore
from rest_framework_jwt.settings import api_settings

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER

User = get_user_model()


class BaseTestCase(TestCase):

    def setUp(self):
        self.email = 'jpueblo@example.com'
        self.username = 'jpueblo'
        self.password = 'password'
        self.user = User.objects.create_user(
            self.username, self.email, self.password)

        self.data = {
            'username': self.username,
            'password': self.password
        }

    def test_payload(self):
        user = self.user
        payload = jwt_payload_handler(user)
        assert payload['user_id'] == user.pk
        assert payload['username'] == user.username

        payload = jwt_payload_handler(extra_data={'cart_id': 123})

        assert payload['user_id'] == ''
        assert payload['username'] == ''
        assert payload['cart_id'] == 123

        payload = jwt_payload_handler(extra_data={'cart_id': 123, 'user_id': 4, 'username': 'test'})

        assert payload['user_id'] == 4
        assert payload['username'] == 'test'
        assert payload['cart_id'] == 123

        payload = jwt_payload_handler(user,
                                      extra_data={'cart_id': 123, 'user_id': 4, 'username': 'test'})
        assert payload['user_id'] == user.pk
        assert payload['username'] == user.username
        assert payload['cart_id'] == 123

    def test_new_session(self):
        store = SessionStore()
        store['cart_id'] = 123
        store.save()
        assert store.session_key
        assert jwt_decode_handler(store.session_key)['cart_id'] == 123

    def test_with_exists_token(self):
        user = self.user
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)
        store = SessionStore(token)
        assert store['user_id'] == user.id

    def test_with_exists_session(self):
        user = self.user
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)
        store = SessionStore(token)
        store['cart_id'] = 123
        store.save()

        store2 = SessionStore(store.session_key)
        assert store2['user_id'] == user.id
        assert store2['cart_id'] == 123



