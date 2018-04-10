import unittest
from calendar import timegm
from datetime import datetime, timedelta
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from django import get_version
from django.test import TestCase
from django.test.utils import override_settings, modify_settings
from rest_framework import status
from rest_framework.test import APIClient

from rest_framework_jwt import utils, views
from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.settings import api_settings, DEFAULTS

from . import utils as test_utils

User = get_user_model()

NO_CUSTOM_USER_MODEL = 'Custom User Model only supported after Django 1.5'

orig_datetime = datetime


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


@override_settings(SESSION_ENGINE='rest_framework_jwt.session.session')
@modify_settings(MIDDLEWARE_CLASSES={
    'prepend': 'rest_framework_jwt.session.middleware.JWTSessionMiddleware',
})
class CustomUserUUIDObtainJSONWebTokenTests(BaseTestCase):
    """JSON Web Token Authentication"""

    def setUp(self):
        api_settings.JWT_SESSION = True
        api_settings.JWT_ALLOW_ANONYMOUS = True
        super(CustomUserUUIDObtainJSONWebTokenTests, self).setUp()

    def test_jwt_empty_session(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        response = client.get('/jwt/session/', format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        assert not response.data['mock_id']

    def test_jwt_set_session(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        response = client.post('/jwt/session/', data={'mock_id': 777}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        assert response.data['mock_id'] == 777

        token = response['Access-Token']
        assert utils.jwt_decode_handler(token)['mock_id'] == 777

    def test_jwt_exists_token_and_empty_session(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)

        response = client.get('/jwt/session/',
                              HTTP_AUTHORIZATION=auth,
                              format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK, str(response.content))
        assert not response.data['mock_id']

    def test_jwt_exists_token_session(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        payload = utils.jwt_payload_handler(self.user, {'mock_id': 555})
        token = utils.jwt_encode_handler(payload)
        assert utils.jwt_decode_handler(token)['mock_id'] == 555
        auth = 'JWT {0}'.format(token)

        response = client.get('/jwt/session/',
                              HTTP_AUTHORIZATION=auth,
                              format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK, str(response.content))
        assert response.data['mock_id'] == 555

    def test_jwt_set_session_with_exists_user(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)
        payload = utils.jwt_payload_handler(self.user, {'mock_id': 888, 'custom_data': 'test'})
        token = utils.jwt_encode_handler(payload)
        auth = 'JWT {0}'.format(token)

        response = client.post('/jwt/session/',
                               HTTP_AUTHORIZATION=auth,
                               data={'mock_id': 777}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        assert response.data['mock_id'] == 777

        token = response['Access-Token']
        decoded_payload = utils.jwt_decode_handler(token)
        assert decoded_payload['mock_id'] == 777
        assert decoded_payload['custom_data'] == 'test'
        assert decoded_payload['user_id'] == self.user.id
        assert decoded_payload['username'] == self.user.username

    def test_jwt_exists_token_session_without_user(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        payload = utils.jwt_payload_handler(extra_data={'mock_id': 555})
        token = utils.jwt_encode_handler(payload)
        assert utils.jwt_decode_handler(token)['mock_id'] == 555
        auth = 'JWT {0}'.format(token)

        response = client.get('/jwt/session/',
                              HTTP_AUTHORIZATION=auth,
                              format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK, str(response.content))
        assert response.data['mock_id'] == 555

    def test_keep_jwt_session_after_login(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        payload = utils.jwt_payload_handler(extra_data={'mock_id': 555})
        token = utils.jwt_encode_handler(payload)
        assert utils.jwt_decode_handler(token)['mock_id'] == 555
        token = 'JWT {0}'.format(token)

        response = client.post('/auth-token/', data=self.data,
                               HTTP_AUTHORIZATION=token,
                               format='json')

        decoded_payload = utils.jwt_decode_handler(response.data['token'])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(decoded_payload['username'], self.username)
        self.assertEqual(decoded_payload['mock_id'], 555)

    def test_keep_jwt_session_after_refresh_anonymous(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        api_settings.JWT_ALLOW_REFRESH = True
        client = APIClient(enforce_csrf_checks=True)

        payload = utils.jwt_payload_handler(extra_data={'mock_id': 555})
        token = utils.jwt_encode_handler(payload)
        assert utils.jwt_decode_handler(token)['mock_id'] == 555

        response = client.post('/auth-token-refresh/', data={'token': token},
                               format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK, str(response.content))

        decoded_payload = utils.jwt_decode_handler(response.data['token'])

        self.assertEqual(decoded_payload['username'], '')
        self.assertEqual(decoded_payload['mock_id'], 555)

    def test_keep_jwt_session_after_refresh_user(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        api_settings.JWT_ALLOW_REFRESH = True
        client = APIClient(enforce_csrf_checks=True)

        payload = utils.jwt_payload_handler(self.user, extra_data={'mock_id': 555})
        token = utils.jwt_encode_handler(payload)
        assert utils.jwt_decode_handler(token)['mock_id'] == 555

        response = client.post('/auth-token-refresh/', data={'token': token},
                               format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK, str(response.content))

        decoded_payload = utils.jwt_decode_handler(response.data['token'])

        self.assertEqual(decoded_payload['username'], self.username)
        self.assertEqual(decoded_payload['mock_id'], 555)
