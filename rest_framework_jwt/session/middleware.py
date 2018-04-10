from importlib import import_module

from django.conf import settings
from django.contrib.sessions.backends.base import UpdateError
from django.core.exceptions import SuspiciousOperation
from django.utils.deprecation import MiddlewareMixin
from rest_framework.exceptions import AuthenticationFailed

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings

ACCESS_TOKEN_HEADER = api_settings.JWT_SESSION_RESPONSE_TOKEN_HEADER_NAME


def get_jwt_value(request):
    auth = JSONWebTokenAuthentication()
    try:
        return auth.get_jwt_value(request)
    except AuthenticationFailed:
        pass


class JWTSessionMiddleware(MiddlewareMixin):
    def __init__(self, get_response=None):
        super(JWTSessionMiddleware, self).__init__(get_response=get_response)
        self.get_response = get_response
        engine = import_module(api_settings.JWT_SESSION_ENGINE)
        self.SessionStore = engine.SessionStore

    def process_request(self, request):
        session_key = get_jwt_value(request)
        request.jwt_session = self.SessionStore(session_key)

    def process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie or delete
        the session cookie if the session has been emptied.
        """
        session = request.jwt_session
        try:
            accessed = session.accessed
            modified = session.modified
            empty = session.is_empty()
        except AttributeError:
            pass
        else:
            if modified:
                if response.status_code != 500:
                    try:
                        session.save()
                    except UpdateError:
                        raise SuspiciousOperation(
                            "The request's session was deleted before the "
                            "request completed. The user may have logged "
                            "out in a concurrent request, for example."
                        )
                    response[ACCESS_TOKEN_HEADER] = session.session_key
        return response
