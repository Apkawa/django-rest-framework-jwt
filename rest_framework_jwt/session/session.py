from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.sessions.backends.base import SessionBase
from rest_framework_jwt.settings import api_settings

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER


class SessionStore(SessionBase):
    def load(self):
        """
        We load the data from the key itself instead of fetching from
        some external data store. Opposite of _get_session_key(),
        raises BadSignature if signature fails.
        """
        try:
            return jwt_decode_handler(self.session_key)
        except Exception:
            # BadSignature, ValueError, or unpickling exceptions. If any of
            # these happen, reset the session.
            self.create()
        return {}

    def _get_session_key(self):
        """
        Most session backends don't need to override this method, but we do,
        because instead of generating a random string, we want to actually
        generate a JWT Token with DRF-JWT.
        """
        session_cache = getattr(self, '_session_cache', {})
        payload = jwt_payload_handler(extra_data=session_cache)
        return jwt_encode_handler(payload)

    def create(self):
        """
        To create a new key, we simply make sure that the modified flag is set
        so that the cookie is set on the client for the current request.
        """
        self.modified = True

    def save(self, must_create=False):
        """
        To save, we get the session key as a securely signed string and then
        set the modified flag so that the cookie is set on the client for the
        current request.
        """
        self._session_key = self._get_session_key()
        self.modified = True

    def exists(self, session_key=None):
        """
        This method makes sense when you're talking to a shared resource, but
        it doesn't matter when you're storing the information in the client's
        cookie.
        """
        return False

    def delete(self, session_key=None):
        """
        To delete, we clear the session key and the underlying data structure
        and set the modified flag so that the cookie is set on the client for
        the current request.
        """
        self._session_key = ''
        self._session_cache = {}
        self.modified = True

    def _validate_session_key(self, key):
        return key
