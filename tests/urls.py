import json

from django.conf.urls import url
from django.http import HttpResponse
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

try:
    from rest_framework_oauth.authentication import OAuth2Authentication
except ImportError:
    try:
        from rest_framework.authentication import OAuth2Authentication
    except ImportError:
        OAuth2Authentication = None

from rest_framework_jwt import views
from rest_framework_jwt.authentication import JSONWebTokenAuthentication


class MockView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return HttpResponse('mockview-get')

    def post(self, request):
        return HttpResponse('mockview-post')


class MockSessionView(MockView):
    permission_classes = (permissions.AllowAny,)
    session_key = 'mock_id'

    def get(self, request):
        return Response({self.session_key: request.jwt_session.get(self.session_key)})

    def post(self, request):
        request.jwt_session[self.session_key] = request.data.get(self.session_key, 123)
        return Response({self.session_key: request.jwt_session.get(self.session_key)})


urlpatterns = [
    url(r'^auth-token/$', views.obtain_jwt_token),
    url(r'^auth-token-refresh/$', views.refresh_jwt_token),
    url(r'^auth-token-verify/$', views.verify_jwt_token),

    url(r'^jwt/$', MockView.as_view(
        authentication_classes=[JSONWebTokenAuthentication])),
    url(r'^jwt-oauth2/$', MockView.as_view(
        authentication_classes=[
            JSONWebTokenAuthentication, OAuth2Authentication])),
    url(r'^oauth2-jwt/$', MockView.as_view(
        authentication_classes=[
            OAuth2Authentication, JSONWebTokenAuthentication])),

    url(r'^jwt/session/$', MockSessionView.as_view(
        authentication_classes=[JSONWebTokenAuthentication])),
]
