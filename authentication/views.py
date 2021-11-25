from django.shortcuts import render
# from django.contrib.auth.models import User
from rest_framework import routers, serializers, viewsets
from .serializers import UserSerializer, AuthTokenLoginSerializer, RegisterSerializer
from django.contrib.auth import get_user_model
from .helpers import LoginView as KnoxLoginView
from django.contrib.auth import login
from rest_framework import generics, status, views, permissions, mixins
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class LoginApiKnox(KnoxLoginView):
    """
    Login with time limit and token authentication.
    """
    permission_classes = (permissions.AllowAny, )

    def post(self, request, format=None):
        serializer = AuthTokenLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginApiKnox, self).post(request, format=None)


class RegisterView(generics.GenericAPIView):
    """
    Normal User Register with email verification.
    """

    serializer_class = RegisterSerializer
    # renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        user.is_active = True
        user.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LogoutAPIView(APIView):
    # serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)
    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)