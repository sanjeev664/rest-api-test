from django.urls import path, include
from . import views
from rest_framework import routers
from rest_framework_simplejwt import views as jwt_views


# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)


urlpatterns = [
    path('', include(router.urls)),
    path('token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/login/', views.LoginApiKnox.as_view(), name='knoz_login'),
    path('auth/register/', views.RegisterView.as_view(), name="knoz_regsiter"),
]
