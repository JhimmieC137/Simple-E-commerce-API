from rest_framework.routers import SimpleRouter

from core.views import UserViewSet, AuthViewSet
users_router = SimpleRouter()

users_router.register(r'auth', AuthViewSet, basename="auth")
users_router.register(r'users', UserViewSet)