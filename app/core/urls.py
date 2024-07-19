from rest_framework.routers import SimpleRouter

from core.views import AuthViewSet, UserViewSet, CategoryViewSet, ProductViewSet, OrderViewSet
users_router = SimpleRouter()

users_router.register(r'auth', AuthViewSet, basename="auth")
users_router.register(r'users', UserViewSet, )
users_router.register(r'categories', CategoryViewSet, )
users_router.register(r'products', ProductViewSet, )
users_router.register(r'orders', OrderViewSet, )