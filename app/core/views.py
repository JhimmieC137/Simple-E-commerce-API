# Django Iports
from django.contrib.auth import login, logout, authenticate
from django.core.exceptions import ValidationError
from django.db.models import Q

# DRF Imports
from rest_framework import viewsets, mixins
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action

# Core Iports
from core.models import User
from core.serializers import *



class AuthViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    queryset = User.objects.all()
    serializers = {
        'default': UserSerializer,
        'register': CreateUserSerializer,
        'reset_password': ResetPasswordSerializer,
        'request_password_reset': RequestPasswordResetSerializer,
    }

    
    def get_queryset(self):                                      
        return super().get_queryset()
    
    def get_serializer_class(self):
        return self.serializers.get(self.action, self.serializers['default'])
    
    def create(self, request):
        """
        User registeration
        """
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({"message": "User created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return Response({'message': f'{e}'}, status=status.HTTP_400_BAD_REQUEST)
    
    
    @action(detail=False, methods = ['post'], url_path='request-password-reset', url_name='request-password-reset')
    def request_password_reset(self, request):
        """
        Send password reset link to user's mail 
        """
        try:
            user = self.queryset.filter(email = request.data['email']).exists()
            
            if user:
                ...
            
            else:
                return Response(f"User not found", status=status.HTTP_404_NOT_FOUND)
            
        
        except:
            return Response(f"Something went wrong", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    @action(detail=False, methods = ['post'], url_path='reset-password', url_name='reset-password')
    def reset_password(self, request):
        """
        User registeration
        """
        try:
            user = self.queryset.filter(email = request.data['email']).exists()
            
            if user:
                ...
            
            else:
                return Response(f"User not found", status=status.HTTP_404_NOT_FOUND)
            
        
        except:
            return Response(f"Something went wrong", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    @action(detail=False, methods = ['post'], url_path='login', url_name='login')
    def login_view(self, request):
        """
        User login 
        """
        
        try:
            user = self.queryset.filter(email = request.data['email']).exists()
            
            if user:
                user = authenticate(request, email=request.data['email'], password=request.data['password'])
                print(user)
                login(request, user)
                print(user)
                return Response('Logged in successfully', status=status.HTTP_200_OK)
            
            else:
                return Response(f"Invalid Credentials", status=status.HTTP_404_NOT_FOUND)
            
        
        except:
            return Response(f"Something went wrong", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        
    
    @action(detail=False, methods = ['get'], url_path='logout', url_name='logout')
    def logout_view(self, request):
        """
        User Logout
        """
        try:
            logout(request)
            return Response('Logged in successfully', status=status.HTTP_200_OK)
        except:
            return Response('Something went wrong', status=status.HTTP_200_OK)



class UserViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    Creates, Updates and Retrieves - User Accounts
    """
    parser_classes = (MultiPartParser, FormParser)
    queryset = User.objects.all()
    serializers = {
        'default': UserSerializer,
    }
    
    def get_queryset(self):                                      
        return super().get_queryset()
    
    def get_serializer_class(self):
        return self.serializers.get(self.action, self.serializers['default'])
    
    
    @action(detail=False, methods=['get'], url_path='me', url_name='me')
    def session(self, instance):
        """
        User in session
        """
        try:
            return Response(UserSerializer(self.request.user, context={'request': self.request}).data, status=status.HTTP_200_OK)
        except:
            return Response({'message': 'Wrong auth token'}, status=status.HTTP_400_BAD_REQUEST)
    
    
    def list(self, request):
        queryset = self.get_queryset()
        queryset = self.queryset.filter(
            Q(name__icontains = request.query_params.get('search') if request.query_params.get('search') else '') |
            Q(email__icontains = request.query_params.get('search') if request.query_params.get('search') else '')
        ).values()
        try:
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response({"message": "Users retrived successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    def retrieve(self, request):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response({"message":"User retrived successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except:
            return Response({"message": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        
        
    def perform_update(self, serializer):
        serializer.save()
        
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
        except:
            return Response({"message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)
        
        
        self.perform_update(serializer)
        return Response({"message": "User updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)