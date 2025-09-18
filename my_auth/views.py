from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import *


def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)  # type: ignore
    }


class UserRegistrationView(APIView):
    def post(self, request):
        ser = UserRegistrationSerializers(data=request.data)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response({
                "Registration Successfull"
            }, status=status.HTTP_201_CREATED)
        return Response(ser.errors ,status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        ser = UserLoginSerializers(data=request.data)
        if ser.is_valid(raise_exception=True):
            email = ser.validated_data.get('email')  # type: ignore
            password = ser.validated_data.get('password') # type: ignore
            user = authenticate(request, email=email, password=password)
            if user is not None:
                token = get_token_for_user(user)
                return Response({
                    "token": token,
                    "message": "successfully logged in "
                }, status=status.HTTP_200_OK)
            else :
                return Response({
                "error":"Invalid Email or password"
            },status=status.HTTP_404_NOT_FOUND)
        return Response(ser.error_messages,status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self , request):
        ser = UserProfileSerializers(request.user)
        return Response({
            "data":ser.data
        })


class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self , request):
        ser = UserChangePasswordSerializers(data = request.data, context={'user':request.user})        
        if ser.is_valid(raise_exception=True):
            
            return Response({"message":"password change successful"}, status=status.HTTP_200_OK)
        return Response(ser.errors,status=status.HTTP_400_BAD_REQUEST)
            


class UserResetPasswordEmailView(APIView):
    def post(self , request):
        ser = UserResetPasswordEmailSerializers(data = request.data)
        if ser.is_valid(raise_exception=True):
            return Response({'message':"Password reset link sent"}, status=status.HTTP_200_OK)
        return Response(ser.errors,status=status.HTTP_400_BAD_REQUEST)


class UserResetPasswordView(APIView):
    def post(self , request , uid , token):
        ser = UserResetPasswordSerializers(data = request.data, context={'uid':uid, 'token':token})
        if ser.is_valid(raise_exception=True):
            
            return Response({"message":"password changed successfully"}, status=status.HTTP_200_OK)
        return Response(ser.errors,status=status.HTTP_400_BAD_REQUEST)
             
