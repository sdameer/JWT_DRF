from rest_framework import serializers
from django.utils.http import urlsafe_base64_decode , urlsafe_base64_encode
from django.utils.encoding import smart_str , force_bytes , DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser


class UserRegistrationSerializers(serializers.ModelSerializer):

    password2 = serializers.CharField(
        write_only=True, style={"input_type": "password"})

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'password', 'password2']

    def validate(self, attrs):
        email = attrs.get('email')
        username = attrs.get('username')
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            raise serializers.ValidationError("Passwords does not match")

        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        return CustomUser.objects.create_user(**validated_data)  # type: ignore


class UserLoginSerializers(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(
        write_only=True, style={"input_type": "password"})
    

    class Meta:
        model = CustomUser
        fields = ['email', 'password']


class UserProfileSerializers(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'username']


class UserChangePasswordSerializers(serializers.ModelSerializer):

    password = serializers.CharField(
        write_only=True, style={"input_type": "password"})
    password2 = serializers.CharField(
        write_only=True, style={"input_type": "password"})

    class Meta:
        model = CustomUser
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")

        if password != password2:
            raise serializers.ValidationError("passwords does not match")

        user = self.context.get('user')
        
        user.set_password(password) # type: ignore
        user.save() # type: ignore
        return attrs

class UserResetPasswordEmailSerializers(serializers.ModelSerializer):
    
    email =  serializers.EmailField(write_only=True)
    class Meta :
        model = CustomUser
        fields = ['email']

    def validate(self , attrs):
        email = attrs.get('email')
        if CustomUser.objects.filter(email = email).exists():
            user = CustomUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id)) # type: ignore
            token = PasswordResetTokenGenerator().make_token(user)
            link = f'https://127.0.0.1:8000/auth/users/reset/{uid}/{token}/'   
            print(f"\n{'-'*30}\nLink to reset password : \n{link}\n{'-'*30}\n")   
            return attrs
        else : 
            raise serializers.ValidationError("E-Mail not registered")

        


class UserResetPasswordSerializers(serializers.Serializer):
    old_password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)    
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['old_password','password', 'password2']

    def validate(self, attrs):
        old_password = attrs.get('old_password')
        password = attrs.get('password')
        password2 = attrs.get('password2')
        
        
        if password != password2:
            raise serializers.ValidationError(
                'Password and confirm password doesnt match')
            
        # password len > 8 and [A-Z a-z 0-9]
        validate_password(password)
            
        uid = self.context.get('uid')
        token = self.context.get('token')
        try : 
            id = smart_str(urlsafe_base64_decode(uid))  # type: ignore
            user = CustomUser.objects.get(id=id)        
        except (DjangoUnicodeDecodeError, CustomUser.DoesNotExist):
            raise serializers.ValidationError('Token is not vallid or expired')
        
        if not PasswordResetTokenGenerator().check_token(user, token):
                    raise serializers.ValidationError(
                        'Token is not vallid or expired')
        
        user.set_password(password)  # type: ignore
        user.save()  # type: ignore
        return attrs

    
