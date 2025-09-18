from django.urls import path
from .views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view()),
    path('login/', UserLoginView.as_view()),
    path('profile/', UserProfileView.as_view()),
    path('change-password/', UserChangePasswordView.as_view()),
    path('password-reset-mail/',UserResetPasswordEmailView.as_view() ),
    path('password-reset/<uid>/<token>/', UserResetPasswordView.as_view()),

]
