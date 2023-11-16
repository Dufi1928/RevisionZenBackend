from django.urls import path
from .views import Register, Login, GetUsersNotif, CheckIfUserExist, UserDetail, checkLoginView, UserView, LogoutView, SocialLogin

urlpatterns = [
    path('auth/register', Register.as_view()),
    path('auth/login', Login.as_view()),
    path('user', UserView.as_view()),
    path('auth/logout', LogoutView.as_view()),
    path('auth/google-login', SocialLogin.as_view()),
    path('auth/facebook-login', SocialLogin.as_view()),
    path('checkLoginView', checkLoginView.as_view()),
    path('checkLoginView', checkLoginView.as_view()),
    path('CheckIfUserExist', CheckIfUserExist.as_view()),
    path('user-detail/<int:user_id>', UserDetail.as_view()),
    path('pseudos', GetUsersNotif.as_view()),
]
