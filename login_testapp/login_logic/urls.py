from django.urls import path
from .views import LoginView,RegisterUserView,RetrieveUserView,DeleteUserView,VerifyTokenView,LogoutView,CustomTokenRefreshView,SocialLoginView

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'), #회원가입
    path('login/', LoginView.as_view(), name='login'), # 로그인
    path('social/login/', SocialLoginView.as_view(), name='login'), # 로그인
    path('logout/', LogoutView.as_view(), name='logout'), # 로그아웃
    path('user/', RetrieveUserView.as_view(), name='user'), # 회원 조회
    path('user/delete/', DeleteUserView.as_view(), name='delete_user'), # 회원 삭제
    path('token/verify/', VerifyTokenView.as_view(), name='verify_token'), # 토큰 검증
    path('token/', CustomTokenRefreshView.as_view(), name='token_obtain_pair'),  # 로그인 (JWT 토큰 발급)

    ]
