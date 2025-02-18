from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.views import TokenRefreshView
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
import jwt

from .authentication import OAuth2Authentication
from .serializers import UserSerializer, LoginSerializer

User = get_user_model()

# 🔹 회원가입 (이메일 인증 없음)
class RegisterUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "회원가입 성공."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 🔹 로그인 (이메일 + 비밀번호)
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            if user.status != 'active':
                return Response({"error": "비활성화된 계정입니다. 관리자에게 문의하세요."}, status=status.HTTP_403_FORBIDDEN)

            refresh = RefreshToken.for_user(user)
            update_last_login(None, user)
            return Response({
                "user": UserSerializer(user).data,
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 🔹 소셜 로그인
class SocialLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        provider = request.data.get("provider")  # "google", "kakao", "naver"
        access_token = request.data.get("access_token")

        if not provider or not access_token:
            return Response({"error": "provider와 access_token이 필요합니다."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            auth_result = OAuth2Authentication.authenticate(provider, access_token)
            return Response({
                "user": UserSerializer(auth_result["user"]).data,
                "refresh": auth_result["refresh"],
                "access": auth_result["access"],
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# 🔹 토큰 검증 (JWT 토큰 유효성 확인)
class VerifyTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            token = request.auth  # 현재 인증된 토큰 가져오기
            decoded_token = jwt.decode(str(token), settings.SIMPLE_JWT['SIGNING_KEY'], algorithms=["HS256"])
            exp = decoded_token.get("exp")

            return Response({
                "message": "토큰이 유효합니다.",
                "exp": exp  # 만료 시간 반환
            }, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({"error": "토큰이 만료되었습니다."}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"error": "유효하지 않은 토큰입니다."}, status=status.HTTP_401_UNAUTHORIZED)


# 🔹 비밀번호 변경
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not user.check_password(old_password):
            return Response({"error": "현재 비밀번호가 올바르지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"message": "비밀번호가 변경되었습니다."}, status=status.HTTP_200_OK)


# 🔹 회원 조회 (현재 로그인한 사용자 정보 반환)
class RetrieveUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# 🔹 회원 삭제 (회원 탈퇴)
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "계정이 삭제되었습니다."}, status=status.HTTP_204_NO_CONTENT)


# 🔹 로그아웃 (JWT 토큰 블랙리스트 등록)
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]  # 요청에서 리프레시 토큰 가져오기
            token = RefreshToken(refresh_token)
            token.blacklist()  # 블랙리스트에 추가

            return Response({"message": "로그아웃 성공"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": "토큰이 유효하지 않거나 이미 로그아웃됨"}, status=status.HTTP_400_BAD_REQUEST)


# 🔹 토큰 갱신 (Refresh Token을 사용하여 새로운 Access Token 발급)
class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        return Response({
            "access": response.data['access'],
            "refresh": response.data['refresh'],
            "message": "토큰 갱신 성공"
        }, status=status.HTTP_200_OK)
