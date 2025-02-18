from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', "password",'name', 'nickname', 'role', 'birth', 'gender', 'contact', 'address', 'status', 'created_at', 'updated_at',"status")


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(email=data["email"], password=data["password"])
        if not user:
            raise serializers.ValidationError("이메일 또는 비밀번호가 올바르지 않습니다.")
        return user

class SocialLoginSerializer(serializers.Serializer):
    """
    소셜 로그인 Serializer
    """
    provider = serializers.ChoiceField(choices=["google", "kakao", "naver"])
    access_token = serializers.CharField()

    def validate(self, data):
        """
        provider와 access_token 유효성 검사
        """
        provider = data.get("provider")
        access_token = data.get("access_token")

        if not provider or not access_token:
            raise serializers.ValidationError("provider와 access_token이 필요합니다.")

        return data