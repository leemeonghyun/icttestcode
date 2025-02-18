"""
Django settings for config project.

Generated by 'django-admin startproject' using Django 5.1.4.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

from pathlib import Path
from decouple import config
from datetime import timedelta
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-c##rjie=j1)4(@54lk+0+bcf*-sclm($)b@98q=d81!0q(rqlo'

# SECURITY WARNING: don't run with debug turned on in production!
#개발시는 아래 두 줄 주석 해제
DEBUG = True
ALLOWED_HOSTS=[]
#배포시는 아래 두줄 주석 해제(배포용으로 변경 후에는 더 이상 개발서버(8000)에서는 서비스가 불가)
#DEBUG = False
#웹 서버릐 주소 지정
#예:nginx의 conf/nginx.conf파일의
#server_name에 설정한 값을 지정 한다
#ALLOWED_HOSTS = ['127.0.0.1','localhost']#로컬에서 개발시


# Application definition
INSTALLED_APPS = [
    'django.contrib.sites',  # 사이트 ID를 관리하기 위한 필수 설정
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',# Django REST Framework 추가
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',  # 블랙리스트 활성화
    "corsheaders",#CORS 에러 처리용
    'rest_framework.authtoken',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',  # 구글 소셜 로그인 추가
    'allauth.socialaccount.providers.kakao',   # 카카오 소셜 로그인 추가
    'allauth.socialaccount.providers.facebook',  # 페이스북 소셜 로그인 추가
    'dj_rest_auth',
    'dj_rest_auth.registration',
    'social_django',
    'login_logic', # 로그인 앱 추가
]



MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # CORS용 미들웨어 최상단에 추가
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',  # Django Allauth 필수 미들웨어
]
#CORS처리용
CORS_ALLOW_ALL_ORIGINS = True

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],  # 템플릿 경로 설정
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.oracle',
        'NAME': config('NAME'),  # 서비스 이름 또는 SID
        'USER': config('USER'),
        'PASSWORD': config('PASSWORD'),
        'HOST': config('HOST'),
        'PORT': config('PORT'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'ko-kr'

TIME_ZONE = 'Asia/Seoul'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 소셜 로그인 환경변수 설정
SOCIAL_AUTH_GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")
SOCIAL_AUTH_GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET")

SOCIAL_AUTH_KAKAO_REST_API_KEY = config("KAKAO_REST_API_KEY")

SOCIAL_AUTH_NAVER_CLIENT_ID = config("NAVER_CLIENT_ID")
SOCIAL_AUTH_NAVER_CLIENT_SECRET = config("NAVER_CLIENT_SECRET")


# JWT 설정
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}


# REST_FRAMEWORK = {
#     'DEFAULT_AUTHENTICATION_CLASSES': (
#         'rest_framework.authentication.SessionAuthentication',
#         'rest_framework.authentication.TokenAuthentication',
#     ),
# }


SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),  #  Access Token 유효 시간 (30분)
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),  #  Refresh Token 유효 시간 (7일)
    'ROTATE_REFRESH_TOKENS': True,  #  Refresh Token을 사용할 때 새로 발급
    'BLACKLIST_AFTER_ROTATION': True,  #  기존 Refresh Token을 블랙리스트 처리
    'ALGORITHM': 'HS256',  #  JWT 암호화 알고리즘
    'SIGNING_KEY': 'your_secret_key',  #  JWT 서명 키 (환경 변수 사용 권장)
    'AUTH_HEADER_TYPES': ('Bearer',),  # "Bearer {토큰}" 형식으로 인증
}


SITE_ID = 1
