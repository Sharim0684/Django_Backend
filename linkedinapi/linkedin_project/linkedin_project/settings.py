import os
from pathlib import Path
from dotenv import load_dotenv  # Load environment variables from .env file

load_dotenv()  # Load environment variables

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key secret!
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "your-default-secret-key")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DJANGO_DEBUG", "True") == "True"

ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "").split(",")

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "linkedin_auth",
    "linkedin_api",
    "rest_framework",
    'corsheaders', 
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    'django.middleware.csrf.CsrfViewMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
CORS_ALLOW_ALL_ORIGINS = True
ROOT_URLCONF = "linkedin_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "linkedin_project.wsgi.application"

# Database configuration
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Localization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = "static/"

# LinkedIn OAuth Credentials (From Environment Variables)
SOCIAL_AUTH_LINKEDIN_OAUTH2_KEY = os.getenv("LINKEDIN_CLIENT_ID")
SOCIAL_AUTH_LINKEDIN_OAUTH2_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
SOCIAL_AUTH_LINKEDIN_OAUTH2_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI", "http://127.0.0.1:8000/linkedin_auth/callback/")
SOCIAL_AUTH_LINKEDIN_OAUTH2_SCOPE = ['openid', 'profile', 'w_member_social', 'email']

# Default primary key field type
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# settings.py
CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:8000"]

CSRF_COOKIE_SECURE = False  # Disable for testing


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
}


LINKEDIN_CLIENT_ID="86embapip2hnsy"
LINKEDIN_CLIENT_SECRET="WPL_AP1.UzATRB3rCrM44AYA.4sGm2g=="
LINKEDIN_REDIRECT_URI="http://127.0.0.1:8000/api/linkedin_auth/callback/"
