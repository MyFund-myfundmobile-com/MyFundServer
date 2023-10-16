"""
Django settings for myfundproject project.

Generated by 'django-admin startproject' using Django 4.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
from datetime import timedelta
import os
from channels_redis.core import RedisChannelLayer
import redis

# Set your OpenAI API key


SSL_PORT = 8443  # You can choose any available port number


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-rct_mdzr=x!99kwy+xy1$#x=5_+!_-dynu%z&!jx_-qkj7*%*%'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1', '192.168.159.34','192.168.226.34','localhost', '192.168.226.34', '192.168.176.34', '10.10.4.174', '192.168.84.34', '10.10.4.174' ]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'authentication',
    'corsheaders',
   # 'sslserver',
    'channels',
    'graphene_django'
   # 'django_socketio',

    ]


ASGI_APPLICATION = "myfundproject.routing.application"
ADMIN_URL = 'admin/'



# Celery settings
CELERY_BROKER_URL = 'redis://localhost:6379/0'  # Use the appropriate broker URL for your environment.
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'  # Use the appropriate result backend URL for your environment.
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'




REST_FRAMEWORK = {
    # Other settings...
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.TokenAuthentication',

    ],
    'DEFAULT_TOKEN_EXPIRE_TIME': 60 * 60 * 24,  # Default is 1 day in seconds
}


MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')


SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=365 * 24 * 60 *60),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
    'SLIDING_TOKEN_LIFETIME': timedelta(days=7),
}

SESSION_COOKIE_AGE = 365 * 24 * 60 * 60  # 1 year


MIDDLEWARE = [

    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
 #   "channels.middleware.WebSocketMiddleware",

]

CORS_ALLOW_ALL_ORIGINS = True

CORS_ALLOWED_ORIGINS = [
    'https://tolulopeahmed.github.io',
    'https://10.10.4.82:8443',
    'https://www.myfundmobile.com',  # Add your domain here
    'http://192.168.238.34:8000'
]


# Excluding CSRF middleware for password reset endpoints
CSRF_EXCLUDE_URLS = [
    '/api/request-password-reset/',
    '/api/reset-password/',
]

ROOT_URLCONF = 'myfundproject.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
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

WSGI_APPLICATION = 'myfundproject.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')


# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'authentication.CustomUser'

# EMAIL SETTINGS
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'myfundmobile.com'
EMAIL_PORT = 465
EMAIL_USE_SSL = True  # Use SSL for secure connection

# For SMTP authentication
EMAIL_HOST_USER = 'info@myfundmobile.com'
EMAIL_HOST_PASSWORD = 'Reproduce1..'

# Other settings
DEFAULT_FROM_EMAIL = 'MyFund <info@myfundmobile.com>'  # Set the default sender email address

APPEND_SLASH = True


# EMAIL TEMPLATES
EMAIL_TEMPLATES = {
    'password_reset': 'authentication/email_templates/password_reset_email.html',
}

AUTHENTICATION_BACKENDS = [
    'authentication.authentication_backends.EmailBackend',  # Replace 'path.to' with the actual path
    # ...
]

#Use myfundmobile.com cert and key here...
# SSL_KEY = os.path.join(BASE_DIR, 'key.pem')
# SSL_CERT = os.path.join(BASE_DIR, 'cert.pem')

# SSL settings
# HTTPS_SUPPORT = True
# if HTTPS_SUPPORT:
#     os.environ['HTTPS'] = "on"
#     os.environ['wsgi.url_scheme'] = 'https'
#     os.environ['DJANGO_SECURE_SSL_REDIRECT'] = 'True'
#     os.environ['SSL_CERT_FILE'] = SSL_CERT  # Set the SSL certificate file
#     os.environ['SSL_KEY_FILE'] = SSL_KEY    # Set the SSL key file


#Configure Django to use HTTPS by default
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
# SECURE_SSL_REDIRECT = True


# SECURE_HSTS_SECONDS = 31536000  # 1 year
# SECURE_HSTS_PRELOAD = True
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True