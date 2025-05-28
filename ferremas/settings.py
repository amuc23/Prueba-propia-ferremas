from pathlib import Path
import os
from dotenv import load_dotenv
load_dotenv()


# Configuración de las rutas dentro del proyecto. BASE_DIR es el directorio raíz.
BASE_DIR = Path(__file__).resolve().parent.parent

# Configuración de la clave secreta, no la dejes visible en producción.
SECRET_KEY = 'django-insecure-60gx)fedy5u0f!3tc7a*4y$xjmv+$4p2@!o)&r)82*3da!7(yl'

# Importante: pon DEBUG en False para producción.
DEBUG = False # Se pone True en desarrollo, y antes de subirlo SI O SI EN FALSE (producción)
#True deja ver los errores claramente / False cifra todo si es que algo falla 

# Define los dominios permitidos para producción (en este caso, el dominio de Railway)
ALLOWED_HOSTS = ['prueba-propia-ferremas-production.up.railway.app', '127.0.0.1', 'localhost']

# Aplicaciones de Django que estarán activas.
INSTALLED_APPS = [
    'django.contrib.admin',  # Panel de administración por defecto
    'django.contrib.auth',  # Autenticación de usuarios
    'django.contrib.contenttypes',  # Para manejar tipos de contenido
    'django.contrib.sessions',  # Para manejar sesiones de usuario
    'django.contrib.messages',  # Para manejar mensajes de usuario
    'django.contrib.staticfiles',  # Archivos estáticos (CSS, JS, imágenes)
    'home',  # Tu aplicación de inicio
    'rest_framework',  # Framework para APIs
    'rest_framework.authtoken',
    'productos',  # Aplicación de productos
    'corsheaders',  # Para evitar el bloqueo de peticiones a la API
    'usuarios',  # Aplicación de usuarios
    'carro_compras', # aplicacion de compras
]

# Middleware necesario para la seguridad, autenticación y manejo de sesiones.
MIDDLEWARE = [
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Para servir archivos estáticos en producción
    'corsheaders.middleware.CorsMiddleware',  # Para que no bloquee peticiones API
    'django.middleware.security.SecurityMiddleware',  # Middleware de seguridad
    'django.contrib.sessions.middleware.SessionMiddleware',  # Middleware de sesiones
    'django.middleware.common.CommonMiddleware',  # Middleware de funcionalidades comunes
    'django.middleware.csrf.CsrfViewMiddleware',  # Middleware de protección CSRF
    'django.contrib.auth.middleware.AuthenticationMiddleware',  # Middleware de autenticación
    'django.contrib.messages.middleware.MessageMiddleware',  # Middleware de mensajes
    'django.middleware.clickjacking.XFrameOptionsMiddleware',  # Middleware de protección contra clickjacking
]

# Configuración CORS (permite solicitudes desde otros dominios)
CORS_ALLOWED_ORIGINS = [
    "http://127.0.0.1:8000",  # Para desarrollo local
    "https://prueba-propia-ferremas-production.up.railway.app",  # Para producción en Railway
]

# Archivo de configuración para las URLs del proyecto.
ROOT_URLCONF = 'ferremas.urls'

# Configuración para los templates de Django
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',  # Usar DjangoTemplates para procesar HTML
        'DIRS': [os.path.join(BASE_DIR, 'home', 'templates')],  # Ruta de los templates (ajusta según tu estructura)
        'APP_DIRS': True,  # Django buscará automáticamente los templates en cada aplicación
        'OPTIONS': {
            'context_processors': [  # Procesadores de contexto para manejar datos en los templates
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# Configuración para el servidor WSGI (conexión entre Django y el servidor web).
WSGI_APPLICATION = 'ferremas.wsgi.application'

# Base de datos para el entorno de producción (usamos SQLite por ahora)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.getenv('MYSQLDATABASE'),
        'USER': os.getenv('MYSQLUSER'),
        'PASSWORD': os.getenv('MYSQLPASSWORD'),
        'HOST': os.getenv('MYSQLHOST'),
        'PORT': os.getenv('MYSQLPORT'),
    }
}

# Validación de contraseñas
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

# Configuración de internacionalización
LANGUAGE_CODE = 'es'  # Idioma por defecto (puedes cambiarlo a 'es' para español)

TIME_ZONE = 'America/Santiago'

USE_I18N = True  # Habilitar internacionalización

USE_TZ = True  # Habilitar el uso de zonas horarias

# Configuración para los archivos estáticos (CSS, JS, imágenes)
STATIC_URL = '/static/'  # URL para servir los archivos estáticos
STATIC_ROOT = BASE_DIR / 'staticfiles'  # Directorio donde se recopilarán los archivos estáticos en producción

# Directorios donde se encuentran los archivos estáticos
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),  # Ruta donde están tus archivos estáticos
]

# Para la carga de archivos estáticos en producción (cuando usas el servidor WhiteNoise)
WHITENOISE_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Tipo de campo por defecto para los identificadores de las tablas de la base de datos
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Configuración adicional para producción: asegurarse de que los formularios CSRF funcionen correctamente
CSRF_TRUSTED_ORIGINS = ['http://127.0.0.1:8000','https://prueba-propia-ferremas-production.up.railway.app']  # Agregar dominio de Railway

CORS_ALLOW_CREDENTIALS = True


# Configuración de los archivos multimedia (si es necesario para manejar archivos de imagen, etc.)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

#ENTORNO = 'local'
ENTORNO = 'produccion'

#cambiar de local a produccion antes de subir o al bajarlo para mantener conexion de la api

LOGIN_URL = '/usuarios/iniciosesion/'


AUTH_USER_MODEL = 'usuarios.Usuario'

# Configuración de Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',  # Permite autenticación con sesión (cookies)
        'rest_framework.authentication.TokenAuthentication',    # Opcional, para APIs que usen tokens
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny'  # Cambia a IsAuthenticated si quieres proteger todo por defecto
    ]
}

TRANSBANK = {
    'COMMERCE_CODE': '597055555532',
    'API_KEY': '597055555532',
    'ENVIRONMENT': 'TEST'
}




# No uses load_dotenv() en producción
if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv()

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True

EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = f"FERREMAS <{EMAIL_HOST_USER}>"




PASSWORD_RESET_TIMEOUT = 7200
