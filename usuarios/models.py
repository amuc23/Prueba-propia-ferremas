from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator

class Usuario(AbstractUser):
    # Heredamos de AbstractUser que ya tiene campos como username, first_name, last_name, email, password, etc.
    
    # Añadimos campos adicionales
    rut = models.CharField(
        max_length=12,
        unique=True,
        validators=[
            RegexValidator(
                regex=r'^\d{7,8}-[\dkK]$',
                message='El RUT debe tener el formato 12345678-9'
            )
        ],
        verbose_name='RUT'
    )
    telefono = models.CharField(
        max_length=15,
        validators=[
            RegexValidator(
                regex=r'^\+?\d{9,15}$',
                message='El teléfono debe tener entre 9 y 15 dígitos'
            )
        ],
        verbose_name='Teléfono'
    )
    
    # Campos requeridos
    REQUIRED_FIELDS = ['rut', 'email', 'telefono']
    
    def __str__(self):
        return f"{self.get_full_name()} ({self.rut})"

    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'