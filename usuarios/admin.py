from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Usuario

class UsuarioAdmin(UserAdmin):
    list_display = ('rut', 'username', 'email', 'first_name', 'last_name', 'telefono', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('rut', 'username', 'first_name', 'last_name', 'email')
    ordering = ('rut',)
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Información Personal', {'fields': ('rut', 'first_name', 'last_name', 'email', 'telefono')}),
        ('Permisos', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Fechas importantes', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('rut', 'username', 'first_name', 'last_name', 'email', 'telefono', 'password1', 'password2'),
        }),
    )

admin.site.register(Usuario, UsuarioAdmin)