from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

Usuario = get_user_model()

class UsuarioSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, required=False, style={'input_type': 'password'})
    is_staff = serializers.BooleanField(required=False)

    class Meta:
        model = Usuario
        fields = [
            'rut', 'username', 'first_name', 'last_name',
            'email', 'telefono', 'is_staff', 'password', 'password2'
        ]
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True},
        }

    def validate(self, data):
        # Validar solo si están presentes
        if 'password' in data and 'password2' in data:
            if data['password'] != data['password2']:
                raise serializers.ValidationError({"password": "Las contraseñas no coinciden."})

        if 'email' in data:
            try:
                validate_email(data['email'])
            except ValidationError:
                raise serializers.ValidationError({"email": "Ingrese un correo electrónico válido."})

        return data

    def create(self, validated_data):
        validated_data.pop('password2', None)
        validated_data['is_active'] = True
        return Usuario.objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        validated_data.pop('password2', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()
        return instance


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            data['user'] = user
            return data
        raise serializers.ValidationError("Credenciales inválidas o cuenta inactiva")


class UsuarioListaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Usuario
        fields = [
            'id', 'rut', 'username', 'first_name', 'last_name',
            'email', 'telefono', 'is_staff', 'is_active'
        ]
