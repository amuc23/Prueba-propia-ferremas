from rest_framework import serializers
from .models import Producto, HistorialPrecio

class ProductoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Producto
        fields = '__all__'

class HistorialPrecioSerializer(serializers.ModelSerializer):
    class Meta:
        model = HistorialPrecio
        fields = '__all__'