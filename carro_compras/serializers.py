from rest_framework import serializers
from .models import Venta, Detalle
from productos.models import Producto

class DetalleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Detalle
        fields = ['producto', 'cantidad_producto', 'subtotal_venta', 'id_venta']
        
    def validate_cantidad_producto(self, value):
        if value <= 0:
            raise serializers.ValidationError("La cantidad del producto debe ser mayor que 0.")
        return value

class VentaSerializer(serializers.ModelSerializer):
    detalles = DetalleSerializer(many=True)  # Incluir los detalles relacionados con la venta

    class Meta:
        model = Venta
        fields = ['id', 'fecha_compra', 'total_venta', 'estado_venta', 'id_usuario', 'detalles']

    def create(self, validated_data):
        detalles_data = validated_data.pop('detalles')
        venta = Venta.objects.create(**validated_data)
        for detalle_data in detalles_data:
            Detalle.objects.create(id_venta=venta, **detalle_data)
        return venta
