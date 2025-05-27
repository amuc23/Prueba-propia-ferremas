from rest_framework import serializers
from .models import Venta, Detalle
from productos.models import Producto
from usuarios.models import Usuario

class UsuarioSerializer(serializers.ModelSerializer):
    class Meta:
        model = Usuario
        fields = ['id', 'username', 'first_name', 'last_name', 'rut']

class DetalleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Detalle
        fields = [
            'nombre_producto',
            'precio_unitario',
            'imagen_producto',
            'cantidad_producto',
            'subtotal_venta'
        ]

class VentaSerializer(serializers.ModelSerializer):
    detalles = serializers.SerializerMethodField()
    id_usuario = UsuarioSerializer()

    class Meta:
        model = Venta
        fields = [
            'id',
            'fecha_compra',
            'total_venta',
            'estado_venta',
            'tipo_entrega',
            'direccion_despacho',
            'estado_entrega',
            'webpay_transaction_id',
            'webpay_payment_status',
            'ultimos_digitos',
            'id_usuario',
            'detalles'
        ]

    def get_detalles(self, obj):
        detalles = Detalle.objects.filter(id_venta=obj)
        return DetalleSerializer(detalles, many=True).data
