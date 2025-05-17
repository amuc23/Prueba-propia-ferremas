from django.db import models
from usuarios.models import Usuario
from productos.models import Producto
from django.contrib.auth import get_user_model

Usuario = get_user_model()

class Venta(models.Model):
    ESTADO_VENTA_CHOICES = [
        ('carrito', 'Carrito'),
        ('pagado', 'Pagado'),
    ]

    id_usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    fecha_compra = models.DateTimeField(null=True, blank=True)
    total_venta = models.IntegerField(default=0)
    estado_venta = models.CharField(max_length=10, choices=ESTADO_VENTA_CHOICES, default='carrito')

    # WebPay
    webpay_transaction_id = models.CharField(max_length=100, blank=True, null=True)
    webpay_payment_status = models.CharField(max_length=50, blank=True, null=True)
    ultimos_digitos = models.CharField(max_length=4, blank=True, null=True)


    # Tipo de entrega: retiro o despacho
    tipo_entrega = models.CharField(
        max_length=10,
        choices=[('retiro', 'Retiro en tienda'), ('despacho', 'Despacho a domicilio')],
        default='retiro'
    )
    direccion_despacho = models.TextField(blank=True, null=True)

    # Estado de la entrega: pendiente o completado
    estado_entrega = models.CharField(
        max_length=20,
        choices=[('pendiente', 'Por entregar'), ('completado', 'Completado')],
        default='pendiente'
    )

    def __str__(self):
        return f"Venta {self.id} - {self.id_usuario.username}"
      # Campo de eliminación lógica
    eliminado = models.BooleanField(default=False)

    def __str__(self):
        return f"Venta {self.id} - {self.id_usuario.username}"
    
    
class Detalle(models.Model):
    cantidad_producto = models.PositiveIntegerField()
    subtotal_venta = models.IntegerField()
    id_venta = models.ForeignKey(Venta, on_delete=models.CASCADE, related_name='detalles')
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE, related_name='detalles')

    # Congelados al momento de la compra
    nombre_producto = models.CharField(max_length=200, default='Producto eliminado')
    precio_unitario = models.IntegerField(default=0)
    imagen_producto = models.URLField(max_length=500, blank=True, null=True)

    def __str__(self):
        return f"{self.id_venta} | {self.nombre_producto} | {self.cantidad_producto} | {self.subtotal_venta}"

    def save(self, *args, **kwargs):
        if not self.pk:
            self.nombre_producto = self.producto.nombre
            self.precio_unitario = self.producto.precio
            self.imagen_producto = self.producto.imagen
        self.subtotal_venta = self.precio_unitario * self.cantidad_producto
        super().save(*args, **kwargs)

