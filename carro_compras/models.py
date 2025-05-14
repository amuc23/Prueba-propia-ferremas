from django.db import models
from usuarios.models import Usuario
from productos.models import Producto

# Tabla Venta
class Venta(models.Model):
    # Campos
    fecha_compra = models.DateTimeField(null=True, blank=True)  # La fecha se establece cuando se confirma la compra
    total_venta = models.IntegerField()  # Total de la venta, en formato decimal
    estado_venta = models.CharField(max_length=100)
    id_usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='ventas')  # Relación con Usuario

    # Campos específicos para WebPay
    webpay_transaction_id = models.CharField(max_length=255, null=True, blank=True)  # ID de la transacción en WebPay
    webpay_payment_status = models.CharField(max_length=50, null=True, blank=True)  # Estado de la transacción (por ejemplo, 'completed', 'failed')
    
    def __str__(self):
        return f"{self.fecha_compra} | {self.total_venta} | {self.webpay_payment_status}"

# Tabla Detalle
class Detalle(models.Model):
    cantidad_producto = models.PositiveIntegerField()  # Cantidad de productos en el carrito
    subtotal_venta = models.IntegerField()  # Subtotal de la venta por producto
    id_venta = models.ForeignKey(Venta, on_delete=models.CASCADE, related_name='detalles')  # Relación con Venta
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE, related_name='detalles')  # Relación con Producto

    def __str__(self):
        return f"{self.id_venta} | {self.producto.nombre} | {self.cantidad_producto} | {self.subtotal_venta}"

    def save(self, *args, **kwargs):
        # Calcular el subtotal de la venta al momento de guardarlo
        self.subtotal_venta = self.producto.precio * self.cantidad_producto
        super().save(*args, **kwargs)  # Llamamos al método save del padre


