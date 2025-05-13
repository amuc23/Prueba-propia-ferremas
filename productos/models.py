from django.db import models

class Producto(models.Model):
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField()
    precio = models.IntegerField()
    imagen = models.URLField(max_length=500, blank=True)
    stock = models.PositiveIntegerField(default=0)
    categoria = models.CharField(max_length=100, default="General")
    activo = models.BooleanField(default=True)  # 🔹 nuevo campo

    def __str__(self):
        return self.nombre

    
class HistorialPrecio(models.Model):
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE, related_name='historial_precios')
    precio_anterior = models.IntegerField()
    precio_nuevo = models.IntegerField()
    fecha = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.producto.nombre} | {self.precio_anterior} → {self.precio_nuevo}"