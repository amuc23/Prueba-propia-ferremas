from django.db import models

class Producto(models.Model):
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField()
    precio = models.DecimalField(max_digits=10, decimal_places=2)
    imagen = models.URLField(max_length=500, blank=True)  # Usamos URL para simplificar
    stock = models.PositiveIntegerField(default=0)
    categoria = models.CharField(max_length=100, default="General")  # Opcional por ahora

    def __str__(self):
        return self.nombre
