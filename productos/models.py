from django.db import models

class Producto(models.Model):
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField()
    precio = models.IntegerField()  # Precio en pesos chilenos, sin decimales
    imagen = models.URLField(max_length=500, blank=True)
    stock = models.PositiveIntegerField(default=0)
    categoria = models.CharField(max_length=100, default="General")

    def __str__(self):
        return self.nombre
