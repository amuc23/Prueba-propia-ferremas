from django.urls import path
from . import views

urlpatterns = [
    path('', views.lista_productos, name='lista_productos'),         # vista HTML
    path('api/', views.api_lista_productos, name='api_lista_productos'),  # vista API JSON
]
