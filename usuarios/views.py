from django.shortcuts import render

# Create your views here.
def iniciosesion(request):
    return render(request, 'usuarios/iniciosesion.html')

def registro(request):
    return render(request, 'usuarios/registro.html')