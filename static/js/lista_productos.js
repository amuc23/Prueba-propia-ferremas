document.addEventListener("DOMContentLoaded", function () {
    const productList = document.getElementById("product-list");

    // Determinar el entorno
    const entorno = "local"; // Cambia esto según tu entorno, puedes hacerlo con Django template o usar un entorno dinámico

    const apiUrl = entorno === "local"
        ? "http://localhost:8000/productos/api/"
        : "https://prueba-propia-ferremas-production.up.railway.app/productos/api/";

    // Hacer la solicitud a la API
    fetch(apiUrl)
        .then(response => response.json())
        .then(productos => {
            productos.forEach(producto => {
                // Crear el HTML dinámico para cada producto
                const productoHTML = `
                    <div class="col-md-4">
                        <div class="card product-card h-100">
                            <img src="${producto.imagen}" class="card-img-top product-img" alt="${producto.nombre}">
                            <div class="card-body product-card-body">
                                <h5 class="card-title">${producto.nombre}</h5>
                                <p class="card-text">${producto.precio}</p>
                                <p class="card-text"><small class="text-muted">${producto.categoria}</small></p>
                                <p class="product-stock">Stock disponible: ${producto.stock}</p>
                                <a href="/productos/${producto.id}/" class="btn btn-primary mb-2">Ver Producto</a>
                                <a href="#" class="btn btn-comprar" onclick="alert('Producto agregado al carrito! ID del producto: ${producto.id}')">Agregar al Carrito</a>
                            </div>
                        </div>
                    </div>
                `;
                // Insertar el producto en el contenedor
                productList.innerHTML += productoHTML;
            });
        })
        .catch(error => {
            console.error("Error al cargar los productos:", error);
        });
});
