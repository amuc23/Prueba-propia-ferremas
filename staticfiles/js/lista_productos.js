document.addEventListener("DOMContentLoaded", function () {
    const entorno = document.body.dataset.entorno;
    let apiUrl = "";

    if (entorno === "local") {
        apiUrl = "http://localhost:8000/productos/api/";
    } else {
        apiUrl = "https://prueba-propia-ferremas-production.up.railway.app/productos/api/";
    }

    // Obtener el contenedor donde se van a agregar los productos
    const productList = document.getElementById('product-list');

    // Solicitar productos con nocache para forzar datos actualizados
    fetch(apiUrl + '?nocache=' + new Date().getTime())
        .then(response => response.json())
        .then(productos => {
            productList.innerHTML = "";  // Limpiar antes de insertar

            productos.forEach(producto => {
                const productoHTML = `
                    <div class="col-md-4">
                        <div class="card product-card h-100">
                            <img src="${producto.imagen}" class="card-img-top product-img" alt="${producto.nombre}">
                            <div class="card-body product-card-body">
                                <h5 class="card-title">${producto.nombre}</h5>
                                <p class="card-text">$${producto.precio}</p>
                                <p class="card-text"><small class="text-muted">${producto.categoria}</small></p>
                                <p class="product-stock">Stock disponible: ${producto.stock}</p>
                                <a href="/productos/${producto.id}/" class="btn btn-primary mb-2">Ver Producto</a>
                                <a href="#" class="btn btn-comprar" onclick="alert('Producto agregado al carrito! ID del producto: ${producto.id}')">Agregar al Carrito</a>
                            </div>
                        </div>
                    </div>
                `;
                productList.innerHTML += productoHTML;
            });
        })
        .catch(error => {
            console.error("Error al cargar los productos:", error);
        });
});
