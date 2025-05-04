document.addEventListener("DOMContentLoaded", function () {
    const entorno = document.body.dataset.entorno;
    let apiUrl = "";

    if (entorno === "local") {
        apiUrl = "http://localhost:8000/productos/api/";
    } else {
        apiUrl = "https://prueba-propia-ferremas-production.up.railway.app/productos/api/";
    }

    fetch(apiUrl)
        .then(response => {
            if (!response.ok) {
                throw new Error("Error al obtener los productos");
            }
            return response.json();
        })
        .then(productos => {
            const tabla = document.getElementById("tabla-productos");
            tabla.innerHTML = "";  // Limpiar

            productos.forEach(producto => {
                const fila = `
                    <tr>
                        <td>${producto.nombre}</td>
                        <td>$${producto.precio}</td>
                        <td>${producto.descripcion}</td>
                        <td>
                            <img src="${producto.imagen}" class="product-photo" 
                                 style="width: 80px; height: 80px; object-fit: cover; border-radius: 5px;">
                        </td>
                        <td>
                            <form action="/productos/eliminar/${producto.id}/" method="POST" style="display:inline;">
                                <input type="hidden" name="csrfmiddlewaretoken" value="${getCSRFToken()}">
                                <button type="submit" class="btn btn-danger btn-sm">
                                    <i class="fas fa-trash"></i> Eliminar
                                </button>
                            </form>
                            <a href="/productos/${producto.id}/" class="btn btn-warning btn-sm">
                                <i class="fas fa-pencil-alt"></i> Editar
                            </a>
                        </td>
                    </tr>
                `;
                tabla.insertAdjacentHTML("beforeend", fila);
            });
        })
        .catch(error => {
            console.error("Error:", error);
        });

    function getCSRFToken() {
        const cookies = document.cookie.split(";");
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split("=");
            if (name === "csrftoken") {
                return value;
            }
        }
        return "";
    }
});
