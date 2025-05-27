document.addEventListener("DOMContentLoaded", function () {
    const entorno = document.body.dataset.entorno;
    let apiUrl = "";

    if (entorno === "local") {
        apiUrl = "http://localhost:8000/productos/api/";
    } else {
        apiUrl = "https://prueba-propia-ferremas-production.up.railway.app/productos/api/";
    }

    // Cargar productos al iniciar
    fetch(apiUrl)
        .then(response => {
            if (!response.ok) {
                throw new Error("Error al obtener los productos");
            }
            return response.json();
        })
        .then(productos => {
            const tabla = document.getElementById("tabla-productos");
            tabla.innerHTML = "";  // Limpiar la tabla antes de insertar

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
                            <button onclick="eliminarProducto(${producto.id})" class="btn btn-danger btn-sm">
                                <i class="fas fa-trash"></i> Eliminar
                            </button>
                            <a href="/productos/editar/${producto.id}/" class="btn btn-warning btn-sm">
    <i class="fas fa-pencil-alt"></i> Editar
</a>

                        </td>
                    </tr>
                `;
                tabla.insertAdjacentHTML("beforeend", fila);
            });
        })
        .catch(error => {
            console.error("Error al cargar los productos:", error);
        });



    // Función global para eliminar producto
    window.eliminarProducto = function (id) {
        if (!confirm("¿Estás seguro de que quieres eliminar este producto?")) return;

        let deleteUrl = "";

        if (entorno === "local") {
            deleteUrl = `http://localhost:8000/productos/api/eliminar/${id}/`;
        } else {
            deleteUrl = `https://prueba-propia-ferremas-production.up.railway.app/productos/api/eliminar/${id}/`;
        }

        fetch(deleteUrl, {
            method: "DELETE",
            headers: {}  // CSRF desactivado en modo local
        })
        .then(response => {
            if (response.status === 204) {
                alert("Producto eliminado correctamente");
                location.reload();
            } else {
                return response.json().then(data => {
                    alert("Error al eliminar: " + (data.error || "Error desconocido"));
                });
            }
        })
        .catch(error => {
            console.error("Error al eliminar producto:", error);
        });
    };

   // === LÓGICA PARA EDITAR PRODUCTO DESDE editar_producto.html ===
const formEditar = document.getElementById("form-editar");

if (formEditar) {
    formEditar.addEventListener("submit", function (e) {
        e.preventDefault();

        const productoId = formEditar.dataset.productoId;
        const entorno = document.body.dataset.entorno;

        const apiEditarUrl = entorno === "local"
            ? `http://localhost:8000/productos/api/editar/${productoId}/`
            : `https://prueba-propia-ferremas-production.up.railway.app/productos/api/editar/${productoId}/`;

        const data = {
            nombre: document.getElementById("nombre").value,
            precio: document.getElementById("precio").value,
            descripcion: document.getElementById("descripcion").value,
            imagen: document.getElementById("imagen").value
        };

        fetch(apiEditarUrl, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        })
        .then(res => {
            if (res.ok) {
                alert("Producto actualizado correctamente");
                window.location.href = "/productos/crud/";
            } else {
                return res.json().then(err => {
                    alert("Error al actualizar: " + JSON.stringify(err));
                });
            }
        })
        .catch(error => {
            console.error("Error al actualizar producto:", error);
        });
    });
}





    
});
