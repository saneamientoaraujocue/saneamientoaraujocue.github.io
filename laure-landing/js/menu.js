// ============================================
// PESTAÑAS DEL MENÚ (mostrar una categoría a la vez)
// Este archivo se usa solo en menu.html
// ============================================
const botonesTab = document.querySelectorAll(".tab-btn");
const categoriasMenu = document.querySelectorAll(".menu-categoria");

for (let i = 0; i < botonesTab.length; i++) {
  botonesTab[i].addEventListener("click", function () {
    const categoriaElegida = this.getAttribute("data-cat");

    // Quitamos "activo" de todos los botones y se lo ponemos solo al elegido
    for (let j = 0; j < botonesTab.length; j++) {
      botonesTab[j].classList.remove("activo");
    }
    this.classList.add("activo");

    // Mostramos solo la categoría que corresponde
    for (let k = 0; k < categoriasMenu.length; k++) {
      if (categoriasMenu[k].id === "cat-" + categoriaElegida) {
        categoriasMenu[k].classList.remove("oculto");
      } else {
        categoriasMenu[k].classList.add("oculto");
      }
    }
  });
}
