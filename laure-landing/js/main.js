// ============================================
// MENÚ HAMBURGUESA (celular)
// Este archivo se usa en TODAS las páginas del sitio
// ============================================
const menuToggle = document.getElementById("menuToggle");
const navMenu = document.getElementById("navMenu");

menuToggle.addEventListener("click", function () {
  navMenu.classList.toggle("abierto");
});

// Cerramos el menú cuando el usuario toca un link (mejor experiencia en celular)
const linksMenu = navMenu.querySelectorAll("a");
for (let i = 0; i < linksMenu.length; i++) {
  linksMenu[i].addEventListener("click", function () {
    navMenu.classList.remove("abierto");
  });
}


// ============================================
// BOTÓN "VOLVER ARRIBA"
// ============================================
const btnArriba = document.getElementById("btnArriba");

window.addEventListener("scroll", function () {
  if (window.scrollY > 400) {
    btnArriba.classList.add("visible");
  } else {
    btnArriba.classList.remove("visible");
  }
});

btnArriba.addEventListener("click", function () {
  window.scrollTo({ top: 0, behavior: "smooth" });
});
