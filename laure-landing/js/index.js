// ============================================
// GALERÍA CON LIGHTBOX (ampliar foto al hacer click)
// Este archivo se usa solo en index.html
// ============================================
const fotosGaleria = document.querySelectorAll(".foto-galeria");
const lightbox = document.getElementById("lightbox");
const imagenLightbox = document.getElementById("imagenLightbox");
const cerrarLightbox = document.getElementById("cerrarLightbox");

for (let i = 0; i < fotosGaleria.length; i++) {
  fotosGaleria[i].addEventListener("click", function () {
    imagenLightbox.src = this.src;
    imagenLightbox.alt = this.alt;
    lightbox.classList.add("activo");
  });
}

cerrarLightbox.addEventListener("click", function () {
  lightbox.classList.remove("activo");
});

// También se cierra si el usuario hace click fuera de la imagen
lightbox.addEventListener("click", function (evento) {
  if (evento.target === lightbox) {
    lightbox.classList.remove("activo");
  }
});


// ============================================
// FORMULARIO DE CONTACTO -> ENVÍA POR WHATSAPP
// ============================================
// En vez de mandar el formulario a un servidor, armamos un mensaje
// con lo que la persona completó y abrimos WhatsApp con ese texto ya escrito.
const formContacto = document.getElementById("formContacto");
const mensajeEnviado = document.getElementById("mensajeEnviado");

const numeroWhatsapp = "595984033698";

formContacto.addEventListener("submit", function (evento) {
  evento.preventDefault();

  const nombre = document.getElementById("nombre").value;
  const motivo = document.getElementById("motivo").value;
  const mensaje = document.getElementById("mensaje").value;

  // Armamos el texto que va a aparecer ya escrito en WhatsApp
  const textoWhatsapp =
    "Hola Laure Resto Bar! Soy " + nombre +
    ". Motivo: " + motivo +
    ". " + mensaje;

  const link = "https://wa.me/" + numeroWhatsapp + "?text=" + encodeURIComponent(textoWhatsapp);

  // Abrimos WhatsApp en una pestaña nueva
  window.open(link, "_blank");

  mensajeEnviado.textContent = "¡Listo! Te abrimos WhatsApp con tu mensaje, solo tenés que enviarlo.";

  formContacto.reset();

  setTimeout(function () {
    mensajeEnviado.textContent = "";
  }, 6000);
});
