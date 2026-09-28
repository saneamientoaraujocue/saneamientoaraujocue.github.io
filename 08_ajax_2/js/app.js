const URLBASE = "https://api.jikan.moe/v4/anime"
const btnBuscar = document.querySelector(".btn-buscador");
const inputBuscar= document.querySelector("#inp-buscador");
const secSinResultado = document.querySelector(".sin-resultados");
const secDefault = document.querySelector(".por-defecto");
const secResultados = document.querySelector(".contenedor-resultados");
const contCards = document.querySelector(".resultados");
const Card = secResultados.querySelector(".result-card").cloneNode(true);



let textoAbuscar ="";
let paginaActual = 1;



btnBuscar.addEventListener("click", prepararConsulta);

function prepararConsulta(){
    const texto = inputBuscar.value.trim();
    if (texto.length===0){
        mostrarDefault()
        return;
    }
    if (texto !== textoAbuscar){
      paginaActual = 1;
    }
    textoAbuscar = texto;
     const url = new URL(URLBASE);
    url.searchParams.append("q", textoAbuscar);
    url.searchParams.append("page", paginaActual);
    url.searchParams.append("limit", 12);
    consultarAPI(url.toString);
    
}

async function consultarAPI(url){
  try {
   
    const respuestaAPI = await fetch(url);
    const datos = await respuestaAPI.json
    const{ data } = datos;
    cargarPagina(datos);
    
  } catch (error) {
    console.error(error);
    mostrarDefault();
  }  
}

function cargarPagina(d){
    if (!d || d.length ===0) {
      mostrarSinResultado();
      return;
    }
    contCards.innerHTML = "";

    d.forEach(a => {
      const newCard = card.cloneNode(true);
      newCard.querySelector('img').src = a.images.jpg.image_url;
      newCard.querySelector('h4').innerText = a.title;
      newCard.querySelector('h5').innerText = a.studios[0].name ||'---';

      const metadatos = newCard.querySelectorAll('span');
      metadatos[0].innerText = a.year ||'---';
      metadatos[1].innerText = a.episodes ||'---';
      metadatos[0].innerText = a.genres [0]?.name ||'---';
      newCard.querySelector('a').href = a.url;
      newCard.querySelector('a').target = '_blank';


      contCards.append(newCard);
    });

    mostrarContenedorResultados();
}


function mostrarDefault(){
    secDefault.classList.remove("oculto");
    secSinResultado.classList.add("oculto");
    secResultados.classList.add("oculto");

}
function mostrarSinResultado(){
    secDefault.classList.add("oculto");
    secSinResultado.classList.remove("oculto");
    secResultados.classList.add("oculto");

}
function ContenedorResultado(){
    secDefault.classList.add("oculto");
    secSinResultado.classList.add("oculto");
    secResultados.classList.remove("oculto");

}