//declaracion de constantes
const URL = 'https://davidruizdiaz.github.io/libros/';
const btn = document.getElementById('btn-datos');
const contenedor = document.querySelector('section')

//asignacion de evento al boton 
btn.addEventListener('click' , traerDatos);


//funcion que se ejecutara al hacer click al boton 
 async function traerDatos(){
    console.log('Probandoo....');
    try {
        const respuesta = await fetch(URL);
        if(!respuesta.ok) throw new Error ('Respuesta fallida');
        const datos = await respuesta.json();
        mostrarDatos(datos);
    } catch (error) {
       console.error('Error:', error);
    }
    
}

function mostrarDatos(libros){
contenedor.innerHTML = '';
for(let c = 0; c < libros.length; c++){
    const tempLibro = `<div class="panel panel-default">
        <div class="panel-body">
          <div class="media-left media-middle">
            <img class="media-object img-rounded" src="${libros[c].portada}">
          </div>
          <div class="media-body">
            <h3></h3>
            <div>
              <strong>Año:</strong>
              <span class="anho">${libros[c].anho}</span>
            </div>
            <div>
              <strong>Género:</strong>
              <spani class="genero">${libros[c].temas}</span>
            </div>
            <div>
              <strong>Autor:</strong>
              <span class="autor">${libros[c].autor.nombre}</span>
            </div>
            <div>
              <strong>Resumen:</strong>
              <span class="resumen">Sit hic nostrum molestias ad soluta. Iusto iste itaque soluta distinctio ad quaerat
                Et sint perspiciatis optio illo culpa Est obcaecati itaque quas error eos, debitis enim, modi voluptate
                Dolor!</span>
            </div>
          </div>
        </div>
      </div>` ;
    console.log(libros[c]);
    contenedor.innerHTML += tempLibro;
}

}