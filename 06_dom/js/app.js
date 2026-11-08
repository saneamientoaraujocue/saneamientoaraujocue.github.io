const inpv1 = document.getElementById("v1");

const inpv2 = document.getElementById("v2");

const boton = document.querySelector('input[type ="submit"]');
const parrafo = document.querySelector('p')
//boton.value = "Ejecutarse"
boton.addEventListener("click", sumar)

function sumar (evento){
    evento.preventDefault();

    const valor1 = inpv1.value;
    
    const valor2 = inpv2.value;

    const resultado =Number(valor1)+Number(valor2);

    console.log('El valor del input 1 es :'+ valor1);
    
    console.log('El valor del input 2 es :'+ valor2);
    
    console.log('El resultado es :'+ resultado);
    parrafo.innerText = 'El resultado es :'+ resultado;
   
}

