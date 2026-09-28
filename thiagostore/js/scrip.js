document.addEventListener('DOMContentLoaded', () => {

    // --- 1. NAVEGACIÓN DINÁMICA (SIN SCROLL) ---
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.section');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();

            const targetId = link.getAttribute('href').slice(1);

            // Activar link
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            // Ocultar todas las secciones
            sections.forEach(section => section.classList.remove('active'));

            // Mostrar la sección seleccionada
            const targetSection = document.getElementById(targetId);
            if (targetSection) {
                targetSection.classList.add('active');
            }
        });
    });


    // --- 2. BOTÓN "VER PRODUCTOS" (CTA) ---
    const ctaButton = document.querySelector('.cta-button');

    if (ctaButton) {
        ctaButton.addEventListener('click', (e) => {
            e.preventDefault();

            // Activar nav Productos
            navLinks.forEach(l => l.classList.remove('active'));
            document.querySelector('a[href="#products"]').classList.add('active');

            // Mostrar productos
            sections.forEach(section => section.classList.remove('active'));
            document.getElementById('products').classList.add('active');
        });
    }


    // --- 3. LÓGICA DEL CARRITO ---
    const addToCartButtons = document.querySelectorAll('.btn-add-cart');

    addToCartButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            e.preventDefault();

            const productCard = e.target.closest('.product-card');
            const productName = productCard.querySelector('h3').innerText;

            showNotification(`"${productName}" se ha añadido al carrito.`);
        });
    });


    // --- 4. NOTIFICACIONES (TOAST) ---
    function showNotification(message) {
        const notification = document.createElement('div');
        notification.classList.add('notification');
        notification.innerText = message;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.classList.add('show');
        }, 10);

        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 500);
        }, 3000);
    }

});