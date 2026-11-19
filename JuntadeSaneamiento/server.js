const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
// Render está detrás de un proxy: así se obtiene la IP real de quien consulta
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());

// Configuración de conexión a Supabase (PostgreSQL)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Fecha de hoy (AAAA-MM-DD) en horario de Paraguay, porque Render trabaja en UTC
function hoyParaguay() {
    return new Date().toLocaleDateString('en-CA', { timeZone: 'America/Asuncion' });
}

// Verificación básica del servidor
app.get('/', (req, res) => {
    res.send('Servidor de la Junta de Saneamiento en funcionamiento');
});

// ==========================================
// 1. AUTENTICACIÓN / LOGIN DE ADMINISTRADOR
// ==========================================
// ------------------------------------------
// Sesión con token (JWT) y roles: 'admin' y 'lector'
// ------------------------------------------
const DURACION_TOKEN = { admin: '12h', lector: '30d' };

function secretoJWT() {
    return process.env.JWT_SECRET || '';
}
if (secretoJWT().length < 32) {
    console.error('⚠️  Falta la variable JWT_SECRET (mínimo 32 caracteres). Mientras no exista, nadie podrá iniciar sesión.');
}

function rolDe(u) {
    return u && u.rol ? u.rol : 'admin';
}

function datosPublicosUsuario(u) {
    return { id: u.id, usuario: u.usuario, nombre: u.nombre, rol: rolDe(u) };
}

function firmarToken(u) {
    return jwt.sign(
        { sub: u.id, usuario: u.usuario, rol: rolDe(u), tv: u.token_version || 0 },
        secretoJWT(),
        { algorithm: 'HS256', expiresIn: DURACION_TOKEN[rolDe(u)] || '12h' }
    );
}

// Middleware: exige un token válido y que la cuenta siga activa
async function autenticar(req, res, next) {
    try {
        if (secretoJWT().length < 32) {
            return res.status(503).json({ error: 'El servidor no está configurado todavía (falta JWT_SECRET).' });
        }
        const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
        if (!m) {
            return res.status(401).json({ error: 'Inicia sesión para continuar.' });
        }

        let payload;
        try {
            payload = jwt.verify(m[1], secretoJWT(), { algorithms: ['HS256'] });
        } catch (e) {
            return res.status(401).json({
                error: e.name === 'TokenExpiredError' ? 'Tu sesión expiró. Inicia sesión de nuevo.' : 'Sesión inválida. Inicia sesión de nuevo.'
            });
        }

        // Se consulta la cuenta en cada pedido: si se desactivó o cambió su contraseña, el token deja de servir
        const r = await pool.query('SELECT * FROM administradores WHERE id = $1', [payload.sub]);
        const u = r.rows[0];
        if (!u || u.activo === false || (u.token_version || 0) !== (payload.tv || 0)) {
            return res.status(401).json({ error: 'Sesión inválida. Inicia sesión de nuevo.' });
        }

        req.usuario = datosPublicosUsuario(u);
        next();
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

function soloRol(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.usuario.rol)) {
            return res.status(403).json({ error: 'No tienes permiso para esta acción.' });
        }
        next();
    };
}

const adminOnly = [autenticar, soloRol('admin')];

// ------------------------------------------
// Límite de intentos fallidos de login (por usuario+IP y por IP)
// ------------------------------------------
const VENTANA_INTENTOS_MS = 15 * 60 * 1000;
const MAX_INTENTOS_USUARIO = 8;
const MAX_INTENTOS_IP = 30;
const intentosFallidos = new Map();

function intentosRecientes(clave) {
    const ahora = Date.now();
    const lista = (intentosFallidos.get(clave) || []).filter(t => ahora - t < VENTANA_INTENTOS_MS);
    if (lista.length) intentosFallidos.set(clave, lista);
    else intentosFallidos.delete(clave);
    return lista;
}

function clavesLogin(req, usuario) {
    return [
        { clave: `${req.ip}|${String(usuario || '').toLowerCase().slice(0, 60)}`, max: MAX_INTENTOS_USUARIO },
        { clave: `${req.ip}|*`, max: MAX_INTENTOS_IP }
    ];
}

function segundosDeBloqueo(claves) {
    let espera = 0;
    for (const { clave, max } of claves) {
        const lista = intentosRecientes(clave);
        if (lista.length >= max) {
            espera = Math.max(espera, Math.max(1, Math.ceil((VENTANA_INTENTOS_MS - (Date.now() - lista[0])) / 1000)));
        }
    }
    return espera;
}

function registrarFallo(claves) {
    for (const { clave } of claves) {
        const lista = intentosRecientes(clave);
        lista.push(Date.now());
        intentosFallidos.set(clave, lista);
    }
}

setInterval(() => { for (const k of [...intentosFallidos.keys()]) intentosRecientes(k); }, 10 * 60 * 1000).unref();

// Compara la contraseña con el hash de bcrypt (o directo, si todavía está en texto plano)
async function verificarPassword(admin, password) {
    if (!admin || !admin.password_hash || typeof password !== 'string') return false;
    if (admin.password_hash.startsWith('$2')) {
        return bcrypt.compare(password, admin.password_hash);
    }
    return password === admin.password_hash;
}

// Para que tardar lo mismo cuando el usuario no existe (no revelar qué usuarios hay)
const HASH_FALSO = bcrypt.hashSync('contraseña-falsa', 10);

app.post('/api/admin/login', async (req, res) => {
    if (secretoJWT().length < 32) {
        return res.status(503).json({ error: 'El servidor no está configurado todavía (falta JWT_SECRET). Avisa al responsable del sistema.' });
    }

    const { usuario, password } = req.body || {};
    const claves = clavesLogin(req, usuario);

    const espera = segundosDeBloqueo(claves);
    if (espera > 0) {
        res.set('Retry-After', String(espera));
        return res.status(429).json({ error: `Demasiados intentos fallidos. Espera ${Math.ceil(espera / 60)} minuto(s) e inténtalo de nuevo.` });
    }

    try {
        let admin;
        if (typeof usuario === 'string') {
            const result = await pool.query('SELECT * FROM administradores WHERE usuario = $1', [usuario]);
            admin = result.rows[0];
        }

        const valida = admin
            ? await verificarPassword(admin, password)
            : (await bcrypt.compare(String(password || ''), HASH_FALSO), false);

        if (!valida) {
            registrarFallo(claves);
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }
        if (admin.activo === false) {
            return res.status(403).json({ error: 'Esta cuenta está desactivada. Consulta con el administrador.' });
        }

        // Acceso correcto: se limpian los intentos fallidos de este usuario
        intentosFallidos.delete(claves[0].clave);

        // Si la contraseña seguía guardada en texto plano, se guarda ya como hash
        if (!admin.password_hash.startsWith('$2')) {
            try {
                const hash = await bcrypt.hash(password, 10);
                await pool.query('UPDATE administradores SET password_hash = $1 WHERE id = $2', [hash, admin.id]);
            } catch (e) {
                console.error('No se pudo convertir la contraseña a hash:', e.message);
            }
        }

        res.json({ mensaje: 'Acceso concedido', token: firmarToken(admin), admin: datosPublicosUsuario(admin) });
    } catch (err) {
        console.error('Error en /api/admin/login:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Quién soy (sirve para recuperar la sesión al recargar la página)
app.get('/api/admin/yo', autenticar, (req, res) => {
    res.json({ admin: req.usuario });
});

// Cambiar el usuario y/o la contraseña de la cuenta con la que se inició sesión (exige la contraseña actual)
app.put('/api/admin/credenciales', autenticar, async (req, res) => {
    const { passwordActual, nuevoUsuario, nuevaPassword } = req.body || {};
    if (!passwordActual) {
        return res.status(400).json({ error: 'Falta la contraseña actual' });
    }

    const usuarioNuevo = typeof nuevoUsuario === 'string' ? nuevoUsuario.trim() : '';
    const hayUsuario = usuarioNuevo !== '' && usuarioNuevo !== req.usuario.usuario;
    const hayPassword = typeof nuevaPassword === 'string' && nuevaPassword !== '';

    if (!hayUsuario && !hayPassword) {
        return res.status(400).json({ error: 'No hay cambios para guardar' });
    }
    if (hayUsuario && !/^[A-Za-z0-9._-]{3,30}$/.test(usuarioNuevo)) {
        return res.status(400).json({ error: 'El usuario debe tener entre 3 y 30 caracteres (letras, números, punto, guion o guion bajo)' });
    }
    if (hayPassword && (nuevaPassword.length < 8 || nuevaPassword.length > 72)) {
        return res.status(400).json({ error: 'La nueva contraseña debe tener entre 8 y 72 caracteres' });
    }

    try {
        const result = await pool.query('SELECT * FROM administradores WHERE id = $1', [req.usuario.id]);
        const admin = result.rows[0];

        // 403 y no 401: el 401 se reserva para "tu sesión ya no sirve" y la página cierra la sesión al recibirlo
        if (!(await verificarPassword(admin, passwordActual))) {
            return res.status(403).json({ error: 'La contraseña actual es incorrecta' });
        }

        const hash = hayPassword ? await bcrypt.hash(nuevaPassword, 10) : null;
        // Al cambiar la contraseña se cierran las demás sesiones abiertas de esta cuenta
        const actualizado = await pool.query(
            `UPDATE administradores
             SET usuario = COALESCE($1, usuario),
                 password_hash = COALESCE($2, password_hash),
                 token_version = COALESCE(token_version, 0) + $3
             WHERE id = $4
             RETURNING *`,
            [hayUsuario ? usuarioNuevo : null, hash, hayPassword ? 1 : 0, admin.id]
        );
        const u = actualizado.rows[0];

        res.json({ mensaje: 'Datos de acceso actualizados', admin: datosPublicosUsuario(u), token: firmarToken(u) });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Ese nombre de usuario ya está en uso' });
        }
        console.error('Error en /api/admin/credenciales:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ------------------------------------------
// Cuentas de LECTORES (quienes salen a tomar las lecturas): las gestiona el administrador
// ------------------------------------------
app.get('/api/admin/lectores', ...adminOnly, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, usuario, nombre, activo, creado FROM administradores WHERE rol = 'lector' ORDER BY id"
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/lectores', ...adminOnly, async (req, res) => {
    const { usuario, nombre, password } = req.body || {};
    const usuarioLimpio = typeof usuario === 'string' ? usuario.trim() : '';
    const nombreLimpio = typeof nombre === 'string' ? nombre.trim() : '';

    if (!/^[A-Za-z0-9._-]{3,30}$/.test(usuarioLimpio)) {
        return res.status(400).json({ error: 'El usuario debe tener entre 3 y 30 caracteres (letras, números, punto, guion o guion bajo)' });
    }
    if (nombreLimpio.length < 2 || nombreLimpio.length > 60) {
        return res.status(400).json({ error: 'El nombre debe tener entre 2 y 60 caracteres' });
    }
    if (typeof password !== 'string' || password.length < 8 || password.length > 72) {
        return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres' });
    }

    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            "INSERT INTO administradores (usuario, password_hash, nombre, rol) VALUES ($1, $2, $3, 'lector') RETURNING id, usuario, nombre, activo, creado",
            [usuarioLimpio, hash, nombreLimpio]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Ese nombre de usuario ya está en uso' });
        }
        res.status(500).json({ error: err.message });
    }
});

// Cambiar nombre, contraseña o activar/desactivar una cuenta de lector
app.put('/api/admin/lectores/:id', ...adminOnly, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) {
        return res.status(400).json({ error: 'Id inválido' });
    }

    const { nombre, password, activo } = req.body || {};
    const nombreLimpio = typeof nombre === 'string' ? nombre.trim() : null;
    if (nombreLimpio !== null && (nombreLimpio.length < 2 || nombreLimpio.length > 60)) {
        return res.status(400).json({ error: 'El nombre debe tener entre 2 y 60 caracteres' });
    }
    if (password !== undefined && (typeof password !== 'string' || password.length < 8 || password.length > 72)) {
        return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres' });
    }
    if (activo !== undefined && typeof activo !== 'boolean') {
        return res.status(400).json({ error: 'El valor de "activo" no es válido' });
    }
    if (nombreLimpio === null && password === undefined && activo === undefined) {
        return res.status(400).json({ error: 'No hay cambios para guardar' });
    }

    try {
        const hash = password !== undefined ? await bcrypt.hash(password, 10) : null;
        // Cambiar la contraseña o desactivar la cuenta cierra sus sesiones abiertas
        const cierraSesiones = password !== undefined || activo === false;
        const result = await pool.query(
            `UPDATE administradores
             SET nombre = COALESCE($1, nombre),
                 password_hash = COALESCE($2, password_hash),
                 activo = COALESCE($3, activo),
                 token_version = COALESCE(token_version, 0) + $4
             WHERE id = $5 AND rol = 'lector'
             RETURNING id, usuario, nombre, activo, creado`,
            [nombreLimpio, hash, activo === undefined ? null : activo, cierraSesiones ? 1 : 0, id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Lector no encontrado' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 2. RUTAS DE USUARIOS / CONTRIBUYENTES
// ==========================================
app.get('/api/usuarios', ...adminOnly, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/usuarios', ...adminOnly, async (req, res) => {
    const { nombre, ci, direccion, medidor, lecturaAnterior, lectura_anterior } = req.body;
    const lecturaInicial = lecturaAnterior !== undefined ? lecturaAnterior : (lectura_anterior || 0);

    try {
        const result = await pool.query(
            'INSERT INTO usuarios (nombre, ci, direccion, medidor, lectura_anterior) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [nombre, ci, direccion, medidor, lecturaInicial]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Corregir los datos de un usuario (nombre, C.I., dirección, medidor y, si hace falta, la lectura anterior)
app.put('/api/usuarios/:id', ...adminOnly, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) {
        return res.status(400).json({ error: 'Id de usuario inválido' });
    }

    const b = req.body || {};
    const limpiar = v => (typeof v === 'string' ? v.trim() : '');
    const nombre = limpiar(b.nombre);
    const ci = limpiar(b.ci);
    const direccion = limpiar(b.direccion);
    const medidor = limpiar(b.medidor);

    if (nombre.length < 2 || nombre.length > 80) {
        return res.status(400).json({ error: 'El nombre debe tener entre 2 y 80 caracteres' });
    }
    if (!ci || ci.length > 20) {
        return res.status(400).json({ error: 'Escribe la C.I. (hasta 20 caracteres)' });
    }
    if (!medidor || medidor.length > 20) {
        return res.status(400).json({ error: 'Escribe el número de medidor (hasta 20 caracteres)' });
    }
    if (direccion.length > 120) {
        return res.status(400).json({ error: 'La dirección es demasiado larga (máximo 120 caracteres)' });
    }

    let lectura = null;
    if (b.lecturaAnterior !== undefined && b.lecturaAnterior !== null && b.lecturaAnterior !== '') {
        lectura = Number(b.lecturaAnterior);
        if (!Number.isFinite(lectura) || lectura < 0) {
            return res.status(400).json({ error: 'La lectura anterior debe ser un número mayor o igual a cero' });
        }
    }
    const actualizarFacturas = b.actualizarFacturas === true;
    const normalizar = s => String(s || '').replace(/\s+/g, '').toLowerCase();

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const actual = await client.query('SELECT * FROM usuarios WHERE id = $1 FOR UPDATE', [id]);
        if (actual.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        const previo = actual.rows[0];

        // La C.I. y el medidor no pueden repetirse con otro usuario (solo se controla si se cambian)
        if (normalizar(ci) !== normalizar(previo.ci)) {
            const dup = await client.query(
                "SELECT nombre FROM usuarios WHERE id <> $1 AND REPLACE(LOWER(ci), ' ', '') = $2 LIMIT 1",
                [id, normalizar(ci)]
            );
            if (dup.rows.length > 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({ error: `Ya hay otro usuario con esa C.I. (${dup.rows[0].nombre})` });
            }
        }
        if (normalizar(medidor) !== normalizar(previo.medidor)) {
            const dup = await client.query(
                "SELECT nombre FROM usuarios WHERE id <> $1 AND REPLACE(LOWER(medidor), ' ', '') = $2 LIMIT 1",
                [id, normalizar(medidor)]
            );
            if (dup.rows.length > 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({ error: `Ya hay otro usuario con ese medidor (${dup.rows[0].nombre})` });
            }
        }

        const actualizado = await client.query(
            'UPDATE usuarios SET nombre = $1, ci = $2, direccion = $3, medidor = $4, lectura_anterior = COALESCE($5, lectura_anterior) WHERE id = $6 RETURNING *',
            [nombre, ci, direccion, medidor, lectura, id]
        );

        // Las facturas guardan una copia de estos datos: se corrigen también para que el cliente las encuentre
        let facturasActualizadas = 0;
        if (actualizarFacturas) {
            const r = await client.query(
                'UPDATE facturas SET nombre = $1, ci = $2, direccion = $3, medidor = $4 WHERE usuario_id = $5',
                [nombre, ci, direccion, medidor, id]
            );
            facturasActualizadas = r.rowCount || 0;
        }

        await client.query('COMMIT');
        res.json({ usuario: actualizado.rows[0], facturasActualizadas });
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        res.status(500).json({ error: err.message });
    } finally {
        if (client) client.release();
    }
});

app.delete('/api/usuarios/:id', ...adminOnly, async (req, res) => {
    try {
        await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
        res.json({ mensaje: 'Usuario eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 3. RUTAS DE FACTURAS Y LECTURAS
// ==========================================
app.get('/api/facturas', ...adminOnly, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM facturas ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/facturas/buscar', async (req, res) => {
    const q = (req.query.q || '').replace(/[\s-]/g, '').toLowerCase();
    try {
        const result = await pool.query(`
            SELECT * FROM facturas 
            WHERE REPLACE(LOWER(ci), ' ', '') = $1 
               OR REPLACE(LOWER(medidor), ' ', '') = $1 
               OR REPLACE(LOWER(num_factura), ' ', '') = $1
            ORDER BY CASE
                WHEN REPLACE(LOWER(ci), ' ', '') = $1 THEN 0
                WHEN REPLACE(LOWER(medidor), ' ', '') = $1 THEN 1
                ELSE 2 END, id DESC
            LIMIT 1
        `, [q]);

        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'Factura no encontrada' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Todas las facturas del usuario al que pertenece la búsqueda (C.I., medidor o N° de factura)
app.get('/api/facturas/historial', async (req, res) => {
    const q = (req.query.q || '').replace(/[\s-]/g, '').toLowerCase();
    if (!q) {
        return res.status(400).json({ error: 'Falta el dato de búsqueda' });
    }
    try {
        const base = await pool.query(`
            SELECT usuario_id, ci, medidor FROM facturas
            WHERE REPLACE(LOWER(ci), ' ', '') = $1
               OR REPLACE(LOWER(medidor), ' ', '') = $1
               OR REPLACE(LOWER(num_factura), ' ', '') = $1
            ORDER BY CASE
                WHEN REPLACE(LOWER(ci), ' ', '') = $1 THEN 0
                WHEN REPLACE(LOWER(medidor), ' ', '') = $1 THEN 1
                ELSE 2 END, id DESC
            LIMIT 1
        `, [q]);

        if (base.rows.length === 0) {
            return res.status(404).json({ error: 'Factura no encontrada' });
        }

        const { usuario_id, ci, medidor } = base.rows[0];
        const result = usuario_id !== null && usuario_id !== undefined
            ? await pool.query('SELECT * FROM facturas WHERE usuario_id = $1 ORDER BY id DESC', [usuario_id])
            : await pool.query('SELECT * FROM facturas WHERE ci = $1 AND medidor = $2 ORDER BY id DESC', [ci, medidor]);

        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Siguiente número de factura: el mayor número existente + 1 (la primera factura es la 1).
// Solo cuentan los valores que son un número entero; cualquier otro texto se ignora.
async function siguienteNumeroFactura(client) {
    const r = await client.query('SELECT num_factura FROM facturas');
    let mayor = 0;
    for (const fila of r.rows) {
        if (/^\d{1,15}$/.test(String(fila.num_factura))) {
            mayor = Math.max(mayor, parseInt(fila.num_factura, 10));
        }
    }
    return String(mayor + 1);
}

app.post('/api/facturas', ...adminOnly, async (req, res) => {
    const f = req.body;
    
    // Mapeo flexible de variables (soporta camelCase del HTML y snake_case)
    // El número de factura lo asigna el servidor (correlativo, desde 1); el que mande la página se ignora
    const usuario_id = f.usuarioId || f.usuario_id;
    const nombre = f.nombre;
    const ci = f.ci;
    const direccion = f.direccion;
    const medidor = f.medidor;
    const ciclo = f.ciclo;
    const emision = f.emision;
    const vencimiento = f.vencimiento;
    const lectura_anterior = f.lecturaAnterior !== undefined ? f.lecturaAnterior : f.lectura_anterior;
    const lectura_actual = f.lecturaActual !== undefined ? f.lecturaActual : f.lectura_actual;
    const consumo_litros = f.consumoLitros !== undefined ? f.consumoLitros : f.consumo_litros;
    const monto_agua = f.montoAgua !== undefined ? f.montoAgua : f.monto_agua;
    const monto_otros = f.montoOtros !== undefined ? f.montoOtros : (f.monto_otros || 0);
    const estado = f.estado || 'PENDIENTE';
    // Si ya se emite como PAGADO, se registra la fecha de pago (la enviada o la de emisión)
    const fecha_pago = estado === 'PAGADO' ? (f.fechaPago || f.fecha_pago || emision || hoyParaguay()) : null;

    // Las fechas deben venir como AAAA-MM-DD: de ellas depende en qué mes cuentan los reportes
    if (!fechaValida(emision)) {
        return res.status(400).json({ error: 'La fecha de emisión debe tener el formato AAAA-MM-DD' });
    }
    if (estado === 'PAGADO' && !fechaValida(fecha_pago)) {
        return res.status(400).json({ error: 'La fecha de pago debe tener el formato AAAA-MM-DD' });
    }

    const tieneUsuario = usuario_id !== undefined && usuario_id !== null && usuario_id !== '';
    let client;

    try {
        client = await pool.connect();
        await client.query('BEGIN');

        // Número correlativo: el bloqueo evita que dos emisiones al mismo tiempo reciban el mismo número
        await client.query('SELECT pg_advisory_xact_lock(4207)');
        const num_factura = await siguienteNumeroFactura(client);

        // Deuda anterior automática: suma de las facturas de este usuario que siguen PENDIENTES
        let deuda_anterior = 0;
        if (tieneUsuario) {
            const deuda = await client.query(
                "SELECT COALESCE(SUM(monto_total - COALESCE(monto_pagado, 0)), 0) AS deuda FROM facturas WHERE usuario_id = $1 AND estado = 'PENDIENTE'",
                [usuario_id]
            );
            deuda_anterior = Number(deuda.rows[0].deuda) || 0;
        }

        // El total lo calcula el servidor: agua + otros conceptos + deuda anterior
        const monto_total = (Number(monto_agua) || 0) + (Number(monto_otros) || 0) + deuda_anterior;

        const result = await client.query(`
            INSERT INTO facturas 
            (num_factura, usuario_id, nombre, ci, direccion, medidor, ciclo, emision, vencimiento, lectura_anterior, lectura_actual, consumo_litros, monto_agua, monto_otros, monto_total, estado, fecha_pago, deuda_anterior, monto_pagado)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
            RETURNING *
        `, [num_factura, usuario_id, nombre, ci, direccion, medidor, ciclo, emision, vencimiento, lectura_anterior, lectura_actual, consumo_litros, monto_agua, monto_otros, monto_total, estado, fecha_pago, deuda_anterior, estado === 'PAGADO' ? monto_total : 0]);

        const nueva = result.rows[0];

        // Si la factura sale ya PAGADA, queda registrado el pago completo
        if (estado === 'PAGADO' && monto_total > 0) {
            await client.query('INSERT INTO pagos (factura_id, monto, fecha) VALUES ($1, $2, $3)', [nueva.id, monto_total, fecha_pago]);
        }

        if (tieneUsuario) {
            // Las facturas pendientes anteriores pasan a TRASLADADA: su deuda ya está dentro de la nueva
            await client.query(
                "UPDATE facturas SET estado = 'TRASLADADA', trasladada_a = $1 WHERE usuario_id = $2 AND estado = 'PENDIENTE' AND id <> $1",
                [nueva.id, usuario_id]
            );
            // Actualizar la última lectura del usuario
            await client.query('UPDATE usuarios SET lectura_anterior = $1 WHERE id = $2', [lectura_actual, usuario_id]);
        }

        await client.query('COMMIT');
        res.json(nueva);
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        res.status(500).json({ error: err.message });
    } finally {
        if (client) client.release();
    }
});

// ------------------------------------------
// PAGOS (totales o parciales) sobre una factura PENDIENTE
// ------------------------------------------
async function registrarPago(facturaId, monto, fecha, nota) {
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const fr = await client.query(
            'SELECT id, monto_total, monto_pagado, estado FROM facturas WHERE id = $1 FOR UPDATE',
            [facturaId]
        );
        if (fr.rows.length === 0) {
            await client.query('ROLLBACK');
            return { status: 404, error: 'Factura no encontrada' };
        }

        const f = fr.rows[0];
        if (f.estado !== 'PENDIENTE') {
            await client.query('ROLLBACK');
            return { status: 409, error: 'Esta factura no está pendiente de cobro' };
        }

        const total = Number(f.monto_total) || 0;
        const pagado = Number(f.monto_pagado) || 0;
        const saldo = total - pagado;

        // monto === null significa "pagar el saldo completo"
        const importe = monto === null ? saldo : monto;

        if (saldo <= 0) {
            // Factura sin saldo (total en cero): solo se cierra, sin registrar dinero
            const cerrada = await client.query(
                "UPDATE facturas SET estado = 'PAGADO', fecha_pago = $1 WHERE id = $2 RETURNING *",
                [fecha, facturaId]
            );
            await client.query('COMMIT');
            return { status: 200, factura: cerrada.rows[0], pago: null };
        }
        if (!Number.isFinite(importe) || importe <= 0) {
            await client.query('ROLLBACK');
            return { status: 400, error: 'El monto debe ser mayor a cero' };
        }
        if (importe > saldo) {
            await client.query('ROLLBACK');
            return { status: 400, error: `El monto supera el saldo pendiente (${saldo})` };
        }

        const nuevoPagado = pagado + importe;
        const liquidada = nuevoPagado >= total;

        const pago = await client.query(
            'INSERT INTO pagos (factura_id, monto, fecha, nota) VALUES ($1, $2, $3, $4) RETURNING *',
            [facturaId, importe, fecha, nota || null]
        );
        const actualizada = await client.query(
            'UPDATE facturas SET monto_pagado = $1, estado = $2, fecha_pago = $3 WHERE id = $4 RETURNING *',
            [nuevoPagado, liquidada ? 'PAGADO' : 'PENDIENTE', liquidada ? fecha : null, facturaId]
        );

        await client.query('COMMIT');
        return { status: 200, factura: actualizada.rows[0], pago: pago.rows[0] };
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        throw err;
    } finally {
        if (client) client.release();
    }
}

function fechaValida(f) {
    return typeof f === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(f);
}

// Registrar un pago (parcial o total) de una factura
app.post('/api/facturas/:id/pagos', ...adminOnly, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) {
        return res.status(400).json({ error: 'Id de factura inválido' });
    }

    const body = req.body || {};
    const monto = Math.round(Number(body.monto));
    if (!Number.isFinite(monto) || monto <= 0) {
        return res.status(400).json({ error: 'El monto debe ser mayor a cero' });
    }
    const fechaEnviada = body.fechaPago || body.fecha_pago;
    if (fechaEnviada && !fechaValida(fechaEnviada)) {
        return res.status(400).json({ error: 'La fecha debe tener el formato AAAA-MM-DD' });
    }
    const nota = typeof body.nota === 'string' ? body.nota.trim().slice(0, 120) : null;

    try {
        const r = await registrarPago(id, monto, fechaEnviada || hoyParaguay(), nota);
        if (r.status !== 200) return res.status(r.status).json({ error: r.error });
        res.json({ factura: r.factura, pago: r.pago });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Marcar una factura como pagada: registra el pago del saldo completo
app.put('/api/facturas/:id/pagar', ...adminOnly, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) {
        return res.status(400).json({ error: 'Id de factura inválido' });
    }

    const fechaEnviada = req.body && (req.body.fechaPago || req.body.fecha_pago);
    if (fechaEnviada && !fechaValida(fechaEnviada)) {
        return res.status(400).json({ error: 'La fecha debe tener el formato AAAA-MM-DD' });
    }

    try {
        const r = await registrarPago(id, null, fechaEnviada || hoyParaguay(), null);
        if (r.status !== 200) return res.status(r.status).json({ error: r.error });
        res.json(r.factura);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Lista de todos los pagos (la usan los reportes)
app.get('/api/pagos', ...adminOnly, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM pagos ORDER BY fecha DESC, id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Anular un pago registrado por error
app.delete('/api/pagos/:id', ...adminOnly, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) {
        return res.status(400).json({ error: 'Id de pago inválido' });
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const pr = await client.query('SELECT * FROM pagos WHERE id = $1', [id]);
        if (pr.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Pago no encontrado' });
        }
        const pago = pr.rows[0];

        const fr = await client.query(
            'SELECT id, monto_total, monto_pagado, estado, fecha_pago FROM facturas WHERE id = $1 FOR UPDATE',
            [pago.factura_id]
        );
        const f = fr.rows[0];

        // Si la deuda ya se trasladó a otra factura, anular este pago descuadraría los saldos
        if (!f || f.estado === 'TRASLADADA') {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'La deuda de esta factura ya fue trasladada a una factura posterior; este pago no se puede anular' });
        }

        const total = Number(f.monto_total) || 0;
        const nuevoPagado = Math.max(0, (Number(f.monto_pagado) || 0) - (Number(pago.monto) || 0));
        const reabrir = nuevoPagado < total;

        await client.query('DELETE FROM pagos WHERE id = $1', [id]);
        const actualizada = await client.query(
            'UPDATE facturas SET monto_pagado = $1, estado = $2, fecha_pago = $3 WHERE id = $4 RETURNING *',
            [nuevoPagado, reabrir ? 'PENDIENTE' : f.estado, reabrir ? null : f.fecha_pago, f.id]
        );

        await client.query('COMMIT');
        res.json({ mensaje: 'Pago anulado', factura: actualizada.rows[0] });
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        res.status(500).json({ error: err.message });
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// 4. RUTAS DE GASTOS / EGRESOS
// ==========================================
app.get('/api/gastos', ...adminOnly, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM gastos ORDER BY fecha DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/gastos', ...adminOnly, async (req, res) => {
    const { categoria, monto, fecha, descripcion } = req.body;

    if (!categoria || !(Number(monto) > 0)) {
        return res.status(400).json({ error: 'Faltan la categoría o el monto del gasto' });
    }
    if (!fechaValida(fecha)) {
        return res.status(400).json({ error: 'La fecha del gasto debe tener el formato AAAA-MM-DD' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO gastos (categoria, monto, fecha, descripcion) VALUES ($1, $2, $3, $4) RETURNING *',
            [categoria, monto, fecha, descripcion]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/gastos/:id', ...adminOnly, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) {
        return res.status(400).json({ error: 'Id de gasto inválido' });
    }
    try {
        const result = await pool.query('DELETE FROM gastos WHERE id = $1 RETURNING id', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Gasto no encontrado' });
        }
        res.json({ mensaje: 'Gasto eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Puerto del servidor
app.listen(PORT, () => {
    console.log(`Servidor iniciado en el puerto ${PORT}`);
});