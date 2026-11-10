const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
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
// Compara la contraseña con el hash de bcrypt (o directo, si todavía está en texto plano)
async function verificarPassword(admin, password) {
    if (!admin || !admin.password_hash || typeof password !== 'string') return false;
    if (admin.password_hash.startsWith('$2')) {
        return bcrypt.compare(password, admin.password_hash);
    }
    return password === admin.password_hash;
}

app.post('/api/admin/login', async (req, res) => {
    const { usuario, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM administradores WHERE usuario = $1', [usuario]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }

        const admin = result.rows[0];

        if (!(await verificarPassword(admin, password))) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }

        // Si la contraseña seguía guardada en texto plano, se guarda ya como hash
        if (!admin.password_hash.startsWith('$2')) {
            try {
                const hash = await bcrypt.hash(password, 10);
                await pool.query('UPDATE administradores SET password_hash = $1 WHERE id = $2', [hash, admin.id]);
            } catch (e) {
                console.error('No se pudo convertir la contraseña a hash:', e.message);
            }
        }

        res.json({
            mensaje: 'Acceso concedido',
            admin: {
                id: admin.id,
                usuario: admin.usuario,
                nombre: admin.nombre
            }
        });
    } catch (err) {
        console.error('Error en /api/admin/login:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Cambiar usuario y/o contraseña del administrador (exige la contraseña actual)
app.put('/api/admin/credenciales', async (req, res) => {
    const { usuarioActual, passwordActual, nuevoUsuario, nuevaPassword } = req.body || {};
    if (!usuarioActual || !passwordActual) {
        return res.status(400).json({ error: 'Faltan los datos de acceso actuales' });
    }

    const usuarioNuevo = typeof nuevoUsuario === 'string' ? nuevoUsuario.trim() : '';
    const hayUsuario = usuarioNuevo !== '' && usuarioNuevo !== usuarioActual;
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
        const result = await pool.query('SELECT * FROM administradores WHERE usuario = $1', [usuarioActual]);
        const admin = result.rows[0];

        if (!(await verificarPassword(admin, passwordActual))) {
            return res.status(401).json({ error: 'La contraseña actual es incorrecta' });
        }

        const hash = hayPassword ? await bcrypt.hash(nuevaPassword, 10) : null;
        const actualizado = await pool.query(
            'UPDATE administradores SET usuario = COALESCE($1, usuario), password_hash = COALESCE($2, password_hash) WHERE id = $3 RETURNING id, usuario, nombre',
            [hayUsuario ? usuarioNuevo : null, hash, admin.id]
        );

        res.json({ mensaje: 'Datos de acceso actualizados', admin: actualizado.rows[0] });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Ese nombre de usuario ya está en uso' });
        }
        console.error('Error en /api/admin/credenciales:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ==========================================
// 2. RUTAS DE USUARIOS / CONTRIBUYENTES
// ==========================================
app.get('/api/usuarios', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/usuarios', async (req, res) => {
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

app.delete('/api/usuarios/:id', async (req, res) => {
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
app.get('/api/facturas', async (req, res) => {
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
            ORDER BY id DESC LIMIT 1
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
            ORDER BY id DESC LIMIT 1
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

app.post('/api/facturas', async (req, res) => {
    const f = req.body;
    
    // Mapeo flexible de variables (soporta camelCase del HTML y snake_case)
    const num_factura = f.numFactura || f.num_factura;
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

    const tieneUsuario = usuario_id !== undefined && usuario_id !== null && usuario_id !== '';
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

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
        await client.query('ROLLBACK').catch(() => {});
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

// ------------------------------------------
// PAGOS (totales o parciales) sobre una factura PENDIENTE
// ------------------------------------------
async function registrarPago(facturaId, monto, fecha, nota) {
    const client = await pool.connect();
    try {
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
        await client.query('ROLLBACK').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
}

function fechaValida(f) {
    return typeof f === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(f);
}

// Registrar un pago (parcial o total) de una factura
app.post('/api/facturas/:id/pagos', async (req, res) => {
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
app.put('/api/facturas/:id/pagar', async (req, res) => {
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
app.get('/api/pagos', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM pagos ORDER BY fecha DESC, id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Anular un pago registrado por error
app.delete('/api/pagos/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) {
        return res.status(400).json({ error: 'Id de pago inválido' });
    }

    const client = await pool.connect();
    try {
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
        await client.query('ROLLBACK').catch(() => {});
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

// ==========================================
// 4. RUTAS DE GASTOS / EGRESOS
// ==========================================
app.get('/api/gastos', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM gastos ORDER BY fecha DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/gastos', async (req, res) => {
    const { categoria, monto, fecha, descripcion } = req.body;
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

app.delete('/api/gastos/:id', async (req, res) => {
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