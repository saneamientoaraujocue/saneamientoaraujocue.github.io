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

// Verificación básica del servidor
app.get('/', (req, res) => {
    res.send('Servidor de la Junta de Saneamiento en funcionamiento');
});

// ==========================================
// 1. AUTENTICACIÓN / LOGIN DE ADMINISTRADOR
// ==========================================
app.post('/api/admin/login', async (req, res) => {
    const { usuario, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM administradores WHERE usuario = $1', [usuario]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }

        const admin = result.rows[0];

        // VALIDACIÓN FLEXIBLE:
        // 1. Si la contraseña en BD es un hash de Bcrypt (empieza con $2), lo compara con bcrypt.
        // 2. Si no es un hash (texto en plano), realiza la comparación directa.
        let esValida = false;

        if (admin.password_hash && admin.password_hash.startsWith('$2')) {
            esValida = await bcrypt.compare(password, admin.password_hash);
        } else {
            esValida = (password === admin.password_hash);
        }

        if (!esValida) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
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

app.post('/api/admin/cambiar-clave', async (req, res) => {
    const { usuario, nuevaPassword } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(nuevaPassword, salt);

        await pool.query('UPDATE administradores SET password_hash = $1 WHERE usuario = $2', [hash, usuario]);
        res.json({ mensaje: 'Contraseña actualizada con éxito' });
    } catch (err) {
        res.status(500).json({ error: 'Error al actualizar contraseña' });
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
    const monto_total = f.montoTotal !== undefined ? f.montoTotal : f.monto_total;
    const estado = f.estado || 'PENDIENTE';

    try {
        const result = await pool.query(`
            INSERT INTO facturas 
            (num_factura, usuario_id, nombre, ci, direccion, medidor, ciclo, emision, vencimiento, lectura_anterior, lectura_actual, consumo_litros, monto_agua, monto_otros, monto_total, estado)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            RETURNING *
        `, [num_factura, usuario_id, nombre, ci, direccion, medidor, ciclo, emision, vencimiento, lectura_anterior, lectura_actual, consumo_litros, monto_agua, monto_otros, monto_total, estado]);

        // Actualizar la última lectura del usuario
        await pool.query('UPDATE usuarios SET lectura_anterior = $1 WHERE id = $2', [lectura_actual, usuario_id]);

        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
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

// Puerto del servidor
app.listen(PORT, () => {
    console.log(`Servidor iniciado en el puerto ${PORT}`);
});