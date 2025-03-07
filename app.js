import express from 'express';

import fs from 'fs';

import mysql from 'mysql2/promise';

import cors from 'cors';

import crypto from 'crypto';

import session from 'express-session';

import dotenv from 'dotenv';

dotenv.config();
const app = express();
const port = process.env.PORT || 10000;

// Configuración de CORS
const corsOptions = {
    origin: ['localhost:5173', 'https://vermillion-babka-8fa83b.netlify.app'], // Cambia al puerto correcto de React
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true, // Habilitar credenciales (cookies, sesiones)
    preflightContinue: false,
    sameSite: 'none',
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

app.use(session({
    secret: process.env.SECRETSESSION || 'asdf',
    resave: false,  // No guardar la sesión si no ha cambiado
    saveUninitialized: false,  // No guardar sesiones no inicializadas
    proxy: true,
    cookie: {
        sameSite: 'none',
        secure: true,
        secure: process.env.NODE_ENV === 'production', // Solo en producción
    }
}));

app.set("trust proxy", 1);

app.use(express.json());  // Para parsear JSON, sino funciona, escriba app.use(express.text());
app.use(express.urlencoded({ extended: true }));  // Para parsear datos de formularios

const saltRounds = 10;

// Conexión a Aiven
const poolAiven = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        ca: fs.readFileSync('./ca.pem'),
    }
});

poolAiven.getConnection()
    .then(() => console.log("Conexión a Aiven exitosa"))
    .catch(err => console.error("Error al conectar a Aiven:", err.message));

// Ruta para registrar un nuevo usuario con clave encriptada en MD5
app.post('/register', async (req, res) => {
    console.log("Recibiendo solicitud de registro...");
    const { usuario, clave, rol } = req.body;

    if (!usuario || !clave) {
        return res.status(400).json({ error: 'Usuario y clave son requeridos' });
    }

    // Si no se especifica un rol, se asigna "USUARIO" por defecto
    const rolAsignado = rol || 'USUARIO';

    try {
        const claveMD5 = crypto.createHash('md5').update(clave).digest('hex');
        await poolAiven.query('INSERT INTO usuarios (usuario, clave, rol) VALUES (?, ?, ?)', [usuario, claveMD5, rolAsignado]);
        return res.json({ message: 'Usuario registrado exitosamente' });
    } catch (err) {
        console.error('Error en el registro:', err.message);
        return res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
});

// Ruta login para almacenar el rol en la sesión
app.post('/login', async (req, res) => {
    console.log("Recibiendo solicitud de login...");
    const { usuario, clave } = req.body;

    if (!usuario || !clave) {
        return res.status(400).json({ error: 'Usuario y clave son requeridos' });
    }

    try {
        const [rows] = await poolAiven.query(
            'SELECT * FROM usuarios WHERE usuario = ?',
            [usuario]
        );

        if (rows.length > 0) {
            const claveMD5 = crypto.createHash('md5').update(clave).digest('hex');

            if (claveMD5 === rows[0].clave) {
                req.session.usuario = usuario;  // Guardar usuario en sesión
                req.session.rol = rows[0].rol;  // Guardar rol en sesión
                return res.json({ logueado: true, rol: rows[0].rol });
            }
        }
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    } catch (err) {
        console.error('Error en el inicio de sesión:', err.message);
        return res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
});

// Ruta para obtener la lista de usuarios
app.get('/usuarios', async (req, res) => {
    try {
        const [usuarios] = await poolAiven.query('SELECT id, usuario, rol FROM usuarios');
        res.json(usuarios);
    } catch (err) {
        console.error('Error al obtener usuarios:', err.message);
        res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
});

// Verificar rol antes de editar/eliminar
/* app.put('/usuario/:usuarioId', async (req, res) => {
    console.log(`Solicitud recibida para actualizar usuario con ID: ${req.params.usuarioId}`);
    const { usuarioId } = req.params;
    const { usuario, clave, rol } = req.body;
    if (rol !== 'ADMINISTRADOR') {
        return res.status(403).json({ error: 'No autorizado' });
    }
    try {
        const claveMD5 = crypto.createHash('md5').update(clave).digest('hex');
        await poolAiven.query('UPDATE usuarios SET usuario = ?, clave = ? WHERE id = ?', [usuario, claveMD5, usuarioId]);
        return res.json({ message: 'Usuario actualizado exitosamente' });
    } catch (err) {
        console.error('Error al actualizar el usuario:', err.message);
        return res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
}); */

// Ruta para editar un usuario - Solo el administrador puede editar
app.put('/usuario/:usuarioId', async (req, res) => {
    const { usuarioId } = req.params;
    const { usuario, clave, rol } = req.body;

    if (!req.session || req.session.rol !== 'ADMINISTRADOR') {
        return res.status(403).json({ error: 'No autorizado' });
    }

    try {
        const claveMD5 = crypto.createHash('md5').update(clave).digest('hex');
        await poolAiven.query('UPDATE usuarios SET usuario = ?, clave = ?, rol = ? WHERE id = ?', [usuario, claveMD5, rol, usuarioId]);
        return res.json({ message: 'Usuario actualizado exitosamente' });
    } catch (err) {
        console.error('Error al actualizar el usuario:', err.message);
        return res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
});

// Ruta para eliminar un usuario - Solo el administrador puede eliminar
app.delete('/usuario/:usuarioId', async (req, res) => {
    const { usuarioId } = req.params;
    // Verificar si el usuario tiene el rol de administrador
    if (!req.session || req.session.rol !== 'ADMINISTRADOR') {
        return res.status(403).json({ error: 'No autorizado' });
    }

    try {
        // Verificar si el usuario existe
        const [existingUser] = await poolAiven.query('SELECT * FROM usuarios WHERE id = ?', [usuarioId]);
        if (existingUser.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }        // Eliminar usuario
        await poolAiven.query('DELETE FROM usuarios WHERE id = ?', [usuarioId]);
        return res.json({ message: 'Usuario eliminado exitosamente' });
    } catch (err) {
        console.error('Error al eliminar el usuario:', err.message);
        return res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
});

app.get('/validar', (req, res) => {
    if (req.session && req.session.usuario) {
        res.json({ logueado: true, rol: req.session.rol });
    } else {
        res.json({ logueado: false });
    }
});

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});

export { poolAiven };