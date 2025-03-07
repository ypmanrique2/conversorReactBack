import express from 'express';

import fs from 'fs';

import mysql from 'mysql2/promise';

import cors from 'cors';

import crypto from 'crypto';

import session from 'express-session';

import dotenv from 'dotenv';

import jwt from 'jsonwebtoken';

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
    const { usuario, clave, rol, nombre } = req.body;

    if (!usuario || !clave) {
        return res.status(400).json({ error: 'Usuario y clave son requeridos' });
    }

    // Si no se especifica un rol, se asigna "USUARIO" por defecto
    const rolAsignado = rol || 'USUARIO';

    try {
        const claveMD5 = crypto.createHash('md5').update(clave).digest('hex');
        await poolAiven.query(
            'INSERT INTO usuarios (usuario, clave, rol, nombre) VALUES (?, ?, ?, ?)',
            [usuario, claveMD5, rolAsignado, nombre || '']
        );
        return res.json({ message: 'Usuario registrado exitosamente' });
    } catch (err) {
        console.error('Error en el registro:', err.message);
        return res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
});

// Ruta login para almacenar el rol en la sesión
app.post('/login', async (req, res) => {
    console.log("Recibiendo solicitud de login...");
    console.log("Body recibido:", req.body);
    console.log("Cookies:", req.cookies);
    console.log("Sesión antes de login:", req.session);

    const { usuario, clave } = req.body;

    if (!usuario || !clave) {
        console.log("Faltan datos");
        return res.status(400).json({ error: 'Usuario y clave son requeridos' });
    }

    try {
        const [rows] = await poolAiven.query(
            'SELECT * FROM usuarios WHERE usuario = ?',
            [usuario]
        );

        console.log("Resultado de la consulta:", rows);

        if (rows.length > 0) {
            const claveMD5 = crypto.createHash('md5').update(clave).digest('hex');

            if (claveMD5 === rows[0].clave) {
                req.session.usuario = usuario;  // Guardar usuario en sesión
                req.session.rol = rows[0].rol;  // Guardar rol en sesión

                console.log("Sesión después de login:", req.session);

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
        const [usuarios] = await poolAiven.query('SELECT id, nombre, usuario, rol FROM usuarios');
        res.json(usuarios);
    } catch (err) {
        console.error('Error al obtener usuarios:', err.message);
        res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
});

// Ruta para actualizar solo el rol de un usuario
app.put('/usuario/:usuarioId/rol', async (req, res) => {
    const { usuarioId } = req.params;
    const { rol } = req.body;

    if (!req.session || req.session.rol !== 'ADMINISTRADOR') {
        return res.status(403).json({ error: 'No autorizado' });
    }

    try {
        await poolAiven.query('UPDATE usuarios SET rol = ? WHERE id = ?', [rol, usuarioId]);
        return res.json({ message: 'Rol actualizado exitosamente' });
    } catch (err) {
        console.error('Error al actualizar el rol del usuario:', err.message);
        return res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
    }
});

// Ruta para editar un usuario - Solo el administrador puede editar
app.put('/usuario/:usuarioId', async (req, res) => {
    const { usuarioId } = req.params;
    const { usuario, clave, rol, nombre } = req.body;

    if (!req.session || req.session.rol !== 'ADMINISTRADOR') {
        return res.status(403).json({ error: 'No autorizado' });
    }

    try {
        let query = 'UPDATE usuarios SET ';
        let params = [];

        if (usuario) {
            query += 'usuario = ?, ';
            params.push(usuario);
        }
        if (clave) {
            const claveMD5 = crypto.createHash('md5').update(clave).digest('hex');
            query += 'clave = ?, ';
            params.push(claveMD5);
        }
        if (rol) {
            query += 'rol = ?, ';
            params.push(rol);
        }
        if (nombre) {
            query += 'nombre = ?, ';
            params.push(nombre);
        }

        query = query.slice(0, -2); // Eliminar la última coma
        query += ' WHERE id = ?';
        params.push(usuarioId);

        await poolAiven.query(query, params);
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

// Ruta para cerrar sesión
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            return res.status(500).json({ error: 'Error al cerrar sesión' });
        }
        res.json({ message: 'Sesión cerrada exitosamente' });
    });
});

export { poolAiven };