import mysql from 'mysql2/promise';

import fs from 'fs';

const pool = mysql.createPool({
    host: 'mysql-conversor-soy-7596.i.aivencloud.com',
    port: 12655,
    user: 'avnadmin',
    password: 'AVNS_QbjHj-vGWZmBnhv3u0L',
    database: 'defaultdb',
    ssl: {
        ca: fs.readFileSync('./ca.pem'),
    }
});

export default async function handler(req, res) {
    if (req.method === 'POST') {
        const { usuario, clave } = req.body;

        if (!usuario || !clave) {
            return res.status(400).json({ error: "El usuario y la clave son obligatorios." });
        }

        try {
            const [results] = await pool.query(
                "INSERT INTO usuarios (usuario, clave) VALUES (?, ?)",
                [usuario, clave]
            );
            res.status(201).json({ message: 'Usuario creado' });
        } catch (err) {
            console.log(err);
            res.status(500).json({ message: 'Error al crear el usuario' });
        }
    } else {
        res.status(405).send('Método no permitido');
    }
}