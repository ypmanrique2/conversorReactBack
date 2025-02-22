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

        try {
            const [results] = await pool.query(
                "SELECT * FROM usuarios WHERE usuario = ? AND clave = ?",
                [usuario, clave]
            );

            if (results.length > 0) {
                res.status(200).json({
                    message: 'Usuario y contraseña correctos',
                    logueado: true
                });
            } else {
                res.status(401).json('Usuario o contraseña incorrectos');
            }
        } catch (err) {
            console.log(err);
            res.status(500).json('Error al procesar la solicitud');
        }
    } else {
        res.status(405).send('Método no permitido');
    }
}