import { Router } from 'express';

import connection from './app.js';

const router = Router();

// Ruta para editar usuario
router.put('/user/:id', async (req, res) => {
    const { id } = req.params; 
    const { usuario, clave } = req.body; 
    
    if (!usuario || !clave) {
        return res.status(400).json({ error: "El usuario y la clave son obligatorios." });
    }

    try {
        const [checkUser] = await connection.query(
            "SELECT * FROM usuarios WHERE id = ?",
            [id]
        );

        if (checkUser.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const [results] = await connection.query(
            "UPDATE usuarios SET usuario = ?, clave = ? WHERE id = ?",
            [usuario, clave, id]
        );

        if (results.affectedRows > 0) {
            res.json({ message: `Usuario con id ${id} actualizado con usuario: ${usuario} y clave: ${clave}` });
        } else {
            res.status(404).json({ message: 'Usuario no encontrado o no se realizó ningún cambio' });
        }
    } catch (err) {
        console.log("Error en la actualización:", err);
        res.status(500).json({ error: 'Error al actualizar el usuario' });
    }
});

// Ruta para eliminar usuario
router.delete('/user/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [results] = await connection.query(
            "DELETE FROM usuarios WHERE id = ?",
            [id]
        );
        if (results.affectedRows > 0) {
            res.json({ message: `Usuario con id ${id} eliminado` });
        } else {
            res.status(404).json({ message: 'Usuario no encontrado' });
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: 'Error al eliminar el usuario' });
    }
});

export default router;