const express = require('express')
const { usuarios } = require('../db')
const { autenticar, soloRol } = require('../middleware/auth')
const router = express.Router()
// Función de administrador: solo el rol admin
router.get('/', autenticar, soloRol('admin'), (req, res) => {
 res.json(usuarios.map(({ clave, ...resto }) => resto)) // sin la clave
})
// Perfil del propio usuario
router.get('/yo', autenticar, (req, res) => {
 const u = usuarios.find(x => x.id === req.usuario.id)
 if (!u) return res.status(404).json({ error: 'Usuario no encontrado' })
 const { clave, ...resto } = u
 res.json(resto)
})
module.exports = router
// Cambiar el rol de un usuario (solo admin)
router.put('/:id/rol', autenticar, soloRol('admin'), (req, res) => {
  const id = Number(req.params.id);
  const { rol } = req.body || {};

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: 'ID inválido' });
  }

  if (!['admin', 'user'].includes(rol)) {
    return res.status(400).json({ error: 'Rol inválido' });
  }

  const usuario = usuarios.find(u => u.id === id);

  if (!usuario) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }

  usuario.rol = rol;

  res.json({
    id: usuario.id,
    nombre: usuario.nombre,
    rol: usuario.rol
  });
});