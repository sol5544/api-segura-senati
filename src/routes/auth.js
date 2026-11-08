const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const rateLimit = require('express-rate-limit')
const { usuarios } = require('../db')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { correoValido, claveFuerte, textoValido } = require('../validar')
const router = express.Router()
// Almacenar los refresh tokens activos
const refreshTokens = new Map()

// Generar un refresh token
function generarRefreshToken(usuario) {
  const jti = crypto.randomUUID()

  const refreshToken = jwt.sign(
    { id: usuario.id, tipo: 'refresh' },
    process.env.REFRESH_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: process.env.REFRESH_EXPIRES || '7d',
      jwtid: jti
    }
  )

  refreshTokens.set(jti, usuario.id)

  return refreshToken
}

// Máximo 5 intentos FALLIDOS de inicio de sesión cada 15 minutos
const limiteLogin = rateLimit({
 windowMs: 15 * 60 * 1000,
 limit: 5,
 skipSuccessfulRequests: true,
 standardHeaders: true,
 legacyHeaders: false,
 message: { error: 'Demasiados intentos. Intente de nuevo en 15 minutos' },
})
router.post('/register', async (req, res) => {
 const { nombre, correo, clave } = req.body || {}
 if (!textoValido(nombre, 3, 60))
 return res.status(400).json({ error: 'Nombre inválido (3 a 60 caracteres)' })
 if (!correoValido(correo))
 return res.status(400).json({ error: 'Correo inválido' })
 if (!claveFuerte(clave))
 return res.status(400).json({
 error: 'La clave debe tener 8 a 72 caracteres, con mayúscula, minúscula y número' })
 if (usuarios.some(u => u.correo === correo.toLowerCase()))
 return res.status(409).json({ error: 'El correo ya está registrado' })
 const nuevo = {
    id: Math.max(...usuarios.map(u => u.id)) + 1,
 nombre: nombre.trim(),
 correo: correo.toLowerCase(),
 clave: await bcrypt.hash(clave, 10),
 rol: 'user', // el rol NUNCA se toma del cuerpo de la petición
 }
 usuarios.push(nuevo)
 res.status(201).json({ id: nuevo.id, nombre: nuevo.nombre, correo: nuevo.correo })
})
router.post('/login', limiteLogin, async (req, res) => {
 const { correo, clave } = req.body || {}
 const usuario = usuarios.find(u => u.correo === String(correo).toLowerCase())
 const valido = usuario && typeof clave === 'string' &&
 await bcrypt.compare(clave, usuario.clave)
 // Mismo mensaje si falla el correo o la clave (no revela qué dato falló)
if (!valido) {
  const fecha = new Date().toISOString()
  const ip = req.ip
  const registro = `${fecha} | IP: ${ip} | Login fallido\n`
  const archivo = path.join(__dirname, '../../intentos_fallidos.log')
  fs.appendFile(archivo, registro, (error) => {
    if (error) {console.error('Error al guardar el intento fallido:', error.message) }
  })
  return res.status(401).json({ error: 'Credenciales incorrectas'})
}
 const token = jwt.sign(
 { id: usuario.id, rol: usuario.rol },
 process.env.JWT_SECRET,
 { algorithm: 'HS256', expiresIn: process.env.JWT_EXPIRES || '15m' }
 )
 const refreshToken = generarRefreshToken(usuario)

res.json({
  token,
  refreshToken,
  usuario: {
    id: usuario.id,
    nombre: usuario.nombre,
    rol: usuario.rol
  }
})
})

router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body || {}

  if (typeof refreshToken !== 'string' || !refreshToken) {
    return res.status(401).json({
      error: 'Refresh token requerido'
    })
  }

  try {
    // Verificar firma y vencimiento del refresh token
    const datos = jwt.verify(
      refreshToken,
      process.env.REFRESH_SECRET,
      { algorithms: ['HS256'] }
    )

    // Verificar que sea un token de renovación activo
    if (
      datos.tipo !== 'refresh' ||
      !datos.jti ||
      refreshTokens.get(datos.jti) !== datos.id
    ) {
      return res.status(401).json({
        error: 'Refresh token inválido'
      })
    }

    const usuario = usuarios.find(u => u.id === datos.id)

    if (!usuario) {
      return res.status(401).json({
        error: 'Usuario no encontrado'
      })
    }

    // Invalidar el refresh token anterior
    refreshTokens.delete(datos.jti)

    // Generar un nuevo access token
    const token = jwt.sign(
      { id: usuario.id, rol: usuario.rol },
      process.env.JWT_SECRET,
      {
        algorithm: 'HS256',
        expiresIn: process.env.JWT_EXPIRES || '15m'
      }
    )

    // Generar un nuevo refresh token
    const nuevoRefreshToken = generarRefreshToken(usuario)

    res.json({
      token,
      refreshToken: nuevoRefreshToken
    })

  } catch (error) {
    return res.status(401).json({
      error: 'Refresh token inválido o expirado'
    })
  }
})
module.exports = router