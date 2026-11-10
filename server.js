
require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES || '15m';

// ==========================================
// 1. VALIDAR CONFIGURACIÓN
// ==========================================

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('ERROR: JWT_SECRET debe tener al menos 32 caracteres.');
    process.exit(1);
}

// ==========================================
// 2. CONFIGURACIÓN DE SEGURIDAD
// ==========================================

app.use(helmet());

app.use(cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10kb' }));

// Límite general de peticiones
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false
}));

// Límite de intentos de inicio de sesión
const limiteLogin = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Demasiados intentos. Intente de nuevo en 15 minutos'
    }
});

// ==========================================
// 3. BASE DE DATOS DE PRUEBA EN MEMORIA
// ==========================================

const usuarios = [
    {
        id: 1,
        nombre: 'Administrador',
        correo: 'admin@mail.com',
        clave: bcrypt.hashSync('Admin#2026', 10),
        rol: 'admin'
    },
    {
        id: 2,
        nombre: 'Ana Torres',
        correo: 'ana@mail.com',
        clave: bcrypt.hashSync('Ana#2026x', 10),
        rol: 'user'
    },
    {
        id: 3,
        nombre: 'Luis Ramos',
        correo: 'luis@mail.com',
        clave: bcrypt.hashSync('Luis#2026', 10),
        rol: 'user'
    }
];

let tareas = [
    {
        id: 1,
        titulo: 'Preparar informe de React',
        hecha: false,
        usuarioId: 2
    },
    {
        id: 2,
        titulo: 'Estudiar MongoDB',
        hecha: true,
        usuarioId: 2
    },
    {
        id: 3,
        titulo: 'Revisar seguridad de la API',
        hecha: false,
        usuarioId: 3
    }
];

// ==========================================
// 4. FUNCIONES DE VALIDACIÓN
// ==========================================

const correoValido = (correo) => {
    return typeof correo === 'string' &&
        correo.length <= 100 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo);
};

const claveFuerte = (clave) => {
    return typeof clave === 'string' &&
        clave.length >= 8 &&
        clave.length <= 72 &&
        /[A-Z]/.test(clave) &&
        /[a-z]/.test(clave) &&
        /[0-9]/.test(clave);
};

const textoValido = (texto, minimo, maximo) => {
    return typeof texto === 'string' &&
        texto.trim().length >= minimo &&
        texto.length <= maximo;
};

// ==========================================
// 5. MIDDLEWARE DE AUTENTICACIÓN JWT
// ==========================================

function autenticar(req, res, next) {
    const cabecera = req.headers.authorization || '';
    const [tipo, token, ...extra] = cabecera.split(' ');

    if (tipo !== 'Bearer' || !token || extra.length > 0) {
        return res.status(401).json({
            error: 'Token requerido'
        });
    }

    try {
        req.usuario = jwt.verify(
            token,
            JWT_SECRET,
            { algorithms: ['HS256'] }
        );

        next();

    } catch (error) {
        return res.status(401).json({
            error: 'Token inválido o expirado'
        });
    }
}

// ==========================================
// 6. MIDDLEWARE DE AUTORIZACIÓN POR ROL
// ==========================================

function soloRol(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.usuario.rol)) {
            return res.status(403).json({
                error: 'No tiene permisos para esta acción'
            });
        }

        next();
    };
}

// ==========================================
// 7. RUTA DE SALUD
// ==========================================

app.get('/api/salud', (req, res) => {
    res.json({
        estado: 'ok'
    });
});

// ==========================================
// 8. REGISTRO DE USUARIOS
// ==========================================

app.post('/api/auth/register', async (req, res, next) => {
    try {
        const { nombre, correo, clave } = req.body || {};

        if (!textoValido(nombre, 3, 60)) {
            return res.status(400).json({
                error: 'Nombre inválido (3 a 60 caracteres)'
            });
        }

        if (!correoValido(correo)) {
            return res.status(400).json({
                error: 'Correo inválido'
            });
        }

        if (!claveFuerte(clave)) {
            return res.status(400).json({
                error: 'La clave debe tener entre 8 y 72 caracteres, con mayúscula, minúscula y número'
            });
        }

        const correoNormalizado = correo.trim().toLowerCase();

        const existe = usuarios.some(
            u => u.correo === correoNormalizado
        );

        if (existe) {
            return res.status(409).json({
                error: 'El correo ya está registrado'
            });
        }

        const nuevo = {
            id: Math.max(0, ...usuarios.map(u => u.id)) + 1,
            nombre: nombre.trim(),
            correo: correoNormalizado,
            clave: await bcrypt.hash(clave, 10),
            rol: 'user'
        };

        usuarios.push(nuevo);

        res.status(201).json({
            id: nuevo.id,
            nombre: nuevo.nombre,
            correo: nuevo.correo
        });

    } catch (error) {
        next(error);
    }
});

// ==========================================
// 9. INICIO DE SESIÓN
// ==========================================

app.post('/api/auth/login', limiteLogin, async (req, res, next) => {
    try {
        const { correo, clave } = req.body || {};

        if (!correoValido(correo) ||
            typeof clave !== 'string') {
            return res.status(401).json({
                error: 'Credenciales incorrectas'
            });
        }

        const usuario = usuarios.find(
            u => u.correo === correo.trim().toLowerCase()
        );

        const valido = usuario &&
            await bcrypt.compare(clave, usuario.clave);

        if (!valido) {
            return res.status(401).json({
                error: 'Credenciales incorrectas'
            });
        }

        const token = jwt.sign(
            {
                id: usuario.id,
                rol: usuario.rol
            },
            JWT_SECRET,
            {
                algorithm: 'HS256',
                expiresIn: JWT_EXPIRES
            }
        );

        res.json({
            token,
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                rol: usuario.rol
            }
        });

    } catch (error) {
        next(error);
    }
});

// ==========================================
// 10. PERFIL DEL USUARIO AUTENTICADO
// ==========================================

app.get('/api/usuarios/yo', autenticar, (req, res) => {
    const usuario = usuarios.find(
        u => u.id === req.usuario.id
    );

    if (!usuario) {
        return res.status(404).json({
            error: 'Usuario no encontrado'
        });
    }

    const { clave, ...datosPublicos } = usuario;

    res.json(datosPublicos);
});

// ==========================================
// 11. LISTAR USUARIOS (SOLO ADMIN)
// ==========================================

app.get(
    '/api/usuarios',
    autenticar,
    soloRol('admin'),
    (req, res) => {
        const lista = usuarios.map(({ clave, ...resto }) => resto);

        res.json(lista);
    }
);

// ==========================================
// 12. PROTECCIÓN DE PROPIEDAD DE TAREAS
// ==========================================

const esAdmin = (req) => req.usuario.rol === 'admin';

function buscarTarea(req, res) {
    const id = Number(req.params.id);

    const tarea = Number.isInteger(id)
        ? tareas.find(t => t.id === id)
        : null;

    if (
        !tarea ||
        (!esAdmin(req) && tarea.usuarioId !== req.usuario.id)
    ) {
        res.status(404).json({
            error: '404 Tarea no encontrada'
        });

        return null;
    }

    return tarea;
}

// ==========================================
// 13. LISTAR TAREAS PROPIAS
// ==========================================

app.get('/api/tareas', autenticar, (req, res) => {
    const lista = esAdmin(req)
        ? tareas
        : tareas.filter(
            t => t.usuarioId === req.usuario.id
        );

    res.json(lista);
});

// ==========================================
// 14. CONSULTAR UNA TAREA
// ==========================================

app.get('/api/tareas/:id', autenticar, (req, res) => {
    const tarea = buscarTarea(req, res);

    if (tarea) {
        res.json(tarea);
    }
});

// ==========================================
// 15. CREAR UNA TAREA
// ==========================================

app.post('/api/tareas', autenticar, (req, res) => {
    const { titulo } = req.body || {};

    if (!textoValido(titulo, 3, 100)) {
        return res.status(400).json({
            error: 'Título inválido (3 a 100 caracteres)'
        });
    }

    const nueva = {
        id: Math.max(0, ...tareas.map(t => t.id)) + 1,
        titulo: titulo.trim(),
        hecha: false,
        usuarioId: req.usuario.id
    };

    tareas.push(nueva);

    res.status(201).json(nueva);
});

// ==========================================
// 16. MODIFICAR UNA TAREA
// ==========================================

app.put('/api/tareas/:id', autenticar, (req, res) => {
    const tarea = buscarTarea(req, res);

    if (!tarea) return;

    const { titulo, hecha } = req.body || {};

    const camposPermitidos = ['titulo', 'hecha'];

    const camposEnviados = Object.keys(req.body || {});

    if (
        camposEnviados.length === 0 ||
        camposEnviados.some(c => !camposPermitidos.includes(c))
    ) {
        return res.status(400).json({
            error: 'Solo se permite modificar titulo y hecha'
        });
    }

    if (titulo !== undefined) {
        if (!textoValido(titulo, 3, 100)) {
            return res.status(400).json({
                error: 'Título inválido'
            });
        }

        tarea.titulo = titulo.trim();
    }

    if (hecha !== undefined) {
        if (typeof hecha !== 'boolean') {
            return res.status(400).json({
                error: 'El campo hecha debe ser true o false'
            });
        }

        tarea.hecha = hecha;
    }

    res.json(tarea);
});

// ==========================================
// 17. ELIMINAR UNA TAREA
// ==========================================

app.delete('/api/tareas/:id', autenticar, (req, res) => {
    const tarea = buscarTarea(req, res);

    if (!tarea) return;

    tareas.splice(tareas.indexOf(tarea), 1);

    res.status(204).end();
});

// ==========================================
// 18. RUTAS INEXISTENTES
// ==========================================

app.use((req, res) => {
    res.status(404).json({
        error: 'Ruta no encontrada'
    });
});

// ==========================================
// 19. MANEJO DE ERRORES
// ==========================================

app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') {
        return res.status(413).json({
            error: 'Cuerpo de la petición demasiado grande'
        });
    }

    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({
            error: 'JSON inválido'
        });
    }

    console.error(err);

    res.status(500).json({
        error: 'Error interno del servidor'
    });
});

// ==========================================
// 20. INICIAR SERVIDOR
// ==========================================

app.listen(PORT, () => {
    console.log(`API segura escuchando en el puerto ${PORT}`);
});
