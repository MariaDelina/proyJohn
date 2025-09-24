// index.js
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { generateBlobSASQueryParameters, BlobSASPermissions, StorageSharedKeyCredential } = require('@azure/storage-blob');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { pool, sql, poolConnect } = require('./db');
require('dotenv').config();
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const { Readable } = require('stream');
const containerClient = require('./azureBlob'); // tu archivo azureBlob.js
const storage = multer.memoryStorage(); // 👈 guardamos en memoria, no en disco
const upload = multer({ storage }); 
const dayjs = require('dayjs');
const utc = require('dayjs/plugin/utc');
const timezone = require('dayjs/plugin/timezone');
dayjs.extend(utc);
dayjs.extend(timezone);

const PORT = process.env.PORT || 3000;

// 🔐 Middleware: verificar JWT
const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });

    req.user = decoded; // ⬅️ Esto permite acceder a req.user.Nombre
    next();
  });
};



// 🔐 Middleware: verificar rol
const verificarRol = (rolesPermitidos) => {
  return (req, res, next) => {
    if (!rolesPermitidos.includes(req.user.rol)) {
      return res.status(403).json({ error: 'Acceso denegado: rol insuficiente' });
    }
    next();
  };
};
//Cors
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'https://wgimportaciones-aec89.web.app',
  'https://proyjohn.onrender.com',
  
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  credentials: true
}));


// 🧠 Registrar usuario
app.post('/auth/register', async (req, res) => {
  const { Username, Password, Nombre, Apellido, Celular, Rol } = req.body;

  if (!Username || !Password) {
    return res.status(400).json({ error: 'Username y Password requeridos' });
  }

  try {
    await poolConnect;
    const hashedPassword = await bcrypt.hash(Password, 10);

    await pool.request()
      .input('Username', sql.NVarChar(100), Username)
      .input('Password', sql.NVarChar(100), hashedPassword)
      .input('Nombre', sql.NVarChar(100), Nombre || null)
      .input('Apellido', sql.NVarChar(100), Apellido || null)
      .input('Celular', sql.NVarChar(20), Celular || null)
      .input('Rol', sql.NVarChar(50), Rol || 'Operario')
      .query(`INSERT INTO Usuarios (Username, Password, Nombre, Apellido, Celular, Rol)
              VALUES (@Username, @Password, @Nombre, @Apellido, @Celular, @Rol)`);

    res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
  } catch (err) {
    console.error('Error en registro:', err);
    res.status(500).send('Error del servidor');
  }
});

// 🔐 Login y JWT
app.post('/auth/login', async (req, res) => {
  const { Nombre, Password } = req.body;

  if (!Nombre || !Password) {
    return res.status(400).json({ error: 'Nombre y Password requeridos' });
  }

  try {
    await poolConnect;
    const result = await pool.request()
      .input('Nombre', sql.NVarChar(100), Nombre)
      .query('SELECT * FROM Usuarios WHERE Nombre = @Nombre');

    const user = result.recordset[0];
    if (!user) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const validPass = await bcrypt.compare(Password, user.Password);
    if (!validPass) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    // 🔐 Generamos el token incluyendo el id, username y rol
    const token = jwt.sign(
      {
        id: user.UsuarioID,          // <- este ID se extraerá luego en rutas protegidas
        username: user.Username,
        rol: user.Rol,
        Nombre: user.Nombre
      },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    // ✅ Enviamos el token + datos que el frontend necesita guardar
    res.json({
      token,
      rol: user.Rol,
      usuarioId: user.UsuarioID,
      nombre: user.Nombre,
    });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).send('Error del servidor');
  }
});




// 🟢 Ruta pública (todos los roles)
app.get('/ordenes', verificarToken, async (req, res) => {
  try {
    await poolConnect;
    const result = await pool.request().query('SELECT * FROM dbo.Ordenes');
    res.json(result.recordset);
  } catch (err) {
    console.error('Error al obtener órdenes:', err);
    res.status(500).send('Error del servidor');
  }
});
//Ruta para traer todo de tabla productos
app.get('/productos', verificarToken, async (req, res) => {
  try {
    await poolConnect;
    const result = await pool.request().query('SELECT * FROM dbo.Productos');
    res.json(result.recordset);
  } catch (err) {
    console.error('Error al obtener productos:', err);
    res.status(500).send('Error del servidor');
  }
});

app.put('/productos/:id/imagen', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { imagen } = req.body;

  if (typeof imagen !== 'string') {
    return res.status(400).json({ error: 'La URL de la imagen es requerida y debe ser texto' });
  }

  try {
    await poolConnect;
    const result = await pool.request()
      .input('id', sql.Int, id)
      .input('imagen', sql.NVarChar(sql.MAX), imagen)
      .query(`
        UPDATE Productos
        SET Imagen = @imagen
        WHERE ID = @id
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    res.json({ message: 'Imagen actualizada correctamente' });
  } catch (error) {
    console.error('Error al actualizar imagen:', error);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Ruta DELETE para borrar solo la imagen de un producto
app.delete('/productos/:id/imagen', verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    await poolConnect;
    const result = await pool.request()
      .input('id', sql.Int, id)
      .query(`
        UPDATE Productos
        SET Imagen = NULL
        WHERE ID = @id
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    res.json({ message: 'Imagen eliminada correctamente' });
  } catch (error) {
    console.error('Error al eliminar imagen:', error);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.get('/productos-detalles-con-imagen', verificarToken, async (req, res) => {
  try {
    await poolConnect;

    const result = await pool.request().query(`
      SELECT 
        pd.*,
        p.Imagen
      FROM DetalleOrdenes pd
      LEFT JOIN Productos p ON pd.Referencia = p.Referencia
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error al obtener productos detalles con imagen:', err);
    res.status(500).send('Error del servidor');
  }
});


// 🟠 Ruta que trae solo órdenes con estado pendiente
app.get('/ordenes/pendientes', verificarToken, async (req, res) => {
  try {
    await poolConnect;

    const result = await pool
      .request()
      .query(`
        SELECT *
        FROM dbo.Ordenes 
        WHERE 
          Estado IN ('Pendiente', 'En Proceso', 'Empacando')
          AND (FechaFinSacado IS NULL OR LTRIM(RTRIM(FechaFinSacado)) = '')
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error al obtener órdenes pendientes:', err);
    res.status(500).send('Error del servidor');
  }
});


//Empacar Pedido segun estado Listo para empacar
app.get('/ordenes/listoparaempacar', verificarToken, async (req, res) => {
  try {
    await poolConnect;

    const result = await pool.request().query(`
      SELECT *
      FROM dbo.Ordenes
      WHERE 
        Estado IN ('Listo para empacar', 'Empacando', 'En Proceso')
        AND (FechaFinEmpaque IS NULL OR LTRIM(RTRIM(FechaFinEmpaque)) = '')
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error al obtener órdenes para empacar:', err);
    return res.status(500).send('Error del servidor');
  }
});





// recuperar productos y detalles de orden
app.get('/detalle-ordenes/:id', verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    await poolConnect;

    const result = await pool.request()
      .input('OrdenID', sql.Int, id)
      .query(`
        SELECT 
          d.DetalleID,
          d.OrdenID,
          d.Cantidad,
          d.CantidadReal,
          d.CantidadEmpacada,
          d.Caja,
          d.ValorUnitario,
          d.Ubicacion,
          d.DetalleAdicional,
          o.Observaciones,     -- 🔹 viene de la tabla Ordenes
          d.Secuencia,
          d.Referencia,
          d.Descripcion
        FROM dbo.DetalleOrdenes d
        LEFT JOIN dbo.Ordenes o
          ON d.OrdenID = o.Orden   -- 🔹 cambiar según el nombre correcto
        WHERE d.OrdenID = @OrdenID
        ORDER BY d.Secuencia
      `);

    res.json(result.recordset);
  } catch (error) {
    console.error('Error al obtener detalles de la orden:', error);
    res.status(500).json({ mensaje: 'Error del servidor' });
  }
});


app.put('/ordenes/:id/estado', verificarToken, async (req, res) => {
  const { id } = req.params;
  const nombreSacador = req.user?.Nombre || 'Desconocido';

const fechaColombia = dayjs().tz('America/Bogota').toDate();

  try {
    await poolConnect;

    const result = await pool
      .request()
      .input('OrdenID', sql.Int, id)
      .input('Estado', sql.VarChar, 'En Proceso')
      .input('FechaInicio', sql.DateTime, fechaColombia)
      .input('Sacador', sql.VarChar, nombreSacador)
      .query(`
        UPDATE dbo.Ordenes
        SET 
          Estado = @Estado,
          FechaInicioSacado = @FechaInicio,
          Sacador = @Sacador
        WHERE Orden = @OrdenID
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ mensaje: 'Orden no encontrada' });
    }

    res.json({ mensaje: 'Orden actualizada a En Proceso correctamente' });
  } catch (err) {
    console.error('Error al actualizar orden:', err);
    res.status(500).send('Error del servidor');
  }
});

// Put para Empacar-Pedido 
app.put('/ordenes/:id/estado-empaque', verificarToken, async (req, res) => {
  const { id } = req.params;

  const nombreEmpacador = req.user?.Nombre  || 'Desconocido';

  // Fecha y hora actual en la zona horaria de Colombia
   const fechaBogotaStr = dayjs().tz('America/Bogota').format('YYYY-MM-DD HH:mm:ss');
 const fechaColombia = dayjs().tz('America/Bogota').toDate();


  try {
    await poolConnect;

    const result = await pool
      .request()
      .input('OrdenID', sql.Int, id)
      .input('Estado', sql.VarChar, 'Empacando')
      .input('FechaInicio', sql.DateTime, fechaColombia)
      .input('Empacador', sql.VarChar, nombreEmpacador)
      .query(`
        UPDATE dbo.Ordenes
        SET 
          Estado = @Estado,
          FechaInicioEmpaque = @FechaInicio,
          Empacador = @Empacador
        WHERE Orden = @OrdenID
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ mensaje: 'Orden no encontrada' });
    }

    res.json({ mensaje: 'Orden actualizada a Empacando correctamente' });
  } catch (err) {
    console.error('Error al actualizar orden:', err);
    res.status(500).send('Error del servidor');
  }
});



// 🔍 Ruta protegida: solo 'manager'
app.get('/ordenes/:id', verificarToken, verificarRol(['Manager']), async (req, res) => {
  const id = req.params.id;
  try {
    await poolConnect;
    const result = await pool
      .request()
      .input('Orden', sql.Int, id)
      .query('SELECT * FROM dbo.Ordenes WHERE Orden = @Orden');

    if (result.recordset.length === 0) {
      return res.status(404).send('Orden no encontrada');
    }

    res.json(result.recordset[0]);
  } catch (err) {
    console.error('Error al buscar la orden:', err);
    res.status(500).send('Error del servidor');
  }
});

// 🛠️ Iniciar el proceso de sacado de una orden
app.post('/orden/:id/sacado/start', verificarToken, async (req, res) => {
  const ordenId = req.params.id;

  try {
    await poolConnect;

    // 1. Obtener datos del usuario autenticado
    const nombre = req.user.nombre;

    // 2. Verificar que exista la orden
    const ordenExistente = await pool
      .request()
      .input('Orden', sql.Int, ordenId)
      .query('SELECT * FROM dbo.Ordenes WHERE Orden = @Orden');

    if (ordenExistente.recordset.length === 0) {
      return res.status(404).json({ error: 'Orden no encontrada' });
    }

    // 3. Actualizar la orden
    const ahora = new Date();

    await pool.request()
      .input('FechaAlistamiento', sql.DateTime, ahora)
      .input('Sacador', sql.NVarChar(100), nombre)
      .input('FechaInicioSacado', sql.DateTime, ahora)
      .input('Estado', sql.NVarChar(50), 'En proceso')
      .input('Orden', sql.Int, ordenId)
      .query(`
        UPDATE dbo.Ordenes
        SET 
          FechaAlistamiento = @FechaAlistamiento,
          Sacador = @Sacador,
          FechaInicioSacado = @FechaInicioSacado,
          Estado = @Estado
        WHERE Orden = @Orden
      `);

    res.status(200).json({ mensaje: `Orden ${ordenId} actualizada a 'En proceso'` });
  } catch (err) {
    console.error('Error al iniciar sacado:', err);
    res.status(500).send('Error del servidor');
  }
});

app.post('/orden/:id/sacado/finish', verificarToken, async (req, res) => {
  const id = req.params.id;
  const fechaFinSacado = new Date();

  try {
    await poolConnect;
    const result = await pool.request()
      .input('id', sql.Int, id)
      .input('FechaFinSacado', sql.DateTime, fechaFinSacado)
      .input('Estado', sql.NVarChar(50), 'listo para empacar')
      .query(`
        UPDATE dbo.Ordenes 
        SET FechaFinSacado = @FechaFinSacado, Estado = @Estado 
        WHERE Orden = @id
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: 'Orden no encontrada' });
    }

    res.json({ mensaje: 'Orden actualizada: sacado finalizado' });
  } catch (err) {
    console.error('Error al finalizar sacado:', err);
    res.status(500).send('Error del servidor');
  }
});

//tabla OrdenesDetalles
app.get('/detalle-ordenes', verificarToken, async (req, res) => {
  try {
    await poolConnect;
    const result = await pool.request().query('SELECT * FROM dbo.DetalleOrdenes');
    res.json(result.recordset);
  } catch (error) {
    console.error('Error al obtener detalles de órdenes:', error);
    res.status(500).send('Error del servidor');
  }
});

app.get('/ordenes-info/:id', verificarToken, async (req, res) => {
  try {
    await poolConnect;
    const { id } = req.params;
    const result = await pool
      .request()
      .input('Orden', sql.Int, id)
      .query('SELECT * FROM dbo.Ordenes WHERE Orden = @Orden');

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }

    res.json(result.recordset[0]);
  } catch (error) {
    console.error('Error al obtener la orden:', error);
    res.status(500).send('Error del servidor');
  }
});

app.put('/ordenes-info/:id/observacion-sacador', verificarToken, async (req, res) => {
  try {
    await poolConnect;
    const { id } = req.params;
    const { observacion } = req.body;

    if (!observacion || typeof observacion !== 'string') {
      return res.status(400).json({ message: 'Observación inválida o faltante' });
    }

    const result = await pool
      .request()
      .input('Orden', sql.Int, id)
      .input('ObservacionesSacador', sql.NVarChar(sql.MAX), observacion)
      .query('UPDATE dbo.Ordenes SET ObservacionesSacador = @ObservacionesSacador WHERE Orden = @Orden');

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }

    res.json({ message: 'Observación del sacador actualizada correctamente' });
  } catch (error) {
    console.error('Error al actualizar ObservacionesSacador:', error);
    res.status(500).send('Error del servidor');
  }
});

app.put('/ordenes-info/:id/observacion-empacador', verificarToken, async (req, res) => {
  try {
    await poolConnect;
    const { id } = req.params;
    const { observacion } = req.body;

    if (!observacion || typeof observacion !== 'string') {
      return res.status(400).json({ message: 'Observación inválida o faltante' });
    }

    const result = await pool
      .request()
      .input('Orden', sql.Int, id)
      .input('ObservacionesEmpacador', sql.NVarChar(sql.MAX), observacion)
      .query('UPDATE dbo.Ordenes SET ObservacionesEmpacador = @ObservacionesEmpacador WHERE Orden = @Orden');

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }

    res.json({ message: 'Observación del sacador actualizada correctamente' });
  } catch (error) {
    console.error('Error al actualizar ObservacionesEmpacador:', error);
    res.status(500).send('Error del servidor');
  }
});

// index.js o rutas/detalleOrdenes.js Modificacion de Cantidad en OrdenesDetalle
app.put('/detalle-ordenes/:id/cantidad', verificarToken, async (req, res) => {
  const detalleID = req.params.id;
  const { cantidad } = req.body;

  if (cantidad == null) {
    return res.status(400).send('Falta la cantidad');
  }

  try {
    await poolConnect;
    const result = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .input('Cantidad', sql.Int, cantidad)
      .query('UPDATE dbo.DetalleOrdenes SET Cantidad = @Cantidad WHERE DetalleID = @DetalleID');

    if (result.rowsAffected[0] === 0) {
      return res.status(404).send('Detalle no encontrado');
    }

    res.send(`Cantidad actualizada para DetalleID ${detalleID}`);
  } catch (error) {
    console.error('Error al actualizar la cantidad:', error);
    res.status(500).send('Error del servidor');
  }
});
// Actualizacion cantidad real para cuando es diferente a cantidad
app.put('/detalle-ordenes/:id/cantidad-real', verificarToken, async (req, res) => {
  const detalleID = req.params.id;
  const { cantidadReal } = req.body;

  if (cantidadReal == null) {
    return res.status(400).send('Falta la cantidad real');
  }

  try {
    await poolConnect;

    // Verificamos que el detalle exista
    const currentResult = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .query('SELECT CantidadReal FROM dbo.DetalleOrdenes WHERE DetalleID = @DetalleID');

    if (currentResult.recordset.length === 0) {
      return res.status(404).send('Detalle no encontrado');
    }

    // En vez de sumar, asignamos directamente la cantidad recibida
    const nuevaCantidad = cantidadReal;

    // Actualizamos la base de datos con el nuevo valor directamente
    const updateResult = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .input('CantidadReal', sql.Int, nuevaCantidad)
      .query('UPDATE dbo.DetalleOrdenes SET CantidadReal = @CantidadReal WHERE DetalleID = @DetalleID');

    if (updateResult.rowsAffected[0] === 0) {
      return res.status(404).send('Detalle no encontrado');
    }

    res.send(`CantidadReal actualizada para DetalleID ${detalleID}, nueva cantidad: ${nuevaCantidad}`);
  } catch (error) {
    console.error('Error al actualizar la cantidad real:', error);
    res.status(500).send('Error del servidor');
  }
});

app.put('/detalle-ordenes/:id/cantidad-empacada', verificarToken, async (req, res) => {
  const detalleID = req.params.id;
  const { cantidadEmpacada } = req.body;

  if (cantidadEmpacada == null) {
    return res.status(400).send('Falta la cantidad empacada');
  }

  try {
    await poolConnect;

    const currentResult = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .query('SELECT DetalleID FROM dbo.DetalleOrdenes WHERE DetalleID = @DetalleID');

    if (currentResult.recordset.length === 0) {
      return res.status(404).send('Detalle no encontrado');
    }

    const updateResult = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .input('CantidadEmpacada', sql.Int, cantidadEmpacada)
      .query(`
        UPDATE dbo.DetalleOrdenes
        SET CantidadEmpacada = @CantidadEmpacada
        WHERE DetalleID = @DetalleID
      `);

    if (updateResult.rowsAffected[0] === 0) {
      return res.status(404).send('No se pudo actualizar la cantidad empacada');
    }

    res.status(200).json({
      message: `Cantidad empacada actualizada para el detalle ${detalleID}`,
      cantidadEmpacada,
    });
  } catch (error) {
    console.error('Error al actualizar cantidad empacada:', error);
    res.status(500).send('Error del servidor');
  }
});

app.put('/detalle-ordenes/:id/caja', verificarToken, async (req, res) => {
  const detalleID = req.params.id;
  const { caja } = req.body;

  if (caja == null) {
    return res.status(400).send('Falta la caja');
  }

  try {
    await poolConnect;

    const currentResult = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .query('SELECT DetalleID FROM dbo.DetalleOrdenes WHERE DetalleID = @DetalleID');

    if (currentResult.recordset.length === 0) {
      return res.status(404).send('Detalle no encontrado');
    }

    const updateResult = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .input('Caja', sql.Int(100), caja)
      .query(`
        UPDATE dbo.DetalleOrdenes
        SET Caja = @Caja
        WHERE DetalleID = @DetalleID
      `);

    if (updateResult.rowsAffected[0] === 0) {
      return res.status(404).send('No se pudo actualizar la caja');
    }

    res.status(200).json({
      message: `Caja actualizada para el detalle ${detalleID}`,
      caja,
    });
  } catch (error) {
    console.error('Error al actualizar la caja:', error);
    res.status(500).send('Error del servidor');
  }
});




app.put('/ordenes/:id/finalizar', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { FechaAlistamiento, FechaFinSacado } = req.body;

  // Obtener nombre del usuario desde el token
  const Sacador = req.user.Nombre || 'Desconocido';

  if (!FechaAlistamiento || !FechaFinSacado) {
    return res.status(400).json({ message: 'Faltan datos requeridos.' });
  }

  try {
    await poolConnect;

    const result = await pool.request()
      .input('FechaAlistamiento', sql.DateTime, new Date(FechaAlistamiento))
      .input('FechaFinSacado', sql.DateTime, new Date(FechaFinSacado))
      .input('Sacador', sql.NVarChar(100), Sacador)
      .input('OrdenID', sql.Int, id)
      .input('Estado', sql.NVarChar(50), 'Listo para empacar')
      .query(`
        UPDATE dbo.Ordenes
        SET FechaAlistamiento = @FechaAlistamiento,
            FechaFinSacado = @FechaFinSacado,
            Sacador = @Sacador,
            Estado = @Estado
        WHERE Orden = @OrdenID
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }

    res.status(200).json({ message: 'Orden finalizada con éxito y estado actualizado' });
  } catch (error) {
    console.error('Error al finalizar orden:', error);
    res.status(500).json({ message: 'Error al finalizar orden', error: error.message });
  }
});

app.put('/ordenes/:id/finalizar-empaque', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { FechaEmpaque, FechaFinEmpaque } = req.body;

  // Verificamos que los datos necesarios estén presentes
  if (!FechaEmpaque || !FechaFinEmpaque) {
    return res.status(400).json({ message: 'Faltan datos requeridos: FechaEmpaque, FechaFinEmpaque.' });
  }

  const Empacador = req.user?.Nombre  || 'Desconocido';

  try {
    await poolConnect;

    const result = await pool.request()
      .input('OrdenID', sql.Int, id)
      .input('FechaEmpaque', sql.DateTime, new Date(FechaEmpaque))
      .input('FechaFinEmpaque', sql.DateTime, new Date(FechaFinEmpaque))
      .input('Empacador', sql.NVarChar(100), Empacador)
      .input('Estado', sql.NVarChar(50), 'Listo para despachar')
      .query(`
        -- Agregá un filtro para no sobreescribir el Sacador
UPDATE dbo.Ordenes
SET 
  FechaEmpaque = @FechaEmpaque,
  FechaFinEmpaque = @FechaFinEmpaque,
  Empacador = @Empacador,
  Estado = @Estado
WHERE Orden = @OrdenID AND Sacador IS NOT NULL

      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }

    res.status(200).json({ message: 'Orden finalizada y marcada como "Listo para despachar"' });
  } catch (error) {
    console.error('Error al finalizar empaque:', error);
    res.status(500).json({ message: 'Error al finalizar empaque', error: error.message });
  }
});


app.get('/ordenes-terminadas', verificarToken, async (req, res) => {
  try {
   await poolConnect;;

    const query = `
      SELECT 
        o.FechaCreacion,
        o.Vendedor,
        o.Cliente,
        o.Ciudad,
        o.Departamento,
        o.Direccion,
        o.Observaciones,
        o.ObservacionesSacador,
        o.ObservacionesEmpacador,
        o.Sacador,
        o.Empacador,
        o.Cedula,
        o.Orden,
        d.DetalleID,
        d.OrdenID,
        d.Referencia,
        d.Descripcion,
        d.Cantidad,
        d.Caja,
        d.CantidadReal,
        d.CantidadEmpacada,
        d.OrdenOriginal,
        d.ValorUnitario,
        d.DetalleAdicional
      FROM dbo.Ordenes o
      LEFT JOIN dbo.DetalleOrdenes d ON o.Orden = d.OrdenID
      WHERE o.Estado = 'Listo para despachar'
      ORDER BY o.Orden, d.DetalleID
    `;

    const result = await pool.request().query(query);

    // Validación defensiva por si algún dato está malformado
    const datosSanitizados = result.recordset.map(item => ({
      ...item,
      Cantidad: typeof item.Cantidad === 'number' ? item.Cantidad : parseInt(item.Cantidad),
      CantidadEmpacada: typeof item.CantidadEmpacada === 'number' ? item.CantidadEmpacada : parseInt(item.CantidadEmpacada),
    }));

    res.json(datosSanitizados);
  } catch (error) {
    console.error('Error al obtener órdenes terminadas:', error);
    res.status(500).send('Error del servidor');
  }
});

app.post('/obtener-url-subida', async (req, res) => {
  const { fileName, fileType } = req.body;

  const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
  const key = process.env.AZURE_STORAGE_ACCOUNT_KEY;
  const container = process.env.AZURE_STORAGE_CONTAINER_NAME;

  const sharedKeyCredential = new StorageSharedKeyCredential(account, key);

  const blobName = `${Date.now()}-${fileName}`;
  const sasOptions = {
    containerName: container,
    blobName,
    permissions: BlobSASPermissions.parse('cw'), // create + write
    expiresOn: new Date(new Date().valueOf() + 10 * 60 * 1000),
  };

  const sasToken = generateBlobSASQueryParameters(sasOptions, sharedKeyCredential).toString();
  const uploadUrl = `https://${account}.blob.core.windows.net/${container}/${blobName}?${sasToken}`;

  res.json({ uploadUrl, blobUrl: uploadUrl.split('?')[0] }); // `blobUrl` es el que guardarás luego
});

app.put('/ordenes/:id/finalizar-revision', verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    await poolConnect;

    const query = `
      UPDATE dbo.Ordenes
      SET Estado = 'Terminado'
      WHERE Orden = @id
    `;

    await pool.request()
      .input('id', id)
      .query(query);

    res.status(200).json({ message: 'Estado actualizado a Terminado' });
  } catch (error) {
    console.error('Error al finalizar revisión:', error);
    res.status(500).send('Error del servidor');
  }
});

// Crear tarea y asignarla
app.post('/crear-con-asignacion', async (req, res) => {
  const {
    nombre,
    descripcion,
    tipoTarea,
    frecuencia,
    creadoPor,
    operarioId,
    fechaAsignacion,
    fechaVencimiento,
  } = req.body;

  try {
    if (!nombre || !tipoTarea || !creadoPor || !operarioId || !fechaAsignacion) {
      return res.status(400).json({ error: 'Faltan datos obligatorios' });
    }
    if (isNaN(parseInt(creadoPor)) || isNaN(parseInt(operarioId))) {
      return res.status(400).json({ error: 'creadoPor y operarioId deben ser números' });
    }
    const fechaAsign = new Date(fechaAsignacion);
    const fechaVenc = fechaVencimiento ? new Date(fechaVencimiento) : null;
    if (isNaN(fechaAsign.getTime()) || (fechaVencimiento && isNaN(fechaVenc.getTime()))) {
      return res.status(400).json({ error: 'Fechas inválidas' });
    }

    await poolConnect;

    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    try {
      const request1 = new sql.Request(transaction);
      const tareaResult = await request1
        .input('Nombre', sql.NVarChar(100), nombre)
        .input('Descripcion', sql.NVarChar(255), descripcion || null)
        .input('TipoTarea', sql.NVarChar(20), tipoTarea)
        .input('Frecuencia', sql.NVarChar(50), frecuencia || null)
        .input('CreadoPor', sql.Int, creadoPor)
        .input('Estado', sql.NVarChar(20), 'pendiente') // <-- estado de la tarea
        .query(`
          INSERT INTO dbo.Tareas (Nombre, Descripcion, TipoTarea, Frecuencia, CreadoPor, Estado)
          OUTPUT INSERTED.TareaID
          VALUES (@Nombre, @Descripcion, @TipoTarea, @Frecuencia, @CreadoPor, @Estado)
        `);

      const tareaId = tareaResult.recordset[0].TareaID;

      const request2 = new sql.Request(transaction);
      await request2
        .input('TareaID', sql.Int, tareaId)
        .input('OperarioID', sql.Int, operarioId)
        .input('FechaAsignacion', sql.DateTime, fechaAsign)
        .input('FechaVencimiento', sql.DateTime, fechaVenc)
        .input('Estado', sql.NVarChar(20), 'pendiente')
        .query(`
          INSERT INTO dbo.AsignacionesTareas (TareaID, OperarioID, FechaAsignacion, FechaVencimiento, Estado)
          VALUES (@TareaID, @OperarioID, @FechaAsignacion, @FechaVencimiento, @Estado)
        `);

      await transaction.commit();

      res.status(201).json({ success: true, tareaId });
    } catch (err) {
      await transaction.rollback();
      throw err;
    }

  } catch (err) {
    console.error('Error al crear tarea:', err);
    res.status(500).json({ error: 'Error al crear la tarea y asignación' });
  }
});



app.get('/tareas-asignadas/:usuarioId', async (req, res) => {
  const { usuarioId } = req.params;

  try {
    await poolConnect;
    const request = pool.request();

    const result = await request
      .input('UsuarioID', sql.Int, usuarioId)
      .query(`
        SELECT
          T.TareaID,
          T.Nombre AS NombreTarea,
          T.Descripcion,
          T.Estado AS EstadoTarea,
          A.AsignacionID,
          A.CriteriosEvaluacion,
          U.Nombre AS NombreOperario,
          E.Enlace AS Evidencia,
          E.Notas,
          E.TipoArchivo,
          E.TamanoArchivo,
          E.ThumbnailLink,
          E.FechaSubida,
          E.SubidoPor,
          E.EvidenciaID
        FROM dbo.AsignacionesTareas A
        INNER JOIN dbo.Tareas T ON A.TareaID = T.TareaID
        INNER JOIN dbo.Usuarios U ON A.OperarioID = U.UsuarioID
        LEFT JOIN dbo.EvidenciasTareas E ON E.AsignacionID = A.AsignacionID
        WHERE A.OperarioID = @UsuarioID AND A.Estado = 'pendiente'
        ORDER BY T.FechaCreacion DESC
      `);

    res.json({ success: true, tareas: result.recordset });
  } catch (error) {
    console.error('Error al obtener tareas asignadas:', error);
    res.status(500).json({ error: 'Error al obtener tareas asignadas' });
  }
});

app.get('/tareas-en-proceso/:usuarioId', async (req, res) => {
  const { usuarioId } = req.params;

  try {
    await poolConnect;
    const request = pool.request();

    const result = await request
      .input('UsuarioID', sql.Int, usuarioId)
      .query(`
        SELECT
          T.TareaID,
          T.Nombre AS NombreTarea,
          T.Descripcion,
          T.Estado AS EstadoTarea,
          A.AsignacionID,
          A.CriteriosEvaluacion,
          U.Nombre AS NombreOperario,
          E.Enlace AS Evidencia,
          E.Notas,
          E.TipoArchivo,
          E.TamanoArchivo,
          E.ThumbnailLink,
          E.FechaSubida,
          E.SubidoPor,
          E.EvidenciaID
        FROM dbo.AsignacionesTareas A
        INNER JOIN dbo.Tareas T ON A.TareaID = T.TareaID
        INNER JOIN dbo.Usuarios U ON A.OperarioID = U.UsuarioID
        LEFT JOIN dbo.EvidenciasTareas E ON E.AsignacionID = A.AsignacionID
        WHERE A.OperarioID = @UsuarioID AND A.Estado = 'en proceso'
        ORDER BY T.FechaCreacion DESC
      `);

    res.json({ success: true, tareas: result.recordset });
  } catch (error) {
    console.error('Error al obtener tareas en proceso:', error);
    res.status(500).json({ error: 'Error al obtener tareas en proceso' });
  }
});


app.put('/tarea/:tareaId/finalizar', async (req, res) => {
  const { tareaId } = req.params;
  const { subidoPor, evidenciaUrl, notas } = req.body;

  try {
    await poolConnect;

    const asignacionRes = await pool.request()
      .input('TareaID', sql.Int, tareaId)
      .query(`SELECT TOP 1 AsignacionID FROM dbo.AsignacionesTareas WHERE TareaID = @TareaID`);

    const asignacionId = asignacionRes.recordset[0]?.AsignacionID;
    if (!asignacionId) {
      return res.status(404).json({ error: 'Asignación no encontrada' });
    }

    await pool.request()
      .input('AsignacionID', sql.Int, asignacionId)
      .input('SubidoPor', sql.Int, subidoPor)
      .input('Enlace', sql.NVarChar(255), evidenciaUrl)
      .input('TipoArchivo', sql.NVarChar(50), 'desconocido') // o sacalo si no lo usás
      .input('TamanoArchivo', sql.Int, 0) // opcional
      .input('FechaSubida', sql.DateTime, new Date())
      .query(`
        INSERT INTO dbo.EvidenciasTareas (AsignacionID, SubidoPor, Enlace, TipoArchivo, TamanoArchivo, FechaSubida)
        VALUES (@AsignacionID, @SubidoPor, @Enlace, @TipoArchivo, @TamanoArchivo, @FechaSubida)
      `);

    await pool.request()
      .input('AsignacionID', sql.Int, asignacionId)
      .query(`UPDATE dbo.AsignacionesTareas SET Estado = 'en proceso' WHERE AsignacionID = @AsignacionID`);

    res.json({ success: true, mensaje: 'Tarea finalizada y evidencia registrada' });
  } catch (err) {
    console.error('Error al guardar evidencia:', err);
    res.status(500).json({ error: 'Error al guardar la evidencia' });
  }
});
//asignar ORDENES


// PUT /ordenes/:id/asignar
app.put('/ordenes/:id/asignar', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { operarioId } = req.body;

  if (!operarioId) {
    return res.status(400).json({ error: 'Falta el ID del operario' });
  }

  try {
    await pool.request()
      .input('ordenId', sql.Int, parseInt(id))
      .input('operarioId', sql.Int, operarioId)
      .query(`
        UPDATE Ordenes
        SET OperarioID = @operarioId
        WHERE Orden = @ordenId
      `);

    res.json({ message: 'Orden asignada correctamente' });
  } catch (err) {
    console.error('Error al asignar orden:', err);
    res.status(500).json({ error: 'Error al asignar la orden' });
  }
});


//listar usuarios en asignacion de usuario
app.get('/usuarios-operarios', async (req, res) => {
  try {
    await poolConnect; // asegurarse de que la conexión esté lista

    const request = new sql.Request(pool);
    const result = await request.query(`
      SELECT UsuarioID, Nombre, Apellido
      FROM dbo.Usuarios
      WHERE Rol = 'operario'
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error al obtener operarios:', err);
    res.status(500).json({ error: 'Error al obtener operarios' });
  }
});
// Productos segun la referencia Stock
app.get('/productos/:referencia', verificarToken, async (req, res) => {
  const { referencia } = req.params;

  try {
    await poolConnect;

    const result = await pool.request()
      .input('Referencia', sql.VarChar, referencia)
      .query('SELECT Referencia, Nombre, Stock FROM dbo.Productos WHERE Referencia = @Referencia');

    if (result.recordset.length === 0) {
      return res.status(404).json({ mensaje: 'No se encontró el producto' });
    }

    res.json(result.recordset[0]); // devuelve un único producto
  } catch (err) {
    console.error('Error al obtener producto:', err);
    res.status(500).send('Error del servidor');
  }
});
//buscar por referencia, sugerencias 
// Todas las referencias (filtrado en SQL con LIKE si quieres autocomplete en el servidor)
app.get('/productos-referencias', verificarToken, async (req, res) => {
  try {
    await poolConnect;

    const result = await pool.request()
      .query('SELECT Referencia FROM dbo.Productos');

    res.json(result.recordset); // lista de objetos con Referencia
  } catch (err) {
    console.error('Error al obtener referencias:', err);
    res.status(500).send('Error del servidor');
  }
});



app.listen(PORT, () => {
  console.log(`💫 Servidor corriendo en http://localhost:${PORT}`);
});