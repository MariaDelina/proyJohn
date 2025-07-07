// index.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { pool, sql, poolConnect } = require('./db');
require('dotenv').config();
const cors = require('cors');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// 🔐 Middleware: verificar JWT
const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
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
  'https://wgimportaciones-aec89.web.app'
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
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

    const validPass = await bcrypt.compare(Password, user.Password);
    if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign(
      { id: user.UsuarioID, username: user.Username, rol: user.Rol },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    // ✅ Ahora también enviamos el rol
    res.json({ token, rol: user.Rol });
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
      .query("SELECT * FROM dbo.Ordenes WHERE Estado = 'pendiente'");

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
    const result = await pool
      .request()
      .query("SELECT * FROM dbo.Ordenes WHERE Estado = 'Listo para empacar'");

    res.json(result.recordset);
  } catch (err) {
    console.error('Error al obtener órdenes pendientes:', err);
    res.status(500).send('Error del servidor');
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
          DetalleID,
          OrdenID,
          Cantidad,
          CantidadReal,
          ValorUnitario,
          Ubicacion,
          DetalleAdicional,
          Secuencia,
          Referencia,
          Descripcion
        FROM dbo.DetalleOrdenes
        WHERE OrdenID = @OrdenID
        ORDER BY Secuencia
      `);

    res.json(result.recordset);
  } catch (error) {
    console.error('Error al obtener detalles de la orden:', error);
    res.status(500).json({ mensaje: 'Error del servidor' });
  }
});


//put para estado en Sacar-Pedido
app.put('/ordenes/:id/estado', verificarToken, async (req, res) => {
  const { id } = req.params;

  const nombreSacador = req.user?.Nombre  || 'Desconocido';

  // Fecha y hora actual en la zona horaria de Colombia
  const fechaColombia = new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Bogota' }));

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
  const fechaColombia = new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Bogota' }));

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
        UPDATE dbo.Ordenes
        SET 
          FechaEmpaque = @FechaEmpaque,
          FechaFinEmpaque = @FechaFinEmpaque,
          Empacador = @Empacador,
          Estado = @Estado
        WHERE Orden = @OrdenID
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
    await poolConnect;

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



app.listen(PORT, () => {
  console.log(`💫 Servidor corriendo en http://localhost:${PORT}`);
});