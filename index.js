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
  const { Username, Password } = req.body;
  if (!Username || !Password) {
    return res.status(400).json({ error: 'Username y Password requeridos' });
  }

  try {
    await poolConnect;
    const result = await pool.request()
      .input('Username', sql.NVarChar(100), Username)
      .query('SELECT * FROM Usuarios WHERE Username = @Username');

    const user = result.recordset[0];
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

    const validPass = await bcrypt.compare(Password, user.Password);
    if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.UsuarioID, username: user.Username, rol: user.Rol }, process.env.JWT_SECRET, {
      expiresIn: '2h'
    });

    res.json({ token });
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

  const nombreSacador = req.user?.Nombre || req.user?.username || 'Desconocido';

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

  const nombreEmpacador = req.user?.Nombre || req.user?.username || 'Desconocido';

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
    const username = req.user.username;

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
      .input('Sacador', sql.NVarChar(100), username)
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

    // Verificar que el detalle exista
    const currentResult = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .query('SELECT CantidadEmpacada FROM dbo.DetalleOrdenes WHERE DetalleID = @DetalleID');

    if (currentResult.recordset.length === 0) {
      return res.status(404).send('Detalle no encontrado');
    }

    // Actualizar la base de datos con el nuevo valor directamente
    const updateResult = await pool
      .request()
      .input('DetalleID', sql.Int, detalleID)
      .input('CantidadEmpacada', sql.Int, cantidadEmpacada)
      .query('UPDATE dbo.DetalleOrdenes SET CantidadEmpacada = @CantidadEmpacada WHERE DetalleID = @DetalleID');

    if (updateResult.rowsAffected[0] === 0) {
      return res.status(404).send('Detalle no encontrado');
    }

    res.send(`CantidadEmpacada actualizada para DetalleID ${detalleID}, nueva cantidad: ${cantidadEmpacada}`);
  } catch (error) {
    console.error('Error al actualizar la cantidad empacada:', error);
    res.status(500).send('Error del servidor');
  }
});



app.put('/ordenes/:id/finalizar', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { FechaAlistamiento, FechaFinSacado } = req.body;

  // Obtener nombre del usuario desde el token
  const Sacador = req.user.Nombre || req.user.username || 'Desconocido';

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
  const { FechaEmpaque, FechaFinEmpaque, Caja } = req.body;

  // Verificamos que los datos necesarios estén presentes
  if (!FechaEmpaque || !FechaFinEmpaque || !Caja) {
    return res.status(400).json({ message: 'Faltan datos requeridos: FechaEmpaque, FechaFinEmpaque o Caja.' });
  }

  const Empacador = req.user?.Nombre || req.user?.username || 'Desconocido';

  try {
    await poolConnect;

    const result = await pool.request()
      .input('OrdenID', sql.Int, id)
      .input('FechaEmpaque', sql.DateTime, new Date(FechaEmpaque))
      .input('FechaFinEmpaque', sql.DateTime, new Date(FechaFinEmpaque))
      .input('Empacador', sql.NVarChar(100), Empacador)
      .input('Caja', sql.NVarChar(50), Caja)
      .input('Estado', sql.NVarChar(50), 'Listo para despachar')
      .query(`
        UPDATE dbo.Ordenes
        SET 
          FechaEmpaque = @FechaEmpaque,
          FechaFinEmpaque = @FechaFinEmpaque,
          Empacador = @Empacador,
          Caja = @Caja,
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





app.listen(PORT, () => {
  console.log(`💫 Servidor corriendo en http://localhost:${PORT}`);
});