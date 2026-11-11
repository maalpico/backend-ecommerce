import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient, Rol } from '@prisma/client';

dotenv.config();

const prisma = new PrismaClient();
const app = express();
const puerto = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'jwt_super_secreto_para_firmar_tokens_123';

app.use(cors());
app.use(express.json());

// ==========================================
// TIPOS Y MIDDLEWARES DE AUTORIZACIÓN
// ==========================================

export interface TokenPayload {
  id: number;
  email: string;
  rol: Rol;
  tenantId?: string | null;
}

export interface AuthRequest extends Request {
  usuario?: TokenPayload;
}

const verificarToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token no proporcionado o formato inválido' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET) as TokenPayload;
    req.usuario = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
};

const soloSuperAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.usuario?.rol !== 'SUPERADMIN') {
    return res.status(403).json({ error: 'Acceso denegado: Se requiere rol SUPERADMIN' });
  }
  next();
};

// Permite acceso si es SUPERADMIN global o ADMIN del tenant solicitado
const accesoTenantAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  const usuario = req.usuario;
  if (!usuario) return res.status(401).json({ error: 'No autenticado' });

  if (usuario.rol === 'SUPERADMIN') {
    return next(); // El SUPERADMIN puede operar en cualquier tienda
  }

  const tenantSlug = req.params.tenantSlug || req.body.tenantSlug;
  if (usuario.rol === 'ADMIN') {
    return next();
  }

  return res.status(403).json({ error: 'Permisos insuficientes para administrar esta tienda' });
};

// ==========================================
// 1. GESTIÓN GLOBAL (SOLO SUPERADMIN)
// ==========================================

// Inicializar el primer SUPERADMIN de la plataforma (Ruta de arranque)
app.post('/api/superadmin/setup', async (req: Request, res: Response) => {
  try {
    const { email, password, nombre, telefono, masterKey } = req.body;

    // Validación de llave maestra para proteger el primer bootstrap
    const serverMasterKey = process.env.MASTER_SETUP_KEY || 'llave_maestra_bootstrap_2026';
    if (masterKey !== serverMasterKey) {
      return res.status(403).json({ error: 'Llave maestra de setup inválida' });
    }

    const existe = await prisma.usuario.findFirst({
      where: { email, rol: 'SUPERADMIN' },
    });
    if (existe) return res.status(400).json({ error: 'El SuperAdmin ya existe' });

    const passwordHash = await bcrypt.hash(password, 10);
    const superadmin = await prisma.usuario.create({
      data: {
        email,
        password: passwordHash,
        nombre,
        telefono: telefono || null,
        rol: 'SUPERADMIN',
        tenantId: null,
      } as any,
    });

    res.status(201).json({
      mensaje: 'SuperAdmin inicial configurado exitosamente',
      id: superadmin.id,
      email: superadmin.email,
    });
  } catch (error) {
    res.status(500).json({ error: 'Error al registrar SuperAdmin' });
  }
});

// Crear un nuevo Tenant (Exclusivo para SUPERADMIN)
app.post('/api/tenants', verificarToken, soloSuperAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const { nombre, slug, dominio } = req.body;

    if (!nombre || !slug) {
      return res.status(400).json({ error: 'Nombre y Slug son campos obligatorios' });
    }

    const existeSlug = await prisma.tenant.findUnique({ where: { slug } });
    if (existeSlug) return res.status(400).json({ error: 'El slug ya se encuentra en uso' });

    const tenant = await prisma.tenant.create({
      data: {
        nombre,
        slug: slug.toLowerCase().trim(),
        dominio: dominio ? dominio.toLowerCase().trim() : null,
      },
    });

    res.status(201).json(tenant);
  } catch (error) {
    res.status(500).json({ error: 'Error al crear la tienda (Tenant)' });
  }
});

// Listar todos los tenants existentes
app.get('/api/tenants', verificarToken, soloSuperAdmin, async (_req: AuthRequest, res: Response) => {
  try {
    const tenants = await prisma.tenant.findMany({
      include: {
        _count: { select: { usuarios: true, productos: true, sucursales: true } },
      },
      orderBy: { creadoEn: 'desc' },
    });
    res.json(tenants);
  } catch (error) {
    res.status(500).json({ error: 'Error al listar los tenants' });
  }
});

// ==========================================
// 2. AUTENTICACIÓN (LOGIN & REGISTRO)
// ==========================================

// Login universal (SUPERADMIN entra sin tenantSlug, ADMIN/CLIENTE con tenantSlug)
app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password, tenantSlug } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña requeridos' });
    }

    // 1. Caso Login SUPERADMIN (Global)
    if (!tenantSlug) {
      const superadmin = await prisma.usuario.findFirst({
        where: { email, rol: 'SUPERADMIN' },
      });

      if (!superadmin) return res.status(401).json({ error: 'Credenciales inválidas' });

      const valido = await bcrypt.compare(password, superadmin.password);
      if (!valido) return res.status(401).json({ error: 'Credenciales inválidas' });

      const token = jwt.sign(
        { id: superadmin.id, email: superadmin.email, rol: superadmin.rol, tenantId: null },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        token,
        usuario: {
          id: superadmin.id,
          nombre: superadmin.nombre,
          email: superadmin.email,
          telefono: superadmin.telefono,
          rol: superadmin.rol,
          tenant: 'GLOBAL_PLATFORM',
        },
      });
    }

    // 2. Caso Login de Tenant (ADMIN / CLIENTE / VENDEDOR)
    const tenant = await prisma.tenant.findUnique({ where: { slug: tenantSlug } });
    if (!tenant) return res.status(404).json({ error: 'Tienda no encontrada' });
    if (!tenant.activo) return res.status(403).json({ error: 'Esta tienda se encuentra suspendida' });

    const usuario = await prisma.usuario.findUnique({
      where: { email_tenantId: { email, tenantId: tenant.id } },
    });

    if (!usuario || !usuario.activo) return res.status(401).json({ error: 'Credenciales inválidas o usuario inactivo' });

    const valido = await bcrypt.compare(password, usuario.password);
    if (!valido) return res.status(401).json({ error: 'Credenciales inválidas' });

    const token = jwt.sign(
      { id: usuario.id, email: usuario.email, rol: usuario.rol, tenantId: tenant.id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        telefono: usuario.telefono,
        rol: usuario.rol,
        tenantId: tenant.id,
        tienda: tenant.nombre,
      },
    });
  } catch (error) {
    res.status(500).json({ error: 'Error durante el proceso de autenticación' });
  }
});

// Registro de Usuario dentro de un Tenant
app.post('/api/auth/registro', async (req: Request, res: Response) => {
  try {
    const { email, password, nombre, telefono, tenantSlug, rol } = req.body;

    const tenant = await prisma.tenant.findUnique({ where: { slug: tenantSlug } });
    if (!tenant) return res.status(404).json({ error: 'Tienda destino no encontrada' });

    const existe = await prisma.usuario.findUnique({
      where: { email_tenantId: { email, tenantId: tenant.id } },
    });
    if (existe) return res.status(400).json({ error: 'El usuario ya se encuentra registrado en esta tienda' });

    const passwordHash = await bcrypt.hash(password, 10);
    const nuevoUsuario = await prisma.usuario.create({
      data: {
        email,
        password: passwordHash,
        nombre,
        telefono: telefono || null,
        rol: rol && ['ADMIN', 'VENDEDOR', 'CLIENTE'].includes(rol) ? rol : 'CLIENTE',
        tenantId: tenant.id,
      },
    });

    res.status(201).json({
      id: nuevoUsuario.id,
      nombre: nuevoUsuario.nombre,
      email: nuevoUsuario.email,
      telefono: nuevoUsuario.telefono,
      rol: nuevoUsuario.rol,
      tenantId: nuevoUsuario.tenantId,
    });
  } catch (error) {
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// ==========================================
// 3. CATEGORÍAS RECURSIVAS (N-NIVELES)
// ==========================================

// Crear Categoría, Subcategoría, o Sub-subcategoría
app.post('/api/tiendas/:tenantSlug/categorias', verificarToken, accesoTenantAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const slugParam = req.params.tenantSlug;
    const tenantSlug = Array.isArray(slugParam) ? slugParam[0] : slugParam;

    if (!tenantSlug) {
      return res.status(400).json({ error: 'El slug de la tienda es requerido' });
    }

    const { nombre, slug, padreId } = req.body;

    console.log('--- CREANDO CATEGORÍA ---');
    console.log('Tenant:', tenantSlug);
    console.log('Payload:', { nombre, slug, padreId });

    const tenant = await prisma.tenant.findUnique({ 
      where: { slug: tenantSlug } 
    });
    
    if (!tenant) {
      console.error(`Tenant con slug "${tenantSlug}" no encontrado.`);
      return res.status(404).json({ error: `La tienda "${tenantSlug}" no existe en la base de datos` });
    }

    // Validar padreId solo si viene con valor numérico válido
    let padreIdValido: number | null = null;
    if (padreId !== undefined && padreId !== null && padreId !== '' && Number(padreId) > 0) {
      padreIdValido = Number(padreId);
      const padre = await prisma.categoria.findFirst({
        where: { id: padreIdValido, tenantId: tenant.id },
      });
      if (!padre) {
        return res.status(400).json({ error: 'La categoría padre no existe en esta tienda' });
      }
    }

    const categoria = await prisma.categoria.create({
      data: {
        nombre: nombre.trim(),
        slug: slug.toLowerCase().trim(),
        padreId: padreIdValido,
        tenantId: tenant.id,
      },
    });

    console.log('Categoría creada exitosamente:', categoria);
    res.status(201).json(categoria);
  } catch (error: any) {
    // ESTO TE MOSTRARÁ LA LÍNEA Y EL MOTIVO EXACTO EN LA TERMINAL
    console.error('ERROR DETALLADO EN PRISMA:', error);

    // Si es error de duplicado en PostgreSQL (código P2002 de Prisma)
    if (error.code === 'P2002') {
      return res.status(400).json({ 
        error: `Ya existe una categoría con el slug "${req.body.slug}" en esta tienda.` 
      });
    }

    res.status(500).json({ 
      error: error.message || 'Error al crear la categoría',
      prismaCode: error.code 
    });
  }
});

// Obtener el árbol jerárquico de categorías (Raíces con sus hijos y nietos anidados)
app.get('/api/tiendas/:tenantSlug/categorias/arbol', async (req: Request, res: Response) => {
  try {
    const tenantSlug = String(req.params.tenantSlug);
    const tenant = await prisma.tenant.findUnique({ where: { slug: tenantSlug } });
    if (!tenant) return res.status(404).json({ error: 'Tienda no encontrada' });

    // Consulta jerárquica: Raíces (padreId: null) cargando hijos y nietos recursivamente
    const arbol = await prisma.categoria.findMany({
      where: { tenantId: tenant.id, padreId: null, activo: true },
      include: {
        hijos: {
          where: { activo: true },
          include: {
            hijos: {
              where: { activo: true },
              include: { hijos: true }, // Nivel 4 disponible
            },
          },
        },
      },
      orderBy: { nombre: 'asc' },
    });

    res.json(arbol);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar categorías' });
  }
});

// ==========================================
// 4. CATÁLOGO DE PRODUCTOS DEL TENANT
// ==========================================

app.get('/api/tiendas/:tenantSlug/productos', async (req: Request, res: Response) => {
  try {
    const tenantSlug = String(req.params.tenantSlug);
    const tenant = await prisma.tenant.findUnique({ where: { slug: tenantSlug } });
    if (!tenant) return res.status(404).json({ error: 'Tienda no encontrada' });

    const productos = await prisma.producto.findMany({
      where: { tenantId: tenant.id, activo: true },
      include: {
        categoria: true,
        marca: true,
        variantes: {
          where: { activo: true },
          include: {
            imagenes: {
              include: { imagen: true },
              orderBy: { orden: 'asc' },
            },
          },
        },
      },
      orderBy: { creadoEn: 'desc' },
    });

    res.json(productos);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar catálogo' });
  }
});

app.listen(puerto, () => {
  console.log(`Backend Headless Multi-Tenant activo en http://localhost:${puerto}`);
});