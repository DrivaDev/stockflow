const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const { User, Admin, Discount, Product, Movement, connect, init } = require('./database');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET    = process.env.JWT_SECRET    || 'stockflow_secret_admin_2024';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'stockflow_secret_client_2024';

const PLANS = {
  basic: { name: 'Plan Básico', price: 30000, products: 500 },
  pro:   { name: 'Plan Pro',    price: 50000, products: null }
};

const PAYMENT_LABELS = {
  efectivo: 'Efectivo', debito: 'Tarjeta Débito',
  credito: 'Tarjeta Crédito', transferencia: 'Transferencia', otro: 'Otro'
};

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// DB en cada request (necesario para Vercel serverless)
app.use(async (req, res, next) => {
  try { await connect(); next(); } catch (e) { res.status(500).json({ error: 'Error de base de datos' }); }
});

// ── EMAIL ─────────────────────────────────────────────────────────────────────
async function sendEmail(to, subject, html) {
  if (!process.env.GMAIL_PASS || !process.env.GMAIL_USER) {
    console.log('Email omitido: GMAIL_USER o GMAIL_PASS no configurados');
    return;
  }
  try {
    const mailer = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS }
    });
    await mailer.sendMail({
      from: `"GestionStock" <${process.env.GMAIL_USER}>`,
      to, subject, html
    });
    console.log('Email enviado a:', to);
  } catch (e) {
    console.error('Email error:', e.message, '| Code:', e.code);
  }
}

// ── AUTH MIDDLEWARES ──────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  try { req.admin = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido' }); }
}

function requireClient(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  try { req.client = jwt.verify(auth.slice(7), CLIENT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Sesión expirada' }); }
}

async function requireSubscription(req, res, next) {
  try {
    const user = await User.findById(req.client.id);
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    const now = new Date();

    if (user.subscriptionStatus === 'trial') {
      if (user.trialEndsAt && user.trialEndsAt < now) {
        const dataDeleteAt = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
        await User.updateOne({ _id: user._id }, { $set: { subscriptionStatus: 'suspended', dataDeleteAt } });
        return res.status(402).json({ error: 'Tu período de prueba terminó. Realizá el pago para continuar.', code: 'TRIAL_EXPIRED' });
      }
      return next();
    }

    if (user.subscriptionStatus === 'active') {
      if (user.paidUntil && user.paidUntil < now) {
        const dataDeleteAt = user.dataDeleteAt || new Date(user.paidUntil.getTime() + 90 * 24 * 60 * 60 * 1000);
        if (now > dataDeleteAt) {
          await Product.deleteMany({ userId: user._id });
          await Movement.deleteMany({ userId: user._id });
          await User.updateOne({ _id: user._id }, { $set: { subscriptionStatus: 'cancelled', dataDeleteAt: null } });
          return res.status(402).json({ error: 'Tu suscripción expiró y los datos del negocio fueron eliminados por inactividad prolongada.', code: 'DATA_DELETED' });
        }
        await User.updateOne({ _id: user._id }, { $set: { subscriptionStatus: 'suspended', dataDeleteAt } });
        return res.status(402).json({ error: 'Tu suscripción ha vencido. Realizá el pago para continuar.', code: 'SUBSCRIPTION_EXPIRED' });
      }
      return next();
    }

    if (user.subscriptionStatus === 'pending') {
      const gracePeriod = new Date(user.createdAt.getTime() + 3 * 24 * 60 * 60 * 1000);
      if (now < gracePeriod) return next();
      return res.status(402).json({ error: 'Necesitás completar el pago para acceder al sistema.', code: 'PAYMENT_REQUIRED' });
    }

    if (user.subscriptionStatus === 'suspended') {
      if (user.dataDeleteAt && now > user.dataDeleteAt) {
        await Product.deleteMany({ userId: user._id });
        await Movement.deleteMany({ userId: user._id });
        await User.updateOne({ _id: user._id }, { $set: { subscriptionStatus: 'cancelled', dataDeleteAt: null } });
        return res.status(402).json({ error: 'Tu suscripción expiró y los datos del negocio fueron eliminados.', code: 'DATA_DELETED' });
      }
      return res.status(402).json({ error: 'Tu suscripción está suspendida. Realizá el pago para continuar.', code: 'SUBSCRIPTION_SUSPENDED' });
    }

    return res.status(402).json({ error: 'Suscripción inactiva.', code: 'SUBSCRIPTION_INACTIVE' });
  } catch (e) { next(); } // En caso de error, permitir acceso para no romper el sistema
}

// ── SETUP ─────────────────────────────────────────────────────────────────────
app.get('/api/setup', async (req, res) => {
  try {
    const exists = await Admin.findOne({ username: 'JuanMSilva' });
    if (exists) return res.json({ message: 'Admin ya existe' });
    const hash = bcrypt.hashSync('JuamiAdmin12-', 10);
    await Admin.create({ username: 'JuanMSilva', password: hash });
    res.json({ message: 'Admin creado correctamente' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ADMIN LOGIN ───────────────────────────────────────────────────────────────
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Datos incompletos' });
    const admin = await Admin.findOne({ username });
    if (!admin || !bcrypt.compareSync(password, admin.password))
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    const token = jwt.sign({ id: admin._id, username: admin.username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, username: admin.username });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── VALIDAR DESCUENTO ─────────────────────────────────────────────────────────
app.post('/api/discount/validate', async (req, res) => {
  try {
    const { code, plan } = req.body;
    if (!code || !plan) return res.status(400).json({ error: 'Faltan datos' });
    const discount = await Discount.findOne({ code: code.toUpperCase(), active: true });
    if (!discount) return res.status(404).json({ error: 'Código no válido o inactivo' });
    if (discount.expiresAt && discount.expiresAt < new Date()) return res.status(400).json({ error: 'El código ha expirado' });
    if (discount.maxUses !== null && discount.currentUses >= discount.maxUses) return res.status(400).json({ error: 'El código ya alcanzó su límite de usos' });
    if (discount.applicablePlans !== 'all' && discount.applicablePlans !== plan) return res.status(400).json({ error: `Este código no aplica al ${PLANS[plan]?.name}` });
    const basePrice = PLANS[plan].price;
    const finalPrice = discount.discountType === 'percentage'
      ? Math.round(basePrice * (1 - discount.discountValue / 100))
      : Math.max(0, basePrice - discount.discountValue);
    res.json({ valid: true, description: discount.description, discount_type: discount.discountType, discount_value: discount.discountValue, original_price: basePrice, final_price: finalPrice });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── REGISTRO CLIENTE ──────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, phone, business_name, plan, discount_code, password } = req.body;
    if (!name || !email || !plan) return res.status(400).json({ error: 'Nombre, email y plan son requeridos' });
    if (!password || password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    if (!PLANS[plan]) return res.status(400).json({ error: 'Plan inválido' });

    const basePrice = PLANS[plan].price;
    let finalPrice = basePrice, validatedCode = null;

    if (discount_code) {
      const disc = await Discount.findOne({ code: discount_code.toUpperCase(), active: true });
      if (disc && (!disc.expiresAt || disc.expiresAt >= new Date()) &&
          (disc.maxUses === null || disc.currentUses < disc.maxUses) &&
          (disc.applicablePlans === 'all' || disc.applicablePlans === plan)) {
        finalPrice = disc.discountType === 'percentage'
          ? Math.round(basePrice * (1 - disc.discountValue / 100))
          : Math.max(0, basePrice - disc.discountValue);
        validatedCode = disc.code;
        await Discount.updateOne({ _id: disc._id }, { $inc: { currentUses: 1 } });
      }
    }

    // Suscripción: básico = 14 días de prueba, pro = pendiente de pago (3 días de gracia)
    const now = new Date();
    let subscriptionStatus, trialEndsAt = null;
    if (plan === 'basic') {
      subscriptionStatus = 'trial';
      trialEndsAt = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
    } else {
      subscriptionStatus = 'pending';
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    try {
      const user = await User.create({
        name, email, phone: phone || null, businessName: business_name || null,
        plan, status: 'active', subscriptionStatus, trialEndsAt,
        discountCode: validatedCode, originalPrice: basePrice, finalPrice,
        password: hashedPassword
      });

      const appUrl = process.env.APP_URL || 'https://stockflow-omega-seven.vercel.app';
      const trialMsg = plan === 'basic'
        ? `<tr><td style="padding:.4rem 0;color:#64748B">Período de prueba</td><td style="font-weight:600">14 días gratuitos</td></tr>`
        : `<tr><td style="padding:.4rem 0;color:#64748B">Estado</td><td style="font-weight:600;color:#EA580C">Pendiente de pago</td></tr>`;

      sendEmail(email, '¡Bienvenido a GestionStock!', `
        <div style="font-family:Inter,Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;color:#1A1A2E">
          <div style="background:linear-gradient(135deg,#EA580C,#F97316);border-radius:14px;padding:2rem;text-align:center;margin-bottom:2rem">
            <h1 style="color:#fff;margin:0;font-size:1.6rem">GestionStock</h1>
            <p style="color:rgba(255,255,255,.85);margin:.5rem 0 0">Sistema de gestión de stock</p>
          </div>
          <h2 style="color:#EA580C">¡Hola ${name}!</h2>
          <p>Tu cuenta fue creada exitosamente. Estos son tus datos:</p>
          <table style="width:100%;background:#FFF7ED;border-radius:10px;padding:1rem;margin:1.5rem 0;border-collapse:collapse">
            <tr><td style="padding:.4rem 0;color:#64748B">Plan</td><td style="font-weight:600">${PLANS[plan].name}</td></tr>
            <tr><td style="padding:.4rem 0;color:#64748B">Precio mensual</td><td style="font-weight:600">$${finalPrice.toLocaleString('es-AR')}</td></tr>
            <tr><td style="padding:.4rem 0;color:#64748B">Email</td><td style="font-weight:600">${email}</td></tr>
            ${trialMsg}
          </table>
          <a href="${appUrl}/login" style="display:inline-block;background:linear-gradient(135deg,#EA580C,#F97316);color:#fff;padding:.75rem 1.75rem;border-radius:10px;text-decoration:none;font-weight:700">Ingresar al sistema</a>
          <p style="margin-top:2rem;color:#64748B;font-size:.85rem">Si tenés alguna duda respondé este email y te ayudamos.</p>
          <p style="color:#94A3B8;font-size:.75rem;margin-top:2rem">Desarrollado por <strong>Driva Dev</strong></p>
        </div>
      `);

      res.status(201).json({
        id: user._id,
        message: plan === 'basic'
          ? '¡Registro exitoso! Tenés 14 días de prueba gratuita.'
          : '¡Registro exitoso! Completá el pago para activar tu cuenta.',
        plan: PLANS[plan].name,
        final_price: finalPrice,
        subscription_status: subscriptionStatus
      });
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: 'Ya existe un usuario con ese email' });
      throw e;
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ADMIN: USUARIOS ───────────────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { status, plan, search } = req.query;
    const query = {};
    if (status) query.status = status;
    if (plan)   query.plan = plan;
    if (search) query.$or = [{ name: new RegExp(search,'i') }, { email: new RegExp(search,'i') }, { businessName: new RegExp(search,'i') }];

    const allUsers = await User.find(query).sort({ createdAt: -1 }).select('-password');
    const all = await User.find({});
    const stats = {
      total: all.length,
      active: all.filter(u => u.status === 'active').length,
      basic: all.filter(u => u.plan === 'basic').length,
      pro: all.filter(u => u.plan === 'pro').length,
      monthly_revenue: all.filter(u => u.status === 'active').reduce((s, u) => s + u.finalPrice, 0)
    };
    res.json({ users: allUsers.map(normalizeUser), stats });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const { status, notes, plan, subscriptionStatus, paidUntil } = req.body;
    const update = {};
    if (status) update.status = status;
    if (notes !== undefined) update.notes = notes;
    if (plan && PLANS[plan]) { update.plan = plan; update.originalPrice = PLANS[plan].price; update.finalPrice = PLANS[plan].price; }
    if (subscriptionStatus) update.subscriptionStatus = subscriptionStatus;
    if (paidUntil !== undefined) {
      update.paidUntil = paidUntil ? new Date(paidUntil) : null;
      if (paidUntil) update.subscriptionStatus = 'active';
    }
    await User.updateOne({ _id: req.params.id }, { $set: update });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    await User.deleteOne({ _id: req.params.id });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ADMIN: DESCUENTOS ─────────────────────────────────────────────────────────
app.get('/api/admin/discounts', requireAdmin, async (req, res) => {
  try {
    const all = await Discount.find().sort({ createdAt: -1 });
    res.json(all.map(normalizeDiscount));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/discounts', requireAdmin, async (req, res) => {
  try {
    const { code, description, discount_type, discount_value, applicable_plans, max_uses, expires_at } = req.body;
    if (!code || !discount_type || !discount_value) return res.status(400).json({ error: 'Faltan campos requeridos' });
    try {
      const d = await Discount.create({ code: code.toUpperCase(), description: description || null, discountType: discount_type, discountValue: parseInt(discount_value), applicablePlans: applicable_plans || 'all', maxUses: max_uses ? parseInt(max_uses) : null, expiresAt: expires_at || null });
      res.status(201).json({ id: d._id, success: true });
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: 'Ese código ya existe' });
      throw e;
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/discounts/:id', requireAdmin, async (req, res) => {
  try {
    const { active, description, max_uses, expires_at } = req.body;
    const update = {};
    if (active !== undefined) update.active = !!active;
    if (description !== undefined) update.description = description;
    if (max_uses !== undefined) update.maxUses = max_uses;
    if (expires_at !== undefined) update.expiresAt = expires_at || null;
    await Discount.updateOne({ _id: req.params.id }, { $set: update });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/discounts/:id', requireAdmin, async (req, res) => {
  try { await Discount.deleteOne({ _id: req.params.id }); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CLIENT AUTH ───────────────────────────────────────────────────────────────
app.post('/api/client/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Datos incompletos' });
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !user.password || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Email o contraseña incorrectos' });
    if (user.status === 'inactive') return res.status(403).json({ error: 'Tu cuenta está inactiva. Contactá al soporte.' });
    const token = jwt.sign({ id: user._id, email: user.email, plan: user.plan }, CLIENT_SECRET, { expiresIn: '24h' });
    res.json({
      token, name: user.name, email: user.email, plan: user.plan,
      businessName: user.businessName,
      subscriptionStatus: user.subscriptionStatus,
      trialEndsAt: user.trialEndsAt,
      paidUntil: user.paidUntil
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/client/me', requireClient, async (req, res) => {
  try {
    const user = await User.findById(req.client.id).select('-password');
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({
      name: user.name, email: user.email, plan: user.plan,
      businessName: user.businessName, status: user.status,
      subscriptionStatus: user.subscriptionStatus,
      trialEndsAt: user.trialEndsAt, paidUntil: user.paidUntil
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PAYMENT: STATUS ───────────────────────────────────────────────────────────
app.get('/api/payment/status', requireClient, async (req, res) => {
  try {
    const user = await User.findById(req.client.id);
    const now = new Date();
    let active = false, daysLeft = 0, message = '';

    if (user.subscriptionStatus === 'trial') {
      if (user.trialEndsAt && user.trialEndsAt > now) {
        active = true;
        daysLeft = Math.ceil((user.trialEndsAt - now) / (1000 * 60 * 60 * 24));
        message = `Período de prueba: ${daysLeft} día${daysLeft !== 1 ? 's' : ''} restante${daysLeft !== 1 ? 's' : ''}`;
      } else {
        message = 'Tu período de prueba ha terminado.';
      }
    } else if (user.subscriptionStatus === 'active') {
      if (!user.paidUntil || user.paidUntil > now) {
        active = true;
        if (user.paidUntil) {
          daysLeft = Math.ceil((user.paidUntil - now) / (1000 * 60 * 60 * 24));
          message = `Suscripción activa: ${daysLeft} día${daysLeft !== 1 ? 's' : ''} restante${daysLeft !== 1 ? 's' : ''}`;
        } else {
          message = 'Suscripción activa';
        }
      } else {
        message = 'Tu suscripción ha vencido.';
      }
    } else if (user.subscriptionStatus === 'pending') {
      const gracePeriod = new Date(user.createdAt.getTime() + 3 * 24 * 60 * 60 * 1000);
      if (now < gracePeriod) {
        active = true;
        daysLeft = Math.ceil((gracePeriod - now) / (1000 * 60 * 60 * 24));
        message = `Período de gracia: completá el pago pronto (${daysLeft} día${daysLeft !== 1 ? 's' : ''})`;
      } else {
        message = 'Necesitás completar el pago para acceder.';
      }
    } else {
      message = user.subscriptionStatus === 'cancelled'
        ? 'Suscripción cancelada. Tus datos de negocio fueron eliminados.'
        : 'Suscripción suspendida. Realizá el pago para continuar.';
    }

    res.json({
      active, message, daysLeft,
      status: user.subscriptionStatus,
      plan: user.plan,
      planName: PLANS[user.plan]?.name,
      finalPrice: user.finalPrice,
      paidUntil: user.paidUntil,
      trialEndsAt: user.trialEndsAt
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PAYMENT: CREAR PREFERENCIA MERCADOPAGO ────────────────────────────────────
app.post('/api/payment/create-preference', requireClient, async (req, res) => {
  if (!process.env.MP_ACCESS_TOKEN) {
    return res.status(503).json({ error: 'Pagos online no configurados. Contactá al soporte.' });
  }
  try {
    const user = await User.findById(req.client.id);
    const plan = PLANS[user.plan];
    const amount = user.finalPrice || plan.price;
    const appUrl = process.env.APP_URL || 'https://stockflow-omega-seven.vercel.app';

    const { MercadoPagoConfig, Preference } = require('mercadopago');
    const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
    const preferenceApi = new Preference(mpClient);

    const result = await preferenceApi.create({
      body: {
        items: [{
          title: `GestionStock - ${plan.name} (mensual)`,
          quantity: 1,
          unit_price: amount,
          currency_id: 'ARS'
        }],
        payer: { email: user.email, name: user.name },
        back_urls: {
          success: `${appUrl}/app?payment=success`,
          failure: `${appUrl}/app?payment=failure`,
          pending: `${appUrl}/app?payment=pending`
        },
        auto_return: 'approved',
        external_reference: user._id.toString(),
        notification_url: `${appUrl}/api/payment/webhook`,
        statement_descriptor: 'GestionStock'
      }
    });

    res.json({ payment_url: result.init_point, preference_id: result.id });
  } catch (e) {
    console.error('MercadoPago error:', e.message);
    res.status(500).json({ error: 'Error al crear preferencia de pago: ' + e.message });
  }
});

// ── PAYMENT: WEBHOOK MERCADOPAGO ──────────────────────────────────────────────
app.post('/api/payment/webhook', async (req, res) => {
  try {
    const { type, data } = req.body;
    if (type === 'payment' && data?.id && process.env.MP_ACCESS_TOKEN) {
      const { MercadoPagoConfig, Payment } = require('mercadopago');
      const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
      const paymentApi = new Payment(mpClient);
      const paymentData = await paymentApi.get({ id: data.id });

      if (paymentData.status === 'approved') {
        const userId = paymentData.external_reference;
        const now = new Date();
        const paidUntil = new Date(now);
        paidUntil.setMonth(paidUntil.getMonth() + 1);

        await User.updateOne(
          { _id: userId },
          { $set: { subscriptionStatus: 'active', paidUntil, dataDeleteAt: null } }
        );

        const user = await User.findById(userId);
        if (user) {
          sendEmail(user.email, 'Pago confirmado - GestionStock', `
            <div style="font-family:Inter,Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;color:#1A1A2E">
              <h2 style="color:#10B981">Pago confirmado</h2>
              <p>Hola ${user.name}, tu pago fue procesado correctamente.</p>
              <p>Tu suscripción al <strong>${PLANS[user.plan]?.name}</strong> está activa hasta el <strong>${paidUntil.toLocaleDateString('es-AR')}</strong>.</p>
              <p style="color:#64748B;font-size:.85rem;margin-top:2rem">Desarrollado por <strong>Driva Dev</strong></p>
            </div>
          `);
        }
      }
    }
    res.sendStatus(200);
  } catch (e) {
    console.error('Webhook error:', e.message);
    res.sendStatus(200); // Siempre 200 para que MP no reintente
  }
});

// ── PRODUCTOS ─────────────────────────────────────────────────────────────────
app.get('/api/client/products', requireClient, requireSubscription, async (req, res) => {
  try {
    const { search, category, low_stock } = req.query;
    const query = { userId: req.client.id };
    if (category) query.category = category;
    if (low_stock === '1') query.$expr = { $lte: ['$stock', '$minStock'] };

    let prods = await Product.find(query).sort({ name: 1 });
    if (search) { const re = new RegExp(search,'i'); prods = prods.filter(p => re.test(p.name) || re.test(p.barcode) || re.test(p.category)); }

    const all = await Product.find({ userId: req.client.id });
    const stats = {
      total: all.length,
      low_stock: all.filter(p => p.stock > 0 && p.stock <= p.minStock).length,
      out_of_stock: all.filter(p => p.stock === 0).length,
      total_value: all.reduce((s, p) => s + p.stock * (p.costPrice || 0), 0)
    };
    res.json({ products: prods, stats });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/client/products', requireClient, requireSubscription, async (req, res) => {
  try {
    const user = await User.findById(req.client.id);
    const plan = PLANS[user.plan];
    if (plan.products !== null) {
      const count = await Product.countDocuments({ userId: req.client.id });
      if (count >= plan.products) return res.status(403).json({ error: `Tu plan permite hasta ${plan.products} productos. Actualizá al Plan Pro para tener productos ilimitados.` });
    }
    const { name, category, barcode, stock, minStock, costPrice, salePrice, unit, description } = req.body;
    if (!name) return res.status(400).json({ error: 'El nombre es requerido' });
    const prod = await Product.create({ userId: req.client.id, name: name.trim(), category: category || 'General', barcode: barcode || null, stock: parseInt(stock) || 0, minStock: parseInt(minStock) || 5, costPrice: parseFloat(costPrice) || 0, salePrice: parseFloat(salePrice) || 0, unit: unit || 'unidad', description: description || null });
    res.status(201).json(prod);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/client/products/:id', requireClient, requireSubscription, async (req, res) => {
  try {
    const prod = await Product.findOne({ _id: req.params.id, userId: req.client.id });
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    const { name, category, barcode, minStock, costPrice, salePrice, unit, description } = req.body;
    const update = {};
    if (name) update.name = name.trim();
    if (category) update.category = category;
    if (barcode !== undefined) update.barcode = barcode;
    if (minStock !== undefined) update.minStock = parseInt(minStock) || 0;
    if (costPrice !== undefined) update.costPrice = parseFloat(costPrice) || 0;
    if (salePrice !== undefined) update.salePrice = parseFloat(salePrice) || 0;
    if (unit) update.unit = unit;
    if (description !== undefined) update.description = description;
    await Product.updateOne({ _id: req.params.id }, { $set: update });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/client/products/:id', requireClient, requireSubscription, async (req, res) => {
  try {
    await Product.deleteOne({ _id: req.params.id, userId: req.client.id });
    await Movement.deleteMany({ productId: req.params.id, userId: req.client.id });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── VENTAS ────────────────────────────────────────────────────────────────────
app.post('/api/client/ventas', requireClient, requireSubscription, async (req, res) => {
  try {
    const { productId, quantity, unitPrice, paymentMethod, note } = req.body;
    if (!productId || !quantity || !paymentMethod) return res.status(400).json({ error: 'Datos incompletos' });

    const prod = await Product.findOne({ _id: productId, userId: req.client.id });
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });

    const qty = parseInt(quantity);
    if (qty <= 0) return res.status(400).json({ error: 'La cantidad debe ser mayor a 0' });
    if (prod.stock < qty) return res.status(400).json({ error: `Stock insuficiente. Disponible: ${prod.stock} ${prod.unit}` });

    const price = parseFloat(unitPrice) || prod.salePrice || 0;
    const newStock = prod.stock - qty;

    await Product.updateOne({ _id: productId }, { $set: { stock: newStock } });

    const mov = await Movement.create({
      userId: req.client.id, productId,
      productName: prod.name, category: prod.category || 'General',
      type: 'venta', quantity: qty,
      stockBefore: prod.stock, stockAfter: newStock,
      unitPrice: price, costPrice: prod.costPrice || 0,
      totalAmount: qty * price,
      paymentMethod: paymentMethod || 'efectivo',
      note: note || null
    });

    res.status(201).json({ ...mov.toObject(), newStock });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/client/ventas', requireClient, requireSubscription, async (req, res) => {
  try {
    const { from, to, paymentMethod, limit: lim = 100 } = req.query;
    const query = { userId: req.client.id, type: 'venta' };
    if (from || to) {
      query.createdAt = {};
      if (from) query.createdAt.$gte = new Date(from);
      if (to) { const toDate = new Date(to); toDate.setHours(23,59,59,999); query.createdAt.$lte = toDate; }
    }
    if (paymentMethod) query.paymentMethod = paymentMethod;
    const ventas = await Movement.find(query).sort({ createdAt: -1 }).limit(parseInt(lim));
    res.json(ventas);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CAJA ──────────────────────────────────────────────────────────────────────
app.get('/api/client/caja', requireClient, requireSubscription, async (req, res) => {
  try {
    const { date } = req.query;
    const targetDate = date ? new Date(date) : new Date();
    const start = new Date(targetDate); start.setHours(0,0,0,0);
    const end   = new Date(targetDate); end.setHours(23,59,59,999);

    const ventas = await Movement.find({
      userId: req.client.id, type: 'venta',
      createdAt: { $gte: start, $lte: end }
    });

    const byMethod = {};
    let total = 0, count = 0;
    for (const v of ventas) {
      const m = v.paymentMethod || 'otro';
      if (!byMethod[m]) byMethod[m] = { label: PAYMENT_LABELS[m] || m, total: 0, count: 0 };
      byMethod[m].total += v.totalAmount || 0;
      byMethod[m].count++;
      total += v.totalAmount || 0;
      count++;
    }

    res.json({ byMethod, total, count, date: targetDate });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── COMPRAS ───────────────────────────────────────────────────────────────────
app.post('/api/client/compras', requireClient, requireSubscription, async (req, res) => {
  try {
    const { productId, quantity, costPrice, note } = req.body;
    if (!productId || !quantity) return res.status(400).json({ error: 'Datos incompletos' });

    const prod = await Product.findOne({ _id: productId, userId: req.client.id });
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });

    const qty = parseInt(quantity);
    if (qty <= 0) return res.status(400).json({ error: 'La cantidad debe ser mayor a 0' });
    const cost = parseFloat(costPrice) || 0;
    const newStock = prod.stock + qty;

    const update = { stock: newStock };
    if (cost > 0) update.costPrice = cost;
    await Product.updateOne({ _id: productId }, { $set: update });

    const mov = await Movement.create({
      userId: req.client.id, productId,
      productName: prod.name, category: prod.category || 'General',
      type: 'compra', quantity: qty,
      stockBefore: prod.stock, stockAfter: newStock,
      costPrice: cost || prod.costPrice || 0,
      totalAmount: qty * (cost || prod.costPrice || 0),
      note: note || null
    });

    res.status(201).json({ ...mov.toObject(), newStock });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/client/compras', requireClient, requireSubscription, async (req, res) => {
  try {
    const { limit: lim = 100 } = req.query;
    const compras = await Movement.find({ userId: req.client.id, type: { $in: ['compra', 'in'] } })
      .sort({ createdAt: -1 }).limit(parseInt(lim));
    res.json(compras);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── AJUSTE DE STOCK ───────────────────────────────────────────────────────────
app.post('/api/client/movements', requireClient, requireSubscription, async (req, res) => {
  try {
    const { productId, type, quantity, note } = req.body;
    if (!productId || !type || !quantity) return res.status(400).json({ error: 'Datos incompletos' });
    if (!['in','out','adjustment','venta','compra'].includes(type)) return res.status(400).json({ error: 'Tipo inválido' });
    const prod = await Product.findOne({ _id: productId, userId: req.client.id });
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    const qty = parseInt(quantity);
    let newStock;
    if (type === 'in' || type === 'compra') newStock = prod.stock + qty;
    else if (type === 'out' || type === 'venta') {
      if (prod.stock < qty) return res.status(400).json({ error: `Stock insuficiente. Disponible: ${prod.stock}` });
      newStock = prod.stock - qty;
    } else newStock = qty;
    await Product.updateOne({ _id: productId }, { $set: { stock: newStock } });
    const mov = await Movement.create({ userId: req.client.id, productId, productName: prod.name, category: prod.category, type, quantity: qty, stockBefore: prod.stock, stockAfter: newStock, note: note || null });
    res.status(201).json({ ...mov.toObject(), newStock });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/client/movements', requireClient, requireSubscription, async (req, res) => {
  try {
    const { productId, type, limit: lim = 50 } = req.query;
    const query = { userId: req.client.id };
    if (productId) query.productId = productId;
    if (type) query.type = type;
    const movs = await Movement.find(query).sort({ createdAt: -1 }).limit(parseInt(lim));
    res.json(movs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ESTADÍSTICAS ──────────────────────────────────────────────────────────────
app.get('/api/client/estadisticas', requireClient, requireSubscription, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const since = new Date();
    since.setDate(since.getDate() - parseInt(days));
    const userId = new mongoose.Types.ObjectId(req.client.id);

    const [topProducts, topCategories, paymentSummary, summaryArr] = await Promise.all([
      Movement.aggregate([
        { $match: { userId, type: 'venta', createdAt: { $gte: since } } },
        { $group: {
          _id: '$productId',
          name: { $first: '$productName' },
          category: { $first: '$category' },
          totalQty: { $sum: '$quantity' },
          totalRevenue: { $sum: '$totalAmount' },
          totalCost: { $sum: { $multiply: ['$costPrice', '$quantity'] } }
        }},
        { $addFields: { ganancia: { $subtract: ['$totalRevenue', '$totalCost'] } } },
        { $sort: { totalQty: -1 } },
        { $limit: 10 }
      ]),
      Movement.aggregate([
        { $match: { userId, type: 'venta', createdAt: { $gte: since } } },
        { $group: {
          _id: '$category',
          totalQty: { $sum: '$quantity' },
          totalRevenue: { $sum: '$totalAmount' },
          totalCost: { $sum: { $multiply: ['$costPrice', '$quantity'] } }
        }},
        { $addFields: { ganancia: { $subtract: ['$totalRevenue', '$totalCost'] } } },
        { $sort: { totalRevenue: -1 } },
        { $limit: 10 }
      ]),
      Movement.aggregate([
        { $match: { userId, type: 'venta', createdAt: { $gte: since } } },
        { $group: { _id: '$paymentMethod', total: { $sum: '$totalAmount' }, count: { $sum: 1 } } },
        { $sort: { total: -1 } }
      ]),
      Movement.aggregate([
        { $match: { userId, type: 'venta', createdAt: { $gte: since } } },
        { $group: {
          _id: null,
          totalRevenue: { $sum: '$totalAmount' },
          totalCost: { $sum: { $multiply: ['$costPrice', '$quantity'] } },
          totalQty: { $sum: '$quantity' },
          count: { $sum: 1 }
        }}
      ])
    ]);

    const summary = summaryArr[0] || { totalRevenue: 0, totalCost: 0, totalQty: 0, count: 0 };
    summary.ganancia = (summary.totalRevenue || 0) - (summary.totalCost || 0);

    res.json({ topProducts, topCategories, paymentSummary, summary, days: parseInt(days) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CATEGORÍAS ────────────────────────────────────────────────────────────────
app.get('/api/client/categories', requireClient, requireSubscription, async (req, res) => {
  try {
    const cats = await Product.distinct('category', { userId: req.client.id });
    res.json(cats.filter(Boolean).sort());
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
function normalizeUser(u) {
  return {
    id: u._id, name: u.name, email: u.email, phone: u.phone,
    business_name: u.businessName, plan: u.plan, status: u.status,
    subscription_status: u.subscriptionStatus,
    trial_ends_at: u.trialEndsAt, paid_until: u.paidUntil,
    discount_code: u.discountCode, original_price: u.originalPrice,
    final_price: u.finalPrice, notes: u.notes, created_at: u.createdAt
  };
}
function normalizeDiscount(d) {
  return { id: d._id, code: d.code, description: d.description, discount_type: d.discountType, discount_value: d.discountValue, applicable_plans: d.applicablePlans, max_uses: d.maxUses, current_uses: d.currentUses, active: d.active, expires_at: d.expiresAt, created_at: d.createdAt };
}

// ── SPA ROUTES ────────────────────────────────────────────────────────────────
app.get('/admin',    (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/registro', (req, res) => res.sendFile(path.join(__dirname, 'public', 'registro.html')));
app.get('/app',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/login',    (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// ── START ─────────────────────────────────────────────────────────────────────
if (require.main === module) {
  init().then(() => {
    app.listen(PORT, () => {
      console.log(`\nGestionStock en http://localhost:${PORT}`);
      console.log(`Admin: http://localhost:${PORT}/admin`);
      console.log(`   Usuario: JuanMSilva | Contrasena: JuamiAdmin12-\n`);
    });
  });
}

module.exports = app;
