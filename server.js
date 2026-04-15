const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');
const { User, Admin, Discount, Product, Movement, connect, init } = require('./database');

// ── EMAIL ─────────────────────────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER || 'driva.devv@gmail.com', pass: process.env.GMAIL_PASS }
});

async function sendEmail(to, subject, html) {
  if (!process.env.GMAIL_PASS) return; // silencioso si no está configurado
  try {
    await mailer.sendMail({ from: `"GestionStock" <${process.env.GMAIL_USER || 'driva.devv@gmail.com'}>`, to, subject, html });
  } catch (e) { console.error('Email error:', e.message); }
}

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET    = process.env.JWT_SECRET    || 'stockflow_secret_admin_2024';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'stockflow_secret_client_2024';

const PLANS = {
  basic: { name: 'Plan Básico', price: 30000, products: 500 },
  pro:   { name: 'Plan Pro',    price: 50000, products: null }
};

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Conectar DB en cada request (necesario para Vercel serverless)
app.use(async (req, res, next) => {
  try { await connect(); next(); } catch (e) { res.status(500).json({ error: 'Error de base de datos' }); }
});

// ── MIDDLEWARES AUTH ──────────────────────────────────────────────────────────
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

// ── SETUP (crea admin la primera vez) ────────────────────────────────────────
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

    const hashedPassword = bcrypt.hashSync(password, 10);
    try {
      const user = await User.create({ name, email, phone: phone || null, businessName: business_name || null, plan, status: 'active', discountCode: validatedCode, originalPrice: basePrice, finalPrice, password: hashedPassword });

      // Email de bienvenida
      sendEmail(email, '¡Bienvenido a GestionStock!', `
        <div style="font-family:Inter,sans-serif;max-width:520px;margin:0 auto;padding:2rem">
          <h2 style="color:#6C63FF">¡Hola ${name}!</h2>
          <p>Tu cuenta en <strong>GestionStock</strong> fue creada exitosamente.</p>
          <table style="width:100%;background:#f8f9ff;border-radius:10px;padding:1rem;margin:1.5rem 0;border-collapse:collapse">
            <tr><td style="padding:.4rem 0;color:#64748B">Plan</td><td style="font-weight:600">${PLANS[plan].name}</td></tr>
            <tr><td style="padding:.4rem 0;color:#64748B">Precio mensual</td><td style="font-weight:600">$${finalPrice.toLocaleString('es-AR')}</td></tr>
            <tr><td style="padding:.4rem 0;color:#64748B">Email</td><td style="font-weight:600">${email}</td></tr>
          </table>
          <a href="https://stockflow-omega-seven.vercel.app/login" style="display:inline-block;background:linear-gradient(135deg,#6C63FF,#9C78FF);color:#fff;padding:.75rem 1.75rem;border-radius:10px;text-decoration:none;font-weight:700">Ingresar al sistema</a>
          <p style="margin-top:2rem;color:#64748B;font-size:.85rem">Si tenés alguna duda, respondé este email y te ayudamos.</p>
        </div>
      `);

      res.status(201).json({ id: user._id, message: '¡Registro exitoso! Ya podés ingresar al sistema.', plan: PLANS[plan].name, final_price: finalPrice });
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
    const { status, notes, plan } = req.body;
    const update = {};
    if (status) update.status = status;
    if (notes !== undefined) update.notes = notes;
    if (plan && PLANS[plan]) { update.plan = plan; update.originalPrice = PLANS[plan].price; update.finalPrice = PLANS[plan].price; }
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
    res.json({ token, name: user.name, email: user.email, plan: user.plan, businessName: user.businessName });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/client/me', requireClient, async (req, res) => {
  try {
    const user = await User.findById(req.client.id).select('-password');
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ name: user.name, email: user.email, plan: user.plan, businessName: user.businessName, status: user.status });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PRODUCTOS ─────────────────────────────────────────────────────────────────
app.get('/api/client/products', requireClient, async (req, res) => {
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

app.post('/api/client/products', requireClient, async (req, res) => {
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

app.put('/api/client/products/:id', requireClient, async (req, res) => {
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

app.delete('/api/client/products/:id', requireClient, async (req, res) => {
  try {
    await Product.deleteOne({ _id: req.params.id, userId: req.client.id });
    await Movement.deleteMany({ productId: req.params.id, userId: req.client.id });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── MOVIMIENTOS ───────────────────────────────────────────────────────────────
app.post('/api/client/movements', requireClient, async (req, res) => {
  try {
    const { productId, type, quantity, note } = req.body;
    if (!productId || !type || !quantity) return res.status(400).json({ error: 'Datos incompletos' });
    if (!['in','out','adjustment'].includes(type)) return res.status(400).json({ error: 'Tipo inválido' });
    const prod = await Product.findOne({ _id: productId, userId: req.client.id });
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    const qty = parseInt(quantity);
    let newStock;
    if (type === 'in')         newStock = prod.stock + qty;
    else if (type === 'out')   newStock = Math.max(0, prod.stock - qty);
    else                       newStock = qty;
    if (type === 'out' && prod.stock < qty) return res.status(400).json({ error: `Stock insuficiente. Disponible: ${prod.stock}` });
    await Product.updateOne({ _id: productId }, { $set: { stock: newStock } });
    const mov = await Movement.create({ userId: req.client.id, productId, productName: prod.name, type, quantity: qty, stockBefore: prod.stock, stockAfter: newStock, note: note || null });
    res.status(201).json({ ...mov.toObject(), newStock });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/client/movements', requireClient, async (req, res) => {
  try {
    const { productId, limit: lim = 50 } = req.query;
    const query = { userId: req.client.id };
    if (productId) query.productId = productId;
    const movs = await Movement.find(query).sort({ createdAt: -1 }).limit(parseInt(lim));
    res.json(movs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/client/categories', requireClient, async (req, res) => {
  try {
    const cats = await Product.distinct('category', { userId: req.client.id });
    res.json(cats.filter(Boolean).sort());
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
function normalizeUser(u) {
  return { id: u._id, name: u.name, email: u.email, phone: u.phone, business_name: u.businessName, plan: u.plan, status: u.status, discount_code: u.discountCode, original_price: u.originalPrice, final_price: u.finalPrice, notes: u.notes, created_at: u.createdAt };
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
      console.log(`\n🚀 StockFlow en http://localhost:${PORT}`);
      console.log(`📊 Admin: http://localhost:${PORT}/admin`);
      console.log(`   Usuario: JuanMSilva | Contraseña: JuamiAdmin12-\n`);
    });
  });
}

module.exports = app;
