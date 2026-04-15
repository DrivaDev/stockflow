const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/stockflow';

// ── SCHEMAS ───────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:               { type: String, required: true },
  email:              { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:           { type: String },
  phone:              { type: String, default: null },
  businessName:       { type: String, default: null },
  plan:               { type: String, enum: ['basic', 'pro'], required: true },
  status:             { type: String, enum: ['active', 'inactive', 'pending'], default: 'active' },
  subscriptionStatus: { type: String, enum: ['trial', 'active', 'suspended', 'pending', 'cancelled'], default: 'trial' },
  trialEndsAt:        { type: Date, default: null },
  paidUntil:          { type: Date, default: null },
  dataDeleteAt:       { type: Date, default: null },
  discountCode:       { type: String, default: null },
  originalPrice:      { type: Number, required: true },
  finalPrice:         { type: Number, required: true },
  notes:              { type: String, default: null },
}, { timestamps: true });

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { timestamps: true });

const discountSchema = new mongoose.Schema({
  code:            { type: String, required: true, unique: true, uppercase: true },
  description:     { type: String, default: null },
  discountType:    { type: String, enum: ['percentage', 'fixed'], required: true },
  discountValue:   { type: Number, required: true },
  applicablePlans: { type: String, default: 'all' },
  maxUses:         { type: Number, default: null },
  currentUses:     { type: Number, default: 0 },
  active:          { type: Boolean, default: true },
  expiresAt:       { type: Date, default: null },
}, { timestamps: true });

const productSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name:        { type: String, required: true },
  category:    { type: String, default: 'General' },
  barcode:     { type: String, default: null },
  stock:       { type: Number, default: 0 },
  minStock:    { type: Number, default: 5 },
  costPrice:   { type: Number, default: 0 },
  salePrice:   { type: Number, default: 0 },
  unit:        { type: String, default: 'unidad' },
  description: { type: String, default: null },
}, { timestamps: true });

const movementSchema = new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  productId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  productName:   { type: String },
  category:      { type: String, default: 'General' },
  type:          { type: String, enum: ['in', 'out', 'adjustment', 'venta', 'compra'], required: true },
  quantity:      { type: Number, required: true },
  stockBefore:   { type: Number },
  stockAfter:    { type: Number },
  unitPrice:     { type: Number, default: 0 },
  costPrice:     { type: Number, default: 0 },
  totalAmount:   { type: Number, default: 0 },
  paymentMethod: { type: String, default: null },
  note:          { type: String, default: null },
}, { timestamps: true });

// ── MODELS ────────────────────────────────────────────────────────────────────
const User     = mongoose.models.User     || mongoose.model('User',     userSchema);
const Admin    = mongoose.models.Admin    || mongoose.model('Admin',    adminSchema);
const Discount = mongoose.models.Discount || mongoose.model('Discount', discountSchema);
const Product  = mongoose.models.Product  || mongoose.model('Product',  productSchema);
const Movement = mongoose.models.Movement || mongoose.model('Movement', movementSchema);

// ── CONNECT ───────────────────────────────────────────────────────────────────
let connected = false;
async function connect() {
  if (connected || mongoose.connection.readyState === 1) return;
  await mongoose.connect(MONGODB_URI);
  connected = true;
  console.log('MongoDB conectado');
}

// ── INIT: crear admin por defecto ─────────────────────────────────────────────
async function init() {
  await connect();
  const exists = await Admin.findOne({ username: 'JuanMSilva' });
  if (!exists) {
    const hash = bcrypt.hashSync('JuamiAdmin12-', 10);
    await Admin.create({ username: 'JuanMSilva', password: hash });
    console.log('Admin creado: JuanMSilva');
  } else {
    console.log('Admin ya existe: JuanMSilva');
  }
}

module.exports = { User, Admin, Discount, Product, Movement, connect, init };
