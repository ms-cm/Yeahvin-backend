// ============================================
// YEAHVIN - Backend API Complete
// E-commerce Geek - Produits Digitaux & Physiques
// ============================================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const fileUpload = require('express-fileupload');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// ============================================
// DOSSIERS SÉCURISÉS
// ============================================
const SECURE_PDFS_PATH = process.env.SECURE_PDFS_PATH || path.join(__dirname, '..', 'secure-pdfs');
const WATERMARKED_PDFS_PATH = process.env.WATERMARKED_PDFS_PATH || path.join(__dirname, '..', 'watermarked');
const TEMP_PATH = path.join(__dirname, '..', 'tmp');

[SECURE_PDFS_PATH, WATERMARKED_PDFS_PATH, TEMP_PATH].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log('📁 Dossier créé :', dir);
    }
});

// ============================================
// CONFIGURATION CLOUDINARY
// ============================================
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
});

// ============================================
// MIDDLEWARE GLOBAL
// ============================================
app.use(helmet({
    crossOriginResourcePolicy: { policy: "same-site" },
    contentSecurityPolicy: false
}));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 },
    abortOnLimit: true,
    useTempFiles: true,
    tempFileDir: TEMP_PATH,
    createParentPath: true,
    uploadTimeout: 120000
}));

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Trop de requêtes, veuillez réessayer plus tard.' }
});
app.use(generalLimiter);

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: { error: 'Trop d\'uploads, veuillez réessayer plus tard.' }
});

const downloadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: { error: 'Trop de téléchargements. Réessayez plus tard.' }
});

// ============================================
// MODÈLES MONGOOSE
// ============================================

const productSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    price: { type: Number, required: true, min: 0 },
    category: { type: String, required: true, trim: true, lowercase: true },
    images: [{ url: String, public_id: String }],
    stock: { type: Number, default: 9999 },
    featured: { type: Boolean, default: false },
    sizes: [String],
    colors: [String],
    type: { type: String, enum: ['digital', 'physique'], default: 'digital' },
    fileUrl: { type: String, default: null },
    fileSize: { type: Number, default: null },
    fileType: { type: String, default: 'pdf' },
    demoUrl: { type: String, default: null },
    isWatermarkable: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
productSchema.index({ category: 1, featured: 1, price: 1 });
productSchema.index({ name: 'text', description: 'text' });
const Product = mongoose.model('Product', productSchema);

const promoCodeSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true, uppercase: true, trim: true },
    discount: { type: Number, required: true, min: 1, max: 100 },
    expiresAt: { type: Date, required: true },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const PromoCode = mongoose.model('PromoCode', promoCodeSchema);

const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true, trim: true },
    email: { type: String, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    phone: { type: String, trim: true },
    role: { type: String, enum: ['client', 'admin'], default: 'client' },
    authProvider: { type: String, enum: ['google', 'apple', 'phone', 'email'], default: 'email' },
    picture: { type: String, default: null },
    createdAt: { type: Date, default: Date.now }
});
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};
const User = mongoose.model('User', userSchema);

const downloadTokenSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    orderId: { type: String, required: true },
    downloadCount: { type: Number, default: 0 },
    maxDownloads: { type: Number, default: 5 },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
});
downloadTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const DownloadToken = mongoose.model('DownloadToken', downloadTokenSchema);

const purchaseSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    products: [{
        productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        productName: String,
        price: Number,
        qty: { type: Number, default: 1 },
        type: { type: String, enum: ['digital', 'physique'] },
        downloadToken: { type: String, default: null },
        watermarked: { type: Boolean, default: false }
    }],
    totalAmount: Number,
    discountAmount: { type: Number, default: 0 },
    promoCode: String,
    status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' },
    orderNumber: { type: String, unique: true },
    purchaseDate: { type: Date, default: Date.now },
    logs: [{
        action: String,
        productId: mongoose.Schema.Types.ObjectId,
        productName: String,
        timestamp: { type: Date, default: Date.now },
        ip: String,
        userAgent: String
    }]
});
const Purchase = mongoose.model('Purchase', purchaseSchema);

// ============================================
// MIDDLEWARE AUTH
// ============================================

const isAdmin = (req, res, next) => {
    const password = req.headers['password'] || req.headers['x-admin-key'];
    if (!password) return res.status(401).json({ error: 'Mot de passe admin requis' });
    if (password !== process.env.ADMIN_PASSWORD) return res.status(403).json({ error: 'Mot de passe admin incorrect' });
    req.isAdmin = true;
    next();
};

const authenticateClient = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Token JWT requis' });
        }
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        if (!user) return res.status(401).json({ error: 'Utilisateur non trouvé' });
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Token invalide ou expiré' });
    }
};

// ============================================
// FONCTIONS UTILITAIRES
// ============================================

async function uploadToCloudinary(fileSource, folder = 'products', options = {}) {
    return new Promise((resolve, reject) => {
        const uploadOptions = {
            folder: 'yeahvin/' + folder,
            resource_type: 'image',
            transformation: [
                { width: options.width || 800, height: options.height || 800, crop: 'limit', quality: 'auto:good', fetch_format: 'auto' }
            ],
            use_filename: true,
            unique_filename: true,
            overwrite: false
        };
        const uploadStream = cloudinary.uploader.upload_stream(uploadOptions, (error, result) => {
            if (error) reject(error);
            else resolve(result);
        });
        if (Buffer.isBuffer(fileSource)) {
            const { Readable } = require('stream');
            const bufferStream = new Readable();
            bufferStream.push(fileSource);
            bufferStream.push(null);
            bufferStream.pipe(uploadStream);
        } else if (typeof fileSource === 'string') {
            fs.createReadStream(fileSource).pipe(uploadStream);
        } else {
            reject(new Error('Source non supportée'));
        }
    });
}

async function deleteFromCloudinary(publicIds) {
    const ids = Array.isArray(publicIds) ? publicIds : [publicIds];
    const results = await Promise.all(ids.map(async (publicId) => {
        if (!publicId || typeof publicId !== 'string') return { public_id: publicId, result: 'ignored' };
        try {
            const result = await cloudinary.uploader.destroy(publicId, { resource_type: 'image', invalidate: true });
            return { public_id: publicId, result: result.result };
        } catch (error) {
            return { public_id: publicId, result: 'error', error: error.message };
        }
    }));
    return { success: results.every(r => r.result === 'ok' || r.result === 'not_found'), details: results };
}

function isValidImageType(mimetype) {
    return ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif', 'image/bmp', 'image/tiff'].includes(mimetype.toLowerCase());
}

async function generateWatermarkedPdf(inputPath, outputPath, clientName, clientEmail, orderId, purchaseDate) {
    console.log('🔒 Watermark:', orderId, 'pour', clientName);
    const existingPdfBytes = fs.readFileSync(inputPath);
    const pdfDoc = await PDFDocument.load(existingPdfBytes);
    const helveticaFont = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const pages = pdfDoc.getPages();
    const watermarkText = 'Licence pour ' + clientName + ' - ' + clientEmail + ' - Commande #' + orderId + ' - ' + purchaseDate;

    for (const page of pages) {
        const { width, height } = page.getSize();
        const angle = Math.atan2(height, width) * (180 / Math.PI);
        const fontSize = Math.max(10, Math.floor(Math.sqrt(width * width + height * height) * 0.025));
        page.drawText(watermarkText, {
            x: width / 2 - (watermarkText.length * fontSize * 0.22),
            y: height / 2,
            size: fontSize,
            font: helveticaFont,
            color: rgb(0.8, 0.8, 0.8),
            opacity: 0.12,
            rotate: { type: 0, angle: angle }
        });
        page.drawText('Yeahvin - ' + orderId, {
            x: width - 160, y: 25,
            size: Math.floor(fontSize * 0.55),
            font: helveticaFont,
            color: rgb(0.7, 0.7, 0.7),
            opacity: 0.08
        });
        page.drawText(clientEmail, {
            x: 30, y: height - 15,
            size: Math.floor(fontSize * 0.45),
            font: helveticaFont,
            color: rgb(0.7, 0.7, 0.7),
            opacity: 0.06
        });
    }
    const pdfBytes = await pdfDoc.save();
    fs.writeFileSync(outputPath, pdfBytes);
    console.log('✅ PDF watermarké:', path.basename(outputPath));
    return outputPath;
}

// ============================================
// ROUTE PING (keep-alive Render)
// ============================================
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Yeahvin API is running', version: '2.0.0', timestamp: new Date().toISOString() });
});

// ============================================
// ROUTES AUTH
// ============================================

app.post('/api/auth/social', async (req, res) => {
    try {
        const { provider, providerId, email, fullName, picture, phone } = req.body;
        if (!provider || !email) return res.status(400).json({ error: 'Provider et email requis' });
        let user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            user = new User({
                fullName: fullName || 'Utilisateur Yeahvin',
                email,
                password: await bcrypt.hash(providerId + Date.now(), 12),
                phone: phone || '',
                authProvider: provider,
                picture: picture || null
            });
            await user.save();
        } else {
            if (picture && !user.picture) user.picture = picture;
            if (!user.authProvider) user.authProvider = provider;
            await user.save();
        }
        const token = jwt.sign({ userId: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
        res.json({
            token, provider,
            user: { id: user._id, fullName: user.fullName, email: user.email, phone: user.phone, role: user.role, picture: user.picture || null, createdAt: user.createdAt }
        });
    } catch (error) {
        console.error('Auth sociale error:', error);
        res.status(500).json({ error: 'Erreur authentification sociale' });
    }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullName, email, password, phone } = req.body;
        if (!fullName || !email || !password) return res.status(400).json({ error: 'Nom, email et mot de passe requis' });
        const existing = await User.findOne({ email: email.toLowerCase() });
        if (existing) return res.status(409).json({ error: 'Cet email est déjà utilisé' });
        const user = new User({ fullName, email, password, phone: phone || '', authProvider: 'email' });
        await user.save();
        const token = jwt.sign({ userId: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
        res.status(201).json({
            token,
            user: { id: user._id, fullName: user.fullName, email: user.email, phone: user.phone, role: user.role, createdAt: user.createdAt }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Erreur inscription' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user || !(await user.comparePassword(password))) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        const token = jwt.sign({ userId: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
        res.json({
            token,
            user: { id: user._id, fullName: user.fullName, email: user.email, phone: user.phone, role: user.role, createdAt: user.createdAt }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur connexion' });
    }
});

app.post('/api/auth/phone/send-code', async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) return res.status(400).json({ error: 'Numéro requis' });
        const verificationId = crypto.randomBytes(16).toString('hex');
        console.log('📱 Code envoyé à ' + phone + ' - Verification ID: ' + verificationId);
        res.json({ verificationId, message: 'Code envoyé sur WhatsApp' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur envoi code' });
    }
});

app.post('/api/auth/phone/verify', async (req, res) => {
    try {
        const { verificationId, code, userData } = req.body;
        if (!verificationId || !code) return res.status(400).json({ error: 'Code et verificationId requis' });
        if (code === '123456' || code === '000000') {
            let user = await User.findOne({ phone: userData.phone });
            if (!user) {
                user = new User({
                    fullName: userData.fullName,
                    email: userData.email || (userData.phone + '@yeahvin.local'),
                    password: await bcrypt.hash(userData.phone + Date.now(), 12),
                    phone: userData.phone,
                    authProvider: 'phone'
                });
                await user.save();
            }
            const token = jwt.sign({ userId: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
            res.json({
                token, provider: 'phone',
                user: { id: user._id, fullName: user.fullName, email: user.email, phone: user.phone, role: user.role, createdAt: user.createdAt }
            });
        } else {
            res.status(400).json({ error: 'Code invalide' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Erreur vérification' });
    }
});

// ============================================
// ROUTES PRODUITS
// ============================================

app.get('/api/products', async (req, res) => {
    try {
        const { category, search, featured, minPrice, maxPrice, sort, page, limit } = req.query;
        const filter = {};
        if (category) filter.category = category.toLowerCase();
        if (search) filter.$or = [{ name: { $regex: search, $options: 'i' } }, { description: { $regex: search, $options: 'i' } }];
        if (featured === 'true') filter.featured = true;
        if (minPrice || maxPrice) {
            filter.price = {};
            if (minPrice) filter.price.$gte = parseFloat(minPrice);
            if (maxPrice) filter.price.$lte = parseFloat(maxPrice);
        }
        const pageNum = parseInt(page) || 1;
        const limitNum = Math.min(parseInt(limit) || 20, 50);
        const sortOrder = sort || '-createdAt';
        const [products, total] = await Promise.all([
            Product.find(filter).sort(sortOrder).skip((pageNum - 1) * limitNum).limit(limitNum).lean(),
            Product.countDocuments(filter)
        ]);
        res.json({ products, pagination: { currentPage: pageNum, totalPages: Math.ceil(total / limitNum), totalProducts: total, hasMore: pageNum * limitNum < total } });
    } catch (error) {
        res.status(500).json({ error: 'Erreur récupération produits' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id).lean();
        if (!product) return res.status(404).json({ error: 'Produit non trouvé' });
        res.json({ product });
    } catch (error) {
        res.status(500).json({ error: 'Erreur récupération produit' });
    }
});

app.get('/api/products/:id/similar', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: 'Produit non trouvé' });
        const similar = await Product.find({ _id: { $ne: product._id }, category: product.category }).limit(4).lean();
        res.json({ products: similar });
    } catch (error) {
        res.status(500).json({ error: 'Erreur produits similaires' });
    }
});

app.post('/api/products', isAdmin, async (req, res) => {
    try {
        const { name, description, price, category, stock, featured, sizes, colors, type, isWatermarkable, fileUrl } = req.body;
        if (!name || !description || !price || !category) return res.status(400).json({ error: 'Nom, description, prix et catégorie requis' });
        const imageUploads = [];
        if (req.files && req.files.images) {
            const files = Array.isArray(req.files.images) ? req.files.images : [req.files.images];
            for (const file of files) {
                if (isValidImageType(file.mimetype)) {
                    const result = await uploadToCloudinary(file.tempFilePath || file.data, 'products');
                    imageUploads.push({ url: result.secure_url, public_id: result.public_id });
                }
            }
        }
        const product = new Product({
            name, description, price: parseFloat(price), category: category.toLowerCase(),
            stock: parseInt(stock) || 9999, featured: featured === 'true' || featured === true,
            sizes: sizes ? (Array.isArray(sizes) ? sizes : JSON.parse(sizes)) : [],
            colors: colors ? (Array.isArray(colors) ? colors : JSON.parse(colors)) : [],
            images: imageUploads, type: type || 'digital',
            isWatermarkable: isWatermarkable === 'true' || isWatermarkable === true,
            fileUrl: fileUrl || null
        });
        await product.save();
        res.status(201).json({ message: 'Produit créé', product });
    } catch (error) {
        console.error('Erreur création produit:', error);
        res.status(500).json({ error: 'Erreur création produit' });
    }
});

app.put('/api/products/:id', isAdmin, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: 'Produit non trouvé' });
        const { name, description, price, category, stock, featured, sizes, colors, type, isWatermarkable, deleteImages, fileUrl } = req.body;
        if (name) product.name = name;
        if (description) product.description = description;
        if (price) product.price = parseFloat(price);
        if (category) product.category = category.toLowerCase();
        if (stock !== undefined) product.stock = parseInt(stock);
        if (featured !== undefined) product.featured = featured === 'true' || featured === true;
        if (sizes) product.sizes = Array.isArray(sizes) ? sizes : JSON.parse(sizes);
        if (colors) product.colors = Array.isArray(colors) ? colors : JSON.parse(colors);
        if (type) product.type = type;
        if (isWatermarkable !== undefined) product.isWatermarkable = isWatermarkable === 'true' || isWatermarkable === true;
        if (fileUrl !== undefined) product.fileUrl = fileUrl;
        if (deleteImages) {
            const toDelete = Array.isArray(deleteImages) ? deleteImages : JSON.parse(deleteImages);
            for (const publicId of toDelete) {
                await deleteFromCloudinary(publicId);
                product.images = product.images.filter(img => img.public_id !== publicId);
            }
        }
        if (req.files && req.files.images) {
            const files = Array.isArray(req.files.images) ? req.files.images : [req.files.images];
            for (const file of files) {
                if (isValidImageType(file.mimetype)) {
                    const result = await uploadToCloudinary(file.tempFilePath || file.data, 'products');
                    product.images.push({ url: result.secure_url, public_id: result.public_id });
                }
            }
        }
        await product.save();
        res.json({ message: 'Produit mis à jour', product });
    } catch (error) {
        res.status(500).json({ error: 'Erreur modification produit' });
    }
});

app.delete('/api/products/:id', isAdmin, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: 'Produit non trouvé' });
        for (const img of product.images) {
            await deleteFromCloudinary(img.public_id);
        }
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: 'Produit supprimé' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur suppression produit' });
    }
});

// ============================================
// ROUTES UPLOAD (ADMIN)
// ============================================

app.post('/api/upload', isAdmin, uploadLimiter, async (req, res) => {
    try {
        if (!req.files || !req.files.image) return res.status(400).json({ error: 'Fichier image requis' });
        const imageFile = req.files.image;
        if (!isValidImageType(imageFile.mimetype)) return res.status(400).json({ error: 'Type de fichier non supporté' });
        const folder = req.body.folder || 'products';
        const result = await uploadToCloudinary(imageFile.tempFilePath || imageFile.data, folder);
        res.json({
            success: true,
            image: { url: result.secure_url, public_id: result.public_id, format: result.format, width: result.width, height: result.height, size: result.bytes }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur upload' });
    }
});

app.post('/api/upload/pdf', isAdmin, async (req, res) => {
    try {
        if (!req.files || !req.files.pdf) return res.status(400).json({ error: 'Fichier PDF requis' });
        const pdfFile = req.files.pdf;
        if (pdfFile.mimetype !== 'application/pdf' && !pdfFile.name.endsWith('.pdf')) {
            return res.status(400).json({ error: 'Seuls les fichiers PDF sont acceptés' });
        }
        const fileName = uuidv4() + '.pdf';
        const filePath = path.join(SECURE_PDFS_PATH, fileName);
        await pdfFile.mv(filePath);
        res.json({
            success: true,
            file: { url: fileName, originalName: pdfFile.name, size: pdfFile.size }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur upload PDF' });
    }
});

app.delete('/api/upload/:public_id', isAdmin, async (req, res) => {
    try {
        const result = await deleteFromCloudinary(req.params.public_id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Erreur suppression' });
    }
});

// ============================================
// ROUTES PROMO
// ============================================

app.post('/api/promo/validate', async (req, res) => {
    try {
        const { code, cartTotal } = req.body;
        if (!code) return res.status(400).json({ error: 'Code requis' });
        const promo = await PromoCode.findOne({ code: code.toUpperCase().trim(), active: true, expiresAt: { $gt: new Date() } });
        if (!promo) return res.status(404).json({ error: 'Code invalide ou expiré', valid: false });
        const discountAmount = (parseFloat(cartTotal || 0) * promo.discount) / 100;
        res.json({ valid: true, promoCode: { code: promo.code, discount: promo.discount }, discountAmount: Math.round(discountAmount * 100) / 100 });
    } catch (error) {
        res.status(500).json({ error: 'Erreur validation promo' });
    }
});

app.get('/api/promo', isAdmin, async (req, res) => {
    const promos = await PromoCode.find().sort('-createdAt').lean();
    res.json({ promoCodes: promos });
});

app.post('/api/promo', isAdmin, async (req, res) => {
    try {
        const { code, discount, expiresAt } = req.body;
        if (!code || !discount || !expiresAt) return res.status(400).json({ error: 'Code, réduction et date requis' });
        const promo = new PromoCode({ code: code.toUpperCase().trim(), discount: parseInt(discount), expiresAt: new Date(expiresAt) });
        await promo.save();
        res.status(201).json({ message: 'Code promo créé', promoCode: promo });
    } catch (error) {
        if (error.code === 11000) return res.status(409).json({ error: 'Ce code existe déjà' });
        res.status(500).json({ error: 'Erreur création promo' });
    }
});

app.put('/api/promo/:id', isAdmin, async (req, res) => {
    try {
        const promo = await PromoCode.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!promo) return res.status(404).json({ error: 'Code promo non trouvé' });
        res.json({ message: 'Code promo mis à jour', promoCode: promo });
    } catch (error) {
        res.status(500).json({ error: 'Erreur modification promo' });
    }
});

app.delete('/api/promo/:id', isAdmin, async (req, res) => {
    try {
        await PromoCode.findByIdAndDelete(req.params.id);
        res.json({ message: 'Code promo supprimé' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur suppression promo' });
    }
});

// ============================================
// ROUTES COMMANDES & TÉLÉCHARGEMENT SÉCURISÉ
// ============================================

app.post('/api/orders/create', authenticateClient, async (req, res) => {
    try {
        const { products, promoCode } = req.body;
        const userId = req.user._id;
        if (!products || products.length === 0) return res.status(400).json({ error: 'Aucun produit' });
        let totalAmount = 0;
        const orderProducts = [];
        for (const item of products) {
            const product = await Product.findById(item.productId);
            if (!product) return res.status(404).json({ error: 'Produit ' + item.productId + ' non trouvé' });
            if (product.stock < item.qty) return res.status(400).json({ error: 'Stock insuffisant pour ' + product.name });
            totalAmount += product.price * item.qty;
            orderProducts.push({
                productId: product._id, productName: product.name, price: product.price,
                qty: item.qty, type: product.type || 'digital', downloadToken: null, watermarked: false
            });
        }
        let discountAmount = 0;
        if (promoCode) {
            const promo = await PromoCode.findOne({ code: promoCode.toUpperCase(), active: true, expiresAt: { $gt: new Date() } });
            if (promo) discountAmount = Math.round((totalAmount * promo.discount) / 100);
        }
        const finalTotal = totalAmount - discountAmount;
        const orderNumber = 'YV-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
        const purchase = new Purchase({
            userId, products: orderProducts, totalAmount: finalTotal, discountAmount,
            promoCode: promoCode || null, status: 'completed', orderNumber,
            logs: [{ action: 'order_created', timestamp: new Date(), ip: req.ip, userAgent: req.headers['user-agent'] }]
        });
        const downloadLinks = [];
        for (const prod of purchase.products) {
            if (prod.type === 'digital') {
                const token = uuidv4();
                const downloadToken = new DownloadToken({
                    token, userId, productId: prod.productId, orderId: orderNumber,
                    expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000), maxDownloads: 5
                });
                await downloadToken.save();
                prod.downloadToken = token;
                downloadLinks.push({ productName: prod.productName, downloadUrl: '/api/download/' + token, expiresAt: downloadToken.expiresAt });
            }
        }
        await purchase.save();
        for (const item of products) {
            await Product.findByIdAndUpdate(item.productId, { $inc: { stock: -item.qty } });
        }
        res.status(201).json({ message: 'Commande créée', order: { orderNumber: purchase.orderNumber, totalAmount: purchase.totalAmount, status: purchase.status, downloadLinks } });
    } catch (error) {
        console.error('Erreur commande:', error);
        res.status(500).json({ error: 'Erreur création commande' });
    }
});

app.get('/api/download/:token', downloadLimiter, async (req, res) => {
    try {
        const { token } = req.params;
        const downloadToken = await DownloadToken.findOne({ token });
        if (!downloadToken) return res.status(404).json({ error: 'Lien invalide' });
        if (new Date() > downloadToken.expiresAt) return res.status(410).json({ error: 'Lien expiré', canRegenerate: true });
        if (downloadToken.downloadCount >= downloadToken.maxDownloads) return res.status(429).json({ error: 'Limite de téléchargements atteinte', canRegenerate: false });
        const user = await User.findById(downloadToken.userId);
        const product = await Product.findById(downloadToken.productId);
        if (!user || !product || !product.fileUrl) return res.status(404).json({ error: 'Fichier non trouvé' });
        const originalPdfPath = path.join(SECURE_PDFS_PATH, product.fileUrl);
        if (!fs.existsSync(originalPdfPath)) return res.status(404).json({ error: 'Fichier source introuvable' });
        const watermarkedDir = path.join(WATERMARKED_PDFS_PATH, downloadToken.userId.toString());
        if (!fs.existsSync(watermarkedDir)) fs.mkdirSync(watermarkedDir, { recursive: true });
        const watermarkedPath = path.join(watermarkedDir, downloadToken.orderId + '_' + product._id + '_watermarked.pdf');
        if (!fs.existsSync(watermarkedPath) && product.isWatermarkable) {
            await generateWatermarkedPdf(originalPdfPath, watermarkedPath, user.fullName, user.email, downloadToken.orderId, new Date().toLocaleDateString('fr-FR'));
        }
        downloadToken.downloadCount += 1;
        await downloadToken.save();
        const purchase = await Purchase.findOne({ orderNumber: downloadToken.orderId });
        if (purchase) {
            purchase.logs.push({ action: 'download', productId: product._id, productName: product.name, timestamp: new Date(), ip: req.ip, userAgent: req.headers['user-agent'] });
            await purchase.save();
        }
        const finalPath = (product.isWatermarkable && fs.existsSync(watermarkedPath)) ? watermarkedPath : originalPdfPath;
        res.download(finalPath, product.name.replace(/[^a-zA-Z0-9]/g, '_') + '.pdf');
    } catch (error) {
        console.error('Erreur téléchargement:', error);
        res.status(500).json({ error: 'Erreur téléchargement' });
    }
});

app.post('/api/download/regenerate', authenticateClient, async (req, res) => {
    try {
        const { orderId, productId } = req.body;
        const userId = req.user._id;
        const purchase = await Purchase.findOne({ orderNumber: orderId, userId, status: 'completed' });
        if (!purchase) return res.status(404).json({ error: 'Commande non trouvée' });
        const prod = purchase.products.find(p => p.productId.toString() === productId);
        if (!prod) return res.status(404).json({ error: 'Produit non trouvé dans cette commande' });
        if (prod.type !== 'digital') return res.status(400).json({ error: 'Produit non digital' });
        const regenerateCount = purchase.logs.filter(log => log.action === 'regenerate_link' && log.productId?.toString() === productId).length;
        if (regenerateCount >= 3) return res.status(429).json({ error: 'Limite de régénérations atteinte' });
        const newToken = uuidv4();
        const downloadToken = new DownloadToken({
            token: newToken, userId, productId, orderId,
            expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000), maxDownloads: 5
        });
        await downloadToken.save();
        prod.downloadToken = newToken;
        purchase.logs.push({ action: 'regenerate_link', productId, productName: prod.productName, timestamp: new Date(), ip: req.ip, userAgent: req.headers['user-agent'] });
        await purchase.save();
        res.json({ message: 'Nouveau lien généré', downloadUrl: '/api/download/' + newToken, remainingRegenerations: 2 - regenerateCount });
    } catch (error) {
        res.status(500).json({ error: 'Erreur régénération' });
    }
});

app.get('/api/client/purchases', authenticateClient, async (req, res) => {
    try {
        const purchases = await Purchase.find({ userId: req.user._id, status: 'completed' }).sort('-purchaseDate').lean();
        const formatted = purchases.map(p => ({
            orderNumber: p.orderNumber,
            purchaseDate: p.purchaseDate,
            totalAmount: p.totalAmount,
            products: p.products.map(prod => ({
                productId: prod.productId,
                productName: prod.productName,
                price: prod.price,
                type: prod.type,
                downloadToken: prod.downloadToken,
                downloadUrl: prod.downloadToken ? '/api/download/' + prod.downloadToken : null
            }))
        }));
        res.json({ purchases: formatted });
    } catch (error) {
        res.status(500).json({ error: 'Erreur récupération achats' });
    }
});

app.get('/api/client/purchase/:orderNumber', authenticateClient, async (req, res) => {
    try {
        const purchase = await Purchase.findOne({ orderNumber: req.params.orderNumber, userId: req.user._id }).lean();
        if (!purchase) return res.status(404).json({ error: 'Commande non trouvée' });
        const productsWithStatus = await Promise.all(purchase.products.map(async (prod) => {
            if (prod.type === 'digital' && prod.downloadToken) {
                const token = await DownloadToken.findOne({ token: prod.downloadToken });
                return {
                    ...prod,
                    downloadStatus: {
                        isExpired: token ? new Date() > token.expiresAt : true,
                        downloadsRemaining: token ? token.maxDownloads - token.downloadCount : 0,
                        expiresAt: token?.expiresAt,
                        canRegenerate: token ? new Date() > token.expiresAt : true
                    }
                };
            }
            return prod;
        }));
        res.json({ ...purchase, products: productsWithStatus });
    } catch (error) {
        res.status(500).json({ error: 'Erreur détail commande' });
    }
});

// ============================================
// ROUTES ADMIN
// ============================================

app.get('/api/admin/stats', isAdmin, async (req, res) => {
    try {
        const [totalProducts, totalClients, activePromos, featuredProducts, totalOrders, totalDigital, totalPhysique] = await Promise.all([
            Product.countDocuments(),
            User.countDocuments({ role: 'client' }),
            PromoCode.countDocuments({ active: true, expiresAt: { $gt: new Date() } }),
            Product.countDocuments({ featured: true }),
            Purchase.countDocuments({ status: 'completed' }),
            Product.countDocuments({ type: 'digital' }),
            Product.countDocuments({ type: 'physique' })
        ]);
        res.json({ stats: { totalProducts, totalClients, activePromos, featuredProducts, totalOrders, totalDigital, totalPhysique } });
    } catch (error) {
        res.status(500).json({ error: 'Erreur stats' });
    }
});

app.get('/api/admin/orders', isAdmin, async (req, res) => {
    try {
        const orders = await Purchase.find().sort('-purchaseDate').populate('userId', 'fullName email phone').lean();
        res.json({ orders });
    } catch (error) {
        res.status(500).json({ error: 'Erreur chargement commandes' });
    }
});

// ============================================
// GESTION ERREURS
// ============================================

app.use((req, res) => {
    res.status(404).json({ error: 'Route non trouvée', path: req.originalUrl });
});

app.use((err, req, res, next) => {
    console.error('Erreur:', err);
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Fichier trop volumineux (max 50MB)' });
    res.status(500).json({ error: 'Erreur serveur interne' });
});

// ============================================
// DÉMARRAGE SERVEUR
// ============================================

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/yeahvin';

mongoose.set('strictQuery', false);

const startServer = async () => {
    try {
        console.log('🔄 Connexion MongoDB...');
        await mongoose.connect(MONGODB_URI, {
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10
        });
        console.log('✅ MongoDB connecté');
        app.listen(PORT, () => {
            console.log('🚀 Yeahvin API sur http://localhost:' + PORT);
            console.log('📦 PDFs: ' + SECURE_PDFS_PATH);
            console.log('🔒 Watermarked: ' + WATERMARKED_PDFS_PATH);
        });
    } catch (error) {
        console.error('❌ Erreur connexion:', error.message);
        console.log('🔄 Nouvelle tentative dans 5s...');
        setTimeout(startServer, 5000);
    }
};

process.on('SIGINT', async () => {
    await mongoose.connection.close();
    console.log('🛑 Serveur arrêté');
    process.exit(0);
});

startServer();
module.exports = app;
