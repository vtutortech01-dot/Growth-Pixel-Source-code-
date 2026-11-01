import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');
const CONTENT_FILE = path.join(DATA_DIR, 'content.json');
const DEFAULT_CONTENT_FILE = path.join(DATA_DIR, 'default-content.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// In-memory active session tokens
const activeSessions = new Map();
const SESSION_LIFETIME_MS = 24 * 60 * 60 * 1000; // 24 hours

function cleanExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of activeSessions.entries()) {
    if (session.expiresAt <= now) {
      activeSessions.delete(token);
    }
  }
}
setInterval(cleanExpiredSessions, 15 * 60 * 1000);

function getAdminRecord() {
  try {
    if (fs.existsSync(ADMIN_FILE)) {
      const data = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf-8'));
      return data;
    }
  } catch (err) {
    console.error('Error reading admin.json:', err);
  }
  return { isInitialized: false };
}

function saveAdminRecord(data) {
  fs.writeFileSync(ADMIN_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

function getContentData() {
  try {
    if (fs.existsSync(CONTENT_FILE)) {
      return JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf-8'));
    }
    if (fs.existsSync(DEFAULT_CONTENT_FILE)) {
      const defaults = JSON.parse(fs.readFileSync(DEFAULT_CONTENT_FILE, 'utf-8'));
      fs.writeFileSync(CONTENT_FILE, JSON.stringify(defaults, null, 2), 'utf-8');
      return defaults;
    }
  } catch (err) {
    console.error('Error reading content:', err);
  }
  return {};
}

function saveContentData(data) {
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  if (req.headers['x-admin-token']) {
    return String(req.headers['x-admin-token']).trim();
  }
  return null;
}

function requireAdmin(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required. No session token provided.' });
  }

  const session = activeSessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    activeSessions.delete(token);
    return res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
  }

  req.admin = session;
  req.adminToken = token;
  next();
}

// Multer storage for direct image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.webp';
    const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`;
    cb(null, uniqueSuffix);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp|svg\+xml|gif|svg/;
    const mimeAllowed = allowed.test(file.mimetype);
    const extAllowed = allowed.test(path.extname(file.originalname).toLowerCase());
    if (mimeAllowed || extAllowed) {
      cb(null, true);
    } else {
      cb(new Error('Only image files (JPG, PNG, WebP, SVG, GIF) are allowed.'));
    }
  }
});

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static assets and direct uploads
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(__dirname));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Admin Status check (Is single admin initialized? Is current client authenticated?)
app.get('/api/admin/status', (req, res) => {
  const adminRecord = getAdminRecord();
  const token = extractToken(req);
  let isAuthenticated = false;
  let email = null;

  if (token) {
    const session = activeSessions.get(token);
    if (session && session.expiresAt > Date.now()) {
      isAuthenticated = true;
      email = session.email;
    }
  }

  res.json({
    isInitialized: Boolean(adminRecord.isInitialized),
    isAuthenticated,
    adminEmail: isAuthenticated ? email : null
  });
});

// Initial Administrator Registration
// STRICT RULE: Only allowed if isInitialized is false. Permanently disabled thereafter.
app.post('/api/admin/register', (req, res) => {
  const adminRecord = getAdminRecord();
  if (adminRecord.isInitialized) {
    return res.status(403).json({
      error: 'Administrator registration is permanently closed. The first administrator account has already been registered.'
    });
  }

  const { email, password, confirmPassword } = req.body;

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'A valid email address is required.' });
  }

  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Password confirmation does not match.' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(password, salt);

  const newAdminData = {
    isInitialized: true,
    email: cleanEmail,
    passwordHash,
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString()
  };

  saveAdminRecord(newAdminData);

  // Issue session token
  const token = crypto.randomBytes(32).toString('hex');
  activeSessions.set(token, {
    email: cleanEmail,
    expiresAt: Date.now() + SESSION_LIFETIME_MS
  });

  return res.status(201).json({
    success: true,
    message: 'First administrator registered successfully.',
    token,
    email: cleanEmail
  });
});

// Administrator Login
app.post('/api/admin/login', (req, res) => {
  const adminRecord = getAdminRecord();
  if (!adminRecord.isInitialized) {
    return res.status(400).json({
      error: 'Initial administrator account setup has not been completed. Please set up the first administrator account.'
    });
  }

  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const cleanEmail = String(email).toLowerCase().trim();
  if (cleanEmail !== adminRecord.email) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  const isMatch = bcrypt.compareSync(password, adminRecord.passwordHash);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  adminRecord.lastLogin = new Date().toISOString();
  saveAdminRecord(adminRecord);

  const token = crypto.randomBytes(32).toString('hex');
  activeSessions.set(token, {
    email: adminRecord.email,
    expiresAt: Date.now() + SESSION_LIFETIME_MS
  });

  return res.json({
    success: true,
    message: 'Administrator logged in successfully.',
    token,
    email: adminRecord.email
  });
});

// Administrator Logout
app.post('/api/admin/logout', requireAdmin, (req, res) => {
  activeSessions.delete(req.adminToken);
  res.json({ success: true, message: 'Logged out successfully.' });
});

// Verify Current Session
app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({
    success: true,
    email: req.admin.email
  });
});

// Security & Password Change
app.put('/api/admin/security', requireAdmin, (req, res) => {
  const adminRecord = getAdminRecord();
  const { currentPassword, newPassword, newEmail } = req.body;

  if (!currentPassword) {
    return res.status(400).json({ error: 'Current password is required to make security changes.' });
  }

  const isMatch = bcrypt.compareSync(currentPassword, adminRecord.passwordHash);
  if (!isMatch) {
    return res.status(401).json({ error: 'Incorrect current password.' });
  }

  if (newEmail && typeof newEmail === 'string' && newEmail.includes('@')) {
    adminRecord.email = newEmail.toLowerCase().trim();
  }

  if (newPassword) {
    if (typeof newPassword !== 'string' || newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }
    const salt = bcrypt.genSaltSync(10);
    adminRecord.passwordHash = bcrypt.hashSync(newPassword, salt);
  }

  saveAdminRecord(adminRecord);
  res.json({ success: true, message: 'Administrator security settings updated.' });
});

// Public Website Content API
app.get('/api/content', (req, res) => {
  const content = getContentData();
  res.json(content);
});

// Admin Update Content API
app.put('/api/admin/content', requireAdmin, (req, res) => {
  const updatedContent = req.body;
  if (!updatedContent || typeof updatedContent !== 'object') {
    return res.status(400).json({ error: 'Invalid content data payload.' });
  }

  const currentContent = getContentData();
  const merged = { ...currentContent, ...updatedContent };
  saveContentData(merged);

  res.json({
    success: true,
    message: 'Website content updated and saved persistently.',
    content: merged
  });
});

// Direct Image Upload for Projects & Branding
app.post('/api/admin/upload', requireAdmin, (req, res) => {
  upload.single('image')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'File upload failed.' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No image file was provided.' });
    }

    const publicUrl = `/uploads/${req.file.filename}`;
    res.json({
      success: true,
      url: publicUrl,
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size
    });
  });
});

// Dedicated Administrator Route: Serves the Admin Portal UI
app.get(['/admin', '/admin/*'], (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Main Website entry point
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`Growth Pixel server running on http://${HOST}:${PORT}`);
});
