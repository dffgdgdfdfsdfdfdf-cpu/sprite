"use strict";

require("dotenv").config();

const path = require("node:path");
const fs = require("node:fs");
const { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } = require("node:crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const express = require("express");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const helmet = require("helmet");

const isProduction = process.env.NODE_ENV === "production";
const dataDirectory = path.join(__dirname, ".private");
fs.mkdirSync(dataDirectory, { recursive: true });
const developmentSecretPath = path.join(dataDirectory, "session-secret");
let developmentSecret = "";
if (!isProduction && !process.env.SESSION_SECRET) {
    developmentSecret = fs.existsSync(developmentSecretPath)
        ? fs.readFileSync(developmentSecretPath, "utf8").trim()
        : "";
    if (!developmentSecret) {
        developmentSecret = randomBytes(48).toString("hex");
        try {
            fs.writeFileSync(developmentSecretPath, developmentSecret, { flag: "wx" });
        } catch (error) {
            if (error.code !== "EEXIST") throw error;
            developmentSecret = fs.readFileSync(developmentSecretPath, "utf8").trim();
        }
    }
}
const sessionSecret = process.env.SESSION_SECRET
    || (isProduction ? "" : developmentSecret);
if (!sessionSecret) {
    throw new Error("SESSION_SECRET must be configured in production.");
}
if (!process.env.SESSION_SECRET && !isProduction) {
    console.warn("SESSION_SECRET is unset; using the private persistent local-development secret.");
}
if (sessionSecret.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters.");
}
const bankEncryptionKeyPath = path.join(dataDirectory, "bank-details-key");
let bankEncryptionKey = process.env.BANK_DETAILS_ENCRYPTION_KEY || "";
if (!isProduction && !bankEncryptionKey) {
    bankEncryptionKey = fs.existsSync(bankEncryptionKeyPath)
        ? fs.readFileSync(bankEncryptionKeyPath, "utf8").trim()
        : "";
    if (!bankEncryptionKey) {
        bankEncryptionKey = randomBytes(32).toString("hex");
        try {
            fs.writeFileSync(bankEncryptionKeyPath, bankEncryptionKey, { flag: "wx", mode: 0o600 });
        } catch (error) {
            if (error.code !== "EEXIST") throw error;
            bankEncryptionKey = fs.readFileSync(bankEncryptionKeyPath, "utf8").trim();
        }
    }
}
if (!/^[a-f0-9]{64}$/i.test(bankEncryptionKey)) {
    throw new Error("BANK_DETAILS_ENCRYPTION_KEY must be a 64-character hexadecimal key.");
}
bankEncryptionKey = Buffer.from(bankEncryptionKey, "hex");

const app = express();
const port = Number(process.env.PORT || 3000);
const mediaDirectory = path.join(__dirname, "uploads", "media");
fs.mkdirSync(mediaDirectory, { recursive: true });
const dummyPasswordHash = bcrypt.hashSync(randomBytes(32).toString("hex"), 12);

const database = new Database(path.join(dataDirectory, "kingfisher.sqlite"));
database.pragma("journal_mode = WAL");
database.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 50),
        phone TEXT NOT NULL UNIQUE CHECK (length(phone) = 10),
        password_hash TEXT NOT NULL,
        balance_paise INTEGER NOT NULL DEFAULT 0 CHECK (balance_paise >= 0),
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        expires INTEGER NOT NULL,
        data TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires);
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        password_change_required INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_login_at TEXT
    );
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL CHECK (category IN ('daily', 'vip')),
        price_paise INTEGER NOT NULL CHECK (price_paise >= 0),
        duration_days INTEGER NOT NULL CHECK (duration_days > 0),
        daily_reward_paise INTEGER NOT NULL DEFAULT 0 CHECK (daily_reward_paise >= 0),
        total_reward_paise INTEGER NOT NULL DEFAULT 0 CHECK (total_reward_paise >= 0),
        purchase_limit INTEGER NOT NULL DEFAULT 1 CHECK (purchase_limit > 0),
        active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
        image_url TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS missions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        target_members INTEGER NOT NULL CHECK (target_members >= 0),
        reward_paise INTEGER NOT NULL CHECK (reward_paise >= 0),
        active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS wallet_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        type TEXT NOT NULL CHECK (type IN ('recharge', 'withdrawal', 'adjustment')),
        amount_paise INTEGER NOT NULL CHECK (amount_paise != 0),
        status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'approved', 'rejected')),
        reference TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        created_by_admin_id INTEGER REFERENCES admins(id),
        reviewed_by_admin_id INTEGER REFERENCES admins(id),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_wallet_transactions_status ON wallet_transactions(status, created_at);
    CREATE TABLE IF NOT EXISTS site_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_by_admin_id INTEGER REFERENCES admins(id)
    );
    CREATE TABLE IF NOT EXISTS admin_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL REFERENCES admins(id),
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL DEFAULT '',
        details_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS mission_claims (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        mission_id INTEGER NOT NULL REFERENCES missions(id),
        status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
        note TEXT NOT NULL DEFAULT '',
        reviewed_by_admin_id INTEGER REFERENCES admins(id),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT,
        UNIQUE (user_id, mission_id)
    );
    CREATE INDEX IF NOT EXISTS idx_mission_claims_status ON mission_claims(status, created_at);
    CREATE TABLE IF NOT EXISTS product_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        product_id INTEGER NOT NULL REFERENCES products(id),
        product_name TEXT NOT NULL,
        price_paise INTEGER NOT NULL CHECK (price_paise >= 0),
        status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
        note TEXT NOT NULL DEFAULT '',
        reviewed_by_admin_id INTEGER REFERENCES admins(id),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_product_requests_status ON product_requests(status, created_at);
    CREATE TABLE IF NOT EXISTS demo_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        demo_code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
        balance_paise INTEGER NOT NULL DEFAULT 0 CHECK (balance_paise >= 0),
        created_by_admin_id INTEGER NOT NULL REFERENCES admins(id),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS demo_wallet_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        demo_account_id INTEGER NOT NULL REFERENCES demo_accounts(id),
        type TEXT NOT NULL CHECK (type IN ('demo_deposit', 'demo_withdrawal')),
        amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
        note TEXT NOT NULL,
        created_by_admin_id INTEGER NOT NULL REFERENCES admins(id),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_demo_wallet_transactions_account
        ON demo_wallet_transactions(demo_account_id, id DESC);
    CREATE TABLE IF NOT EXISTS bank_accounts (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        holder_name TEXT NOT NULL,
        bank_name TEXT NOT NULL,
        account_ciphertext TEXT NOT NULL,
        account_iv TEXT NOT NULL,
        account_tag TEXT NOT NULL,
        account_last4 TEXT NOT NULL,
        ifsc TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS user_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        product_id INTEGER NOT NULL REFERENCES products(id),
        product_name TEXT NOT NULL,
        price_paise INTEGER NOT NULL CHECK (price_paise >= 0),
        duration_days INTEGER NOT NULL CHECK (duration_days > 0),
        purchased_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired'))
    );
    CREATE INDEX IF NOT EXISTS idx_user_products_user_status
        ON user_products(user_id, status, expires_at);
`);

const walletTransactionsSql = database.prepare(
    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'wallet_transactions'"
).get()?.sql || "";
if (!walletTransactionsSql.includes("'processing'")) {
    const migrateWalletTransactionStatuses = database.transaction(() => {
        database.exec("ALTER TABLE wallet_transactions RENAME TO wallet_transactions_legacy");
        database.exec("DROP INDEX IF EXISTS idx_wallet_transactions_status");
        database.exec(`
            CREATE TABLE wallet_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                type TEXT NOT NULL CHECK (type IN ('recharge', 'withdrawal', 'adjustment')),
                amount_paise INTEGER NOT NULL CHECK (amount_paise != 0),
                status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'approved', 'rejected')),
                reference TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                created_by_admin_id INTEGER REFERENCES admins(id),
                reviewed_by_admin_id INTEGER REFERENCES admins(id),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TEXT
            );
            INSERT INTO wallet_transactions
                (id, user_id, type, amount_paise, status, reference, note,
                 created_by_admin_id, reviewed_by_admin_id, created_at, reviewed_at)
            SELECT id, user_id, type, amount_paise, status, reference, note,
                   created_by_admin_id, reviewed_by_admin_id, created_at, reviewed_at
            FROM wallet_transactions_legacy;
            DROP TABLE wallet_transactions_legacy;
            CREATE INDEX idx_wallet_transactions_status
                ON wallet_transactions(status, created_at);
        `);
    });
    migrateWalletTransactionStatuses();
}

const productColumns = new Set(database.prepare("PRAGMA table_info(products)").all().map(column => column.name));
if (!productColumns.has("image_url")) {
    database.exec("ALTER TABLE products ADD COLUMN image_url TEXT NOT NULL DEFAULT ''");
}

const userColumns = new Set(database.prepare("PRAGMA table_info(users)").all().map(column => column.name));
if (!userColumns.has("balance_paise")) {
    database.exec("ALTER TABLE users ADD COLUMN balance_paise INTEGER NOT NULL DEFAULT 0");
}
if (!userColumns.has("status")) {
    database.exec("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'");
}
if (!userColumns.has("updated_at")) {
    database.exec("ALTER TABLE users ADD COLUMN updated_at TEXT");
    database.exec("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL");
}
if (!userColumns.has("referral_code")) {
    database.exec("ALTER TABLE users ADD COLUMN referral_code TEXT");
}
if (!userColumns.has("referred_by_user_id")) {
    database.exec("ALTER TABLE users ADD COLUMN referred_by_user_id INTEGER REFERENCES users(id)");
}
database.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code) WHERE referral_code IS NOT NULL");
for (const user of database.prepare("SELECT id FROM users WHERE referral_code IS NULL OR referral_code = ''").all()) {
    let code;
    do {
        code = randomBytes(5).toString("hex").toUpperCase();
    } while (database.prepare("SELECT 1 FROM users WHERE referral_code = ?").get(code));
    database.prepare("UPDATE users SET referral_code = ? WHERE id = ?").run(code, user.id);
}
if (database.prepare("SELECT COUNT(*) AS count FROM products").get().count === 0) {
    const initialProducts = [
        [372, "Product A", "daily", 900, 2, 4000, 8000, 5],
        [374, "Product B", "daily", 295, 45, 240, 10800, 10],
        [376, "Product C", "daily", 550, 10, 1400, 14000, 10],
        [377, "Product D", "daily", 1100, 7, 4000, 28000, 10],
        [379, "Product F", "daily", 2500, 5, 7450, 37250, 5],
        [380, "Product G", "daily", 4999, 2, 29999, 59998, 1],
        [387, "VIP 1", "vip", 999, 3, 2500, 7500, 10],
        [386, "VIP 2", "vip", 1500, 2, 6000, 12000, 10],
        [378, "VIP 3", "vip", 3000, 2, 12000, 24000, 10],
        [388, "VIP 4", "vip", 6000, 1, 50000, 50000, 1]
    ];
    const insertProduct = database.prepare(
        `INSERT INTO products
         (id, name, category, price_paise, duration_days, daily_reward_paise, total_reward_paise, purchase_limit)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    database.transaction(rows => rows.forEach(row => {
        const [id, name, category, price, duration, daily, total, limit] = row;
        insertProduct.run(id, name, category, price * 100, duration, daily * 100, total * 100, limit);
    }))(initialProducts);
}
if (database.prepare("SELECT COUNT(*) AS count FROM missions").get().count === 0) {
    const initialMissions = [
        ["3 team members", "Reach 3 team members", 3, 50],
        ["5 team members", "Reach 5 team members", 5, 120],
        ["10 team members", "Reach 10 team members", 10, 300],
        ["20 team members", "Reach 20 team members", 20, 700],
        ["35 team members", "Reach 35 team members", 35, 1500],
        ["50 team members", "Reach 50 team members", 50, 3000],
        ["100 team members", "Reach 100 team members", 100, 7000]
    ];
    const insertMission = database.prepare(
        "INSERT INTO missions (name, description, target_members, reward_paise) VALUES (?, ?, ?, ?)"
    );
    database.transaction(rows => rows.forEach(row => {
        const [name, description, target, reward] = row;
        insertMission.run(name, description, target, reward * 100);
    }))(initialMissions);
}
const initialSettings = [
    ["site_name", "Finora"],
    ["site_logo_url", "/assets/images/kingfisher-logo.svg"],
    ["site_banner_url", "/assets/images/money-hero.svg"],
    ["site_spinner_url", "/assets/images/Speener.svg"],
    ["support_url", "https://t.me/Kingfisher_supportbot"],
    ["minimum_recharge_rupees", "295"],
    ["minimum_withdrawal_rupees", "170"],
    ["maintenance_mode", "false"]
];
const insertSetting = database.prepare(
    "INSERT OR IGNORE INTO site_settings (key, value) VALUES (?, ?)"
);
initialSettings.forEach(row => insertSetting.run(...row));
database.prepare(
    "UPDATE site_settings SET value = '/assets/images/money-hero.svg' WHERE key = 'site_banner_url' AND value = '/assets/images/hero.svg'"
).run();

const adminUsername = (process.env.ADMIN_USERNAME || "").trim();
const adminPassword = process.env.ADMIN_PASSWORD || "";
if (Boolean(adminUsername) !== Boolean(adminPassword)) {
    throw new Error("Set both ADMIN_USERNAME and ADMIN_PASSWORD to bootstrap the first admin.");
}
if (adminUsername && (adminUsername.length < 3 || adminUsername.length > 64)) {
    throw new Error("ADMIN_USERNAME must be 3 to 64 characters.");
}
if (adminPassword && adminPassword.length < 12) {
    throw new Error("ADMIN_PASSWORD must be at least 12 characters.");
}
if (adminUsername && database.prepare("SELECT COUNT(*) AS count FROM admins").get().count === 0) {
    database.prepare(
        "INSERT INTO admins (username, password_hash, password_change_required) VALUES (?, ?, 1)"
    ).run(adminUsername, bcrypt.hashSync(adminPassword, 12));
    console.log("Initial admin account created; it must change its password after signing in.");
}

class SqliteSessionStore extends session.Store {
    get(sid, callback) {
        try {
            const row = database.prepare(
                "SELECT data FROM sessions WHERE sid = ? AND expires > ?"
            ).get(sid, Date.now());
            callback(null, row ? JSON.parse(row.data) : null);
        } catch (error) {
            callback(error);
        }
    }

    set(sid, value, callback) {
        const expires = value.cookie && value.cookie.expires
            ? new Date(value.cookie.expires).getTime()
            : Date.now() + 24 * 60 * 60 * 1000;
        try {
            database.prepare(
                `INSERT INTO sessions (sid, expires, data) VALUES (?, ?, ?)
                 ON CONFLICT(sid) DO UPDATE SET expires = excluded.expires, data = excluded.data`
            ).run(sid, expires, JSON.stringify(value));
            callback(null);
        } catch (error) {
            callback(error);
        }
    }

    touch(sid, value, callback) {
        const expires = value.cookie && value.cookie.expires
            ? new Date(value.cookie.expires).getTime()
            : Date.now() + 24 * 60 * 60 * 1000;
        try {
            database.prepare("UPDATE sessions SET expires = ? WHERE sid = ?").run(expires, sid);
            callback(null);
        } catch (error) {
            callback(error);
        }
    }

    destroy(sid, callback) {
        try {
            database.prepare("DELETE FROM sessions WHERE sid = ?").run(sid);
            callback(null);
        } catch (error) {
            callback(error);
        }
    }
}

const sessionStore = new SqliteSessionStore();

app.disable("x-powered-by");
if (isProduction) {
    app.set("trust proxy", 1);
}
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            baseUri: ["'self'"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            imgSrc: ["'self'", "data:", "https://img.icons8.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"]
        }
    }
}));
app.use(express.json({ limit: "10kb" }));
app.use(session({
    name: "kingfisher.sid",
    secret: sessionSecret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: "strict",
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use((req, res, next) => {
    const maintenanceMode = database.prepare(
        "SELECT value FROM site_settings WHERE key = 'maintenance_mode'"
    ).get()?.value === "true";
    if (!maintenanceMode
        || req.path === "/admin"
        || req.path === "/admin.html"
        || req.path === "/api/admin"
        || req.path.startsWith("/api/admin/")
        || req.path === "/api/csrf"
        || req.path === "/api/logout"
        || req.path.startsWith("/assets/")
        || req.path.startsWith("/uploads/")) {
        return next();
    }

    res.set("Cache-Control", "no-store");
    res.set("Retry-After", "60");
    if (req.path.startsWith("/api/")) {
        return res.status(503).json({
            success: false,
            message: "The site is temporarily unavailable for maintenance."
        });
    }
    res.status(503).type("html").send(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">" +
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
        "<title>Maintenance · Finora</title><body style=\"font:16px system-ui,sans-serif;max-width:560px;margin:15vh auto;padding:24px;color:#344054\">" +
        "<h1>We’ll be back soon</h1><p>The site is temporarily unavailable while maintenance is in progress. Please try again shortly.</p>" +
        "</body></html>"
    );
});

function asyncRoute(handler) {
    return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function createCsrfToken() {
    return randomBytes(32).toString("hex");
}

function tokenMatches(expected, supplied) {
    if (typeof supplied !== "string" || !/^[a-f0-9]{64}$/i.test(supplied)) {
        return false;
    }
    const expectedBuffer = Buffer.from(expected, "hex");
    const suppliedBuffer = Buffer.from(supplied, "hex");
    return expectedBuffer.length === suppliedBuffer.length
        && timingSafeEqual(expectedBuffer, suppliedBuffer);
}

function requireCsrf(req, res, next) {
    if (!req.session.csrfToken
        || !tokenMatches(req.session.csrfToken, req.get("X-CSRF-Token"))) {
        return res.status(403).json({ success: false, message: "Session expired. Refresh and try again." });
    }
    next();
}

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Please log in first." });
    }
    const user = database.prepare("SELECT status FROM users WHERE id = ?").get(req.session.user.id);
    if (!user || user.status !== "active") {
        if (req.session.impersonation && req.session.admin) {
            delete req.session.user;
            delete req.session.impersonation;
            req.session.csrfToken = createCsrfToken();
            return res.status(401).json({ success:false, message:"This user account is unavailable. Admin access has been restored." });
        }
        req.session.destroy(() => {});
        return res.status(401).json({ success: false, message: "This account is unavailable." });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.admin) {
        return res.status(401).json({ success: false, message: "Admin login required." });
    }
    next();
}

function auditAdmin(adminId, action, entityType, entityId, details) {
    database.prepare(
        "INSERT INTO admin_audit (admin_id, action, entity_type, entity_id, details_json) VALUES (?, ?, ?, ?, ?)"
    ).run(adminId, action, entityType, String(entityId || ""), JSON.stringify(details || {}));
}

function parseRupees(value) {
    const amount = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(amount) || Math.abs(amount) > 10000000) return null;
    const paise = Math.round(amount * 100);
    return Number.isSafeInteger(paise) ? paise : null;
}

function encryptBankAccount(accountNumber) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", bankEncryptionKey, iv);
    const ciphertext = Buffer.concat([
        cipher.update(accountNumber, "utf8"),
        cipher.final()
    ]);
    return {
        ciphertext: ciphertext.toString("hex"),
        iv: iv.toString("hex"),
        tag: cipher.getAuthTag().toString("hex")
    };
}

function decryptBankAccount(record) {
    const decipher = createDecipheriv(
        "aes-256-gcm",
        bankEncryptionKey,
        Buffer.from(record.account_iv, "hex")
    );
    decipher.setAuthTag(Buffer.from(record.account_tag, "hex"));
    return Buffer.concat([
        decipher.update(Buffer.from(record.account_ciphertext, "hex")),
        decipher.final()
    ]).toString("utf8");
}

function createReferralCode() {
    let code;
    do {
        code = randomBytes(5).toString("hex").toUpperCase();
    } while (database.prepare("SELECT 1 FROM users WHERE referral_code = ?").get(code));
    return code;
}

function countTeamMembers(userId) {
    return database.prepare(
        `WITH RECURSIVE descendants(id) AS (
             SELECT id FROM users WHERE referred_by_user_id = ?
             UNION ALL
             SELECT users.id FROM users JOIN descendants ON users.referred_by_user_id = descendants.id
         )
         SELECT COUNT(*) AS count FROM descendants`
    ).get(userId).count;
}

function countActiveTeamMembers(userId) {
    return database.prepare(
        `WITH RECURSIVE descendants(id, level) AS (
             SELECT id, 1 FROM users WHERE referred_by_user_id = ?
             UNION ALL
             SELECT users.id, descendants.level + 1
             FROM users JOIN descendants ON users.referred_by_user_id = descendants.id
             WHERE descendants.level < 3
         )
         SELECT COUNT(*) AS count FROM descendants JOIN users ON users.id = descendants.id
         WHERE users.status = 'active'`
    ).get(userId).count;
}

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { success: false, message: "Too many attempts. Please try again later." }
});

app.get("/api/csrf", asyncRoute(async (req, res) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = createCsrfToken();
    }
    res.set("Cache-Control", "no-store");
    res.json({ csrfToken: req.session.csrfToken });
}));
app.get("/api/public/settings", (req, res) => {
    const settings = database.prepare(
        "SELECT key, value FROM site_settings WHERE key IN ('site_name', 'site_logo_url', 'site_banner_url', 'site_spinner_url', 'minimum_recharge_rupees', 'minimum_withdrawal_rupees', 'support_url')"
    ).all();
    res.set("Cache-Control", "no-store");
    res.json({ success:true, settings:Object.fromEntries(settings.map(setting => [setting.key, setting.value])) });
});
function siteImagePath(settingKey, fallbackFilename) {
    const imageUrl = database.prepare("SELECT value FROM site_settings WHERE key = ?").get(settingKey)?.value || "";
    let imagePath;
    if (/^\/uploads\/media\/[a-f0-9]{32}\.(?:png|jpg|webp)$/.test(imageUrl)) {
        imagePath = path.join(mediaDirectory, path.basename(imageUrl));
    } else if (/^\/assets\/images\/[a-zA-Z0-9_-]+\.(?:svg|png|jpe?g|webp)$/.test(imageUrl)) {
        imagePath = path.join(__dirname, "assets", "images", path.basename(imageUrl));
    }
    if (!imagePath || !fs.existsSync(imagePath)) {
        imagePath = path.join(__dirname, "assets", "images", fallbackFilename);
    }
    return imagePath;
}
app.get("/site-logo", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(siteImagePath("site_logo_url", "kingfisher-logo.svg"));
});
app.get("/site-banner", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(siteImagePath("site_banner_url", "money-hero.svg"));
});

app.post("/api/register", authLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const phone = typeof req.body.phone === "string" ? req.body.phone : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const referralCode = typeof req.body.referralCode === "string"
        ? req.body.referralCode.trim().toUpperCase()
        : "";

    if (!name || name.length > 50) {
        return res.status(400).json({ success: false, message: "Enter a name up to 50 characters." });
    }
    if (!/^\d{10}$/.test(phone)) {
        return res.status(400).json({ success: false, message: "Enter a valid 10 digit mobile number." });
    }
    if (password.length < 6 || password.length > 64) {
        return res.status(400).json({ success: false, message: "Password must be 6 to 64 characters." });
    }
    if (referralCode && !/^[A-F0-9]{10}$/.test(referralCode)) {
        return res.status(400).json({ success: false, message: "Invalid invite code." });
    }
    const referrer = referralCode
        ? database.prepare("SELECT id FROM users WHERE referral_code = ?").get(referralCode)
        : null;
    if (referralCode && !referrer) {
        return res.status(400).json({ success: false, message: "This invite code is not valid." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    try {
        database.prepare(
            "INSERT INTO users (name, phone, password_hash, referral_code, referred_by_user_id) VALUES (?, ?, ?, ?, ?)"
        ).run(name, phone, passwordHash, createReferralCode(), referrer ? referrer.id : null);
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).json({ success: false, message: "An account with this mobile number already exists." });
        }
        throw error;
    }

    res.status(201).json({ success: true, message: "Account created successfully." });
}));

app.post("/api/login", authLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const phone = typeof req.body.phone === "string" ? req.body.phone : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";

    if (!/^\d{10}$/.test(phone) || !password || password.length > 64) {
        return res.status(400).json({ success: false, message: "Enter a valid mobile number and password." });
    }

    const user = database.prepare(
        "SELECT id, name, phone, password_hash, status FROM users WHERE phone = ?"
    ).get(phone);
    const passwordMatches = user
        ? await bcrypt.compare(password, user.password_hash)
        : await bcrypt.compare(password, dummyPasswordHash);

    if (!user || user.status !== "active" || !passwordMatches) {
        return res.status(401).json({ success: false, message: "Invalid mobile number or password." });
    }

    await new Promise((resolve, reject) => {
        req.session.regenerate(error => error ? reject(error) : resolve());
    });
    req.session.user = { id: user.id, name: user.name, phone: user.phone };
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => {
        req.session.save(error => error ? reject(error) : resolve());
    });

    res.json({
        success: true,
        message: "Login successful.",
        csrfToken: req.session.csrfToken
    });
}));

app.get("/api/session", (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Not logged in." });
    }
    const user = database.prepare(
        `SELECT id, name, phone, status, balance_paise AS balancePaise, referral_code AS referralCode
         FROM users WHERE id = ?`
    ).get(req.session.user.id);
    if (!user || user.status !== "active") {
        return res.status(401).json({ success: false, message: "This account is unavailable." });
    }
    res.json({ success: true, user });
});

app.post("/api/logout", requireCsrf, asyncRoute(async (req, res) => {
    if (req.session.impersonation) {
        return res.status(403).json({ success:false, message:"Use the support access banner to return to admin." });
    }
    await new Promise((resolve, reject) => {
        req.session.destroy(error => error ? reject(error) : resolve());
    });
    res.clearCookie("kingfisher.sid", {
        httpOnly: true,
        secure: isProduction,
        sameSite: "strict"
    });
    res.json({ success: true, message: "Logged out." });
}));

app.post("/api/products/purchase", requireCsrf, requireAuth, (req, res) => {
    const productId = Number.parseInt(req.body.productId, 10);
    if (!Number.isSafeInteger(productId) || productId < 1) {
        return res.status(400).json({ success:false, message:"Choose a valid product." });
    }
    const outcome = database.transaction(() => {
        const product = database.prepare(
            `SELECT id, name, price_paise AS pricePaise, duration_days AS durationDays,
                    purchase_limit AS purchaseLimit
             FROM products WHERE id = ? AND active = 1`
        ).get(productId);
        if (!product) return { error:"This product is no longer available.", status:404 };
        const purchasedCount = database.prepare(
            "SELECT COUNT(*) AS count FROM user_products WHERE user_id = ? AND product_id = ?"
        ).get(req.session.user.id, productId).count;
        if (purchasedCount >= product.purchaseLimit) {
            return { error:"You have reached the purchase limit for this product.", status:409 };
        }
        const user = database.prepare(
            "SELECT balance_paise AS balancePaise FROM users WHERE id = ?"
        ).get(req.session.user.id);
        const pendingWithdrawals = database.prepare(
            `SELECT COALESCE(SUM(amount_paise), 0) AS total FROM wallet_transactions
             WHERE user_id = ? AND type = 'withdrawal' AND status IN ('pending', 'processing')`
        ).get(req.session.user.id).total;
        const availablePaise = user.balancePaise - pendingWithdrawals;
        if (availablePaise < product.pricePaise) {
            return { error:"Insufficient available wallet balance. Complete a verified recharge first.", status:400 };
        }
        const purchase = database.prepare(
            `INSERT INTO user_products
             (user_id, product_id, product_name, price_paise, duration_days, expires_at)
             VALUES (?, ?, ?, ?, ?, datetime('now', '+' || ? || ' days'))`
        ).run(req.session.user.id, product.id, product.name, product.pricePaise,
            product.durationDays, product.durationDays);
        if (product.pricePaise > 0) {
            database.prepare(
                "UPDATE users SET balance_paise = balance_paise - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            ).run(product.pricePaise, req.session.user.id);
            database.prepare(
                `INSERT INTO wallet_transactions (user_id, type, amount_paise, status, note, reviewed_at)
                 VALUES (?, 'adjustment', ?, 'approved', ?, CURRENT_TIMESTAMP)`
            ).run(req.session.user.id, -product.pricePaise,
                `Product purchase #${purchase.lastInsertRowid}: ${product.name}`);
        }
        return { purchaseId:purchase.lastInsertRowid, productName:product.name, pricePaise:product.pricePaise };
    })();
    if (outcome.error) return res.status(outcome.status).json({ success:false, message:outcome.error });
    res.status(201).json({
        success:true,
        ...outcome,
        message:`${outcome.productName} is active. ₹${(outcome.pricePaise / 100).toFixed(2)} was deducted from the internal wallet. Product purchase does not activate any return or reward.`
    });
});

app.get("/api/my-products", requireAuth, (req, res) => {
    const products = database.prepare(
        `SELECT up.id, up.product_id AS productId, up.product_name AS productName,
                up.price_paise AS pricePaise, up.duration_days AS durationDays,
                up.purchased_at AS purchasedAt, up.expires_at AS expiresAt,
                CASE WHEN up.expires_at <= CURRENT_TIMESTAMP THEN 'expired' ELSE up.status END AS status,
                COALESCE(p.image_url, '') AS imageUrl
         FROM user_products up LEFT JOIN products p ON p.id = up.product_id
         WHERE up.user_id = ? ORDER BY up.id DESC LIMIT 100`
    ).all(req.session.user.id);
    res.set("Cache-Control", "no-store");
    res.json({ success:true, products });
});

app.get("/api/bank-account", requireAuth, (req, res) => {
    const account = database.prepare(
        `SELECT holder_name AS holderName, bank_name AS bankName,
                account_last4 AS accountLast4, ifsc, updated_at AS updatedAt
         FROM bank_accounts WHERE user_id = ?`
    ).get(req.session.user.id);
    res.set("Cache-Control", "no-store");
    res.json({ success:true, account:account || null });
});

app.put("/api/bank-account", requireCsrf, requireAuth, (req, res) => {
    const holderName = typeof req.body.holderName === "string" ? req.body.holderName.trim() : "";
    const bankName = typeof req.body.bankName === "string" ? req.body.bankName.trim() : "";
    const accountNumber = typeof req.body.accountNumber === "string"
        ? req.body.accountNumber.replace(/\s+/g, "")
        : "";
    const ifsc = typeof req.body.ifsc === "string" ? req.body.ifsc.trim().toUpperCase() : "";
    if (!holderName || holderName.length > 80 || !bankName || bankName.length > 80
        || !/^\d{8,18}$/.test(accountNumber) || !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) {
        return res.status(400).json({ success:false, message:"Enter a valid account holder, bank, 8–18 digit account number and IFSC code." });
    }
    const pendingWithdrawal = database.prepare(
        "SELECT 1 FROM wallet_transactions WHERE user_id = ? AND type = 'withdrawal' AND status IN ('pending', 'processing') LIMIT 1"
    ).get(req.session.user.id);
    if (pendingWithdrawal) {
        return res.status(409).json({ success:false, message:"Bank details cannot be changed while a withdrawal is pending." });
    }
    const encrypted = encryptBankAccount(accountNumber);
    database.prepare(
        `INSERT INTO bank_accounts
         (user_id, holder_name, bank_name, account_ciphertext, account_iv, account_tag, account_last4, ifsc, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(user_id) DO UPDATE SET holder_name = excluded.holder_name,
         bank_name = excluded.bank_name, account_ciphertext = excluded.account_ciphertext,
         account_iv = excluded.account_iv, account_tag = excluded.account_tag,
         account_last4 = excluded.account_last4, ifsc = excluded.ifsc, updated_at = CURRENT_TIMESTAMP`
    ).run(req.session.user.id, holderName, bankName, encrypted.ciphertext,
        encrypted.iv, encrypted.tag, accountNumber.slice(-4), ifsc);
    res.json({
        success:true,
        account:{holderName, bankName, accountLast4:accountNumber.slice(-4), ifsc},
        message:"Bank details saved encrypted. Only the last four account digits are shown in your profile."
    });
});
app.post("/api/recharge", requireCsrf, requireAuth, (req, res) => {
    const amountPaise = parseRupees(req.body.amount);
    const method = typeof req.body.method === "string" ? req.body.method.trim().slice(0, 40) : "";
    const minimum = Number(database.prepare(
        "SELECT value FROM site_settings WHERE key = 'minimum_recharge_rupees'"
    ).get()?.value || 295);
    if (!amountPaise || amountPaise < minimum * 100 || !method) {
        return res.status(400).json({ success: false, message: "Enter a valid amount and payment channel." });
    }
    const result = database.prepare(
        `INSERT INTO wallet_transactions (user_id, type, amount_paise, status, reference, note)
         VALUES (?, 'recharge', ?, 'pending', ?, 'Submitted for manual verification')`
    ).run(req.session.user.id, amountPaise, method);
    res.status(202).json({
        success: true,
        transactionId: result.lastInsertRowid,
        message: "Recharge request submitted for admin review. No balance has been credited yet."
    });
});
app.post("/api/withdrawal", requireCsrf, requireAuth, (req, res) => {
    const amountPaise = parseRupees(req.body.amount);
    const minimum = Number(database.prepare(
        "SELECT value FROM site_settings WHERE key = 'minimum_withdrawal_rupees'"
    ).get()?.value || 170);
    if (!amountPaise || amountPaise < minimum * 100) {
        return res.status(400).json({ success: false, message: "Enter a valid withdrawal amount." });
    }
    const bankAccount = database.prepare(
        "SELECT 1 FROM bank_accounts WHERE user_id = ?"
    ).get(req.session.user.id);
    if (!bankAccount) {
        return res.status(400).json({ success:false, message:"Save your bank account in Bank setup before requesting a withdrawal." });
    }
    const result = database.transaction(() => {
        const user = database.prepare("SELECT balance_paise FROM users WHERE id = ?").get(req.session.user.id);
        const pendingTotal = database.prepare(
            `SELECT COALESCE(SUM(amount_paise), 0) AS total FROM wallet_transactions
             WHERE user_id = ? AND type = 'withdrawal' AND status IN ('pending', 'processing')`
        ).get(req.session.user.id).total;
        if (amountPaise + pendingTotal > user.balance_paise) {
            return { error:"Amount exceeds your available balance." };
        }
        return database.prepare(
            `INSERT INTO wallet_transactions (user_id, type, amount_paise, status, note)
             VALUES (?, 'withdrawal', ?, 'pending', 'Awaiting manual payout review')`
        ).run(req.session.user.id, amountPaise);
    })();
    if (result.error) return res.status(400).json({ success:false, message:result.error });
    res.status(202).json({
        success: true,
        transactionId: result.lastInsertRowid,
        message: "Withdrawal request submitted for admin review. No payout has been sent yet."
    });
});
app.post("/api/spin", requireCsrf, requireAuth, (req, res) => {
    res.status(503).json({
        success: false,
        message: "Prize spins are not configured. No spin or reward was used."
    });
});

app.get("/api/products", requireAuth, (req, res) => {
    const products = database.prepare(
        `SELECT id, name, category, price_paise AS pricePaise, duration_days AS durationDays,
                daily_reward_paise AS dailyRewardPaise, total_reward_paise AS totalRewardPaise,
                purchase_limit AS purchaseLimit, image_url AS imageUrl,
                (SELECT COUNT(*) FROM user_products up
                 WHERE up.user_id = ? AND up.product_id = products.id) AS purchasedCount
         FROM products WHERE active = 1 ORDER BY category, id`
    ).all(req.session.user.id);
    res.set("Cache-Control", "no-store");
    res.json({ success: true, products });
});
app.get("/api/wallet", requireAuth, (req, res) => {
    const userId = req.session.user.id;
    const balancePaise = database.prepare("SELECT balance_paise FROM users WHERE id = ?").get(userId).balance_paise;
    const pendingWithdrawalsPaise = database.prepare(
        `SELECT COALESCE(SUM(amount_paise), 0) AS total FROM wallet_transactions
         WHERE user_id = ? AND type = 'withdrawal' AND status IN ('pending', 'processing')`
    ).get(userId).total;
    const transactions = database.prepare(
        `SELECT id, type, amount_paise AS amountPaise, status, reference, note,
                created_at AS createdAt, reviewed_at AS reviewedAt
         FROM wallet_transactions WHERE user_id = ? ORDER BY id DESC LIMIT 100`
    ).all(userId);
    const bankAccount = database.prepare(
        "SELECT account_last4 AS accountLast4, ifsc FROM bank_accounts WHERE user_id = ?"
    ).get(userId);
    const minimumRecharge = Number(database.prepare(
        "SELECT value FROM site_settings WHERE key = 'minimum_recharge_rupees'"
    ).get().value);
    const minimumWithdrawal = Number(database.prepare(
        "SELECT value FROM site_settings WHERE key = 'minimum_withdrawal_rupees'"
    ).get().value);
    const approvedRechargesPaise = database.prepare(
        `SELECT COALESCE(SUM(amount_paise), 0) AS total FROM wallet_transactions
         WHERE user_id = ? AND type = 'recharge' AND status = 'approved'`
    ).get(userId).total;
    const approvedRewardsPaise = database.prepare(
        `SELECT COALESCE(SUM(amount_paise), 0) AS total FROM wallet_transactions
         WHERE user_id = ? AND type = 'adjustment' AND status = 'approved' AND amount_paise > 0`
    ).get(userId).total;
    const requests = [
        ...database.prepare(
            `SELECT id, 'product' AS type, product_name AS title, price_paise AS amountPaise,
                    status, note, created_at AS createdAt
             FROM product_requests WHERE user_id = ?`
        ).all(userId),
        ...database.prepare(
            `SELECT c.id, 'mission' AS type, m.name AS title, m.reward_paise AS amountPaise,
                    c.status, c.note, c.created_at AS createdAt
             FROM mission_claims c JOIN missions m ON m.id = c.mission_id WHERE c.user_id = ?`
        ).all(userId)
    ].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
    res.set("Cache-Control", "no-store");
    res.json({
        success: true, balancePaise, pendingWithdrawalsPaise, approvedRechargesPaise, approvedRewardsPaise,
        bankAccount:bankAccount || null,
        minimumRecharge, minimumWithdrawal, transactions, requests
    });
});
app.get("/api/team", requireAuth, (req, res) => {
    const userId = req.session.user.id;
    const team = database.prepare(
        `WITH RECURSIVE descendants(id, level) AS (
             SELECT id, 1 FROM users WHERE referred_by_user_id = ?
             UNION ALL
             SELECT users.id, descendants.level + 1
             FROM users JOIN descendants ON users.referred_by_user_id = descendants.id
             WHERE descendants.level < 3
         ), recharge_by_user AS (
             SELECT user_id, SUM(amount_paise) AS total FROM wallet_transactions
             WHERE status = 'approved' AND type = 'recharge' GROUP BY user_id
         )
         SELECT descendants.level, COUNT(*) AS total,
                SUM(CASE WHEN users.status = 'active' THEN 1 ELSE 0 END) AS active,
                COALESCE(SUM(recharge_by_user.total), 0) AS rechargePaise
         FROM descendants JOIN users ON users.id = descendants.id
         LEFT JOIN recharge_by_user ON recharge_by_user.user_id = users.id
         GROUP BY descendants.level ORDER BY descendants.level`
    ).all(userId);
    const levels = [1, 2, 3].map(level => {
        const row = team.find(item => item.level === level);
        return { level, total: row ? row.total : 0, active: row ? row.active : 0,
            rechargePaise: row ? row.rechargePaise : 0 };
    });
    const profile = database.prepare(
        "SELECT referral_code AS referralCode FROM users WHERE id = ?"
    ).get(userId);
    res.set("Cache-Control", "no-store");
    res.json({
        success: true, referralCode: profile.referralCode,
        totalMembers: levels.reduce((sum, row) => sum + row.total, 0),
        activeMembers: levels.reduce((sum, row) => sum + row.active, 0),
        totalRechargePaise: levels.reduce((sum, row) => sum + row.rechargePaise, 0),
        levels, commissionPaise: 0
    });
});
app.get("/api/missions", requireAuth, (req, res) => {
    const activeMembers = countActiveTeamMembers(req.session.user.id);
    const missions = database.prepare(
        `SELECT m.id, m.name, m.description, m.target_members AS targetMembers,
                m.reward_paise AS rewardPaise, c.status AS claimStatus
         FROM missions m LEFT JOIN mission_claims c
           ON c.mission_id = m.id AND c.user_id = ?
         WHERE m.active = 1 ORDER BY m.target_members, m.id`
    ).all(req.session.user.id);
    res.json({ success: true, activeMembers, missions });
});
app.post("/api/missions/claim", requireCsrf, requireAuth, (req, res) => {
    const missionId = Number.parseInt(req.body.missionId, 10);
    if (!Number.isSafeInteger(missionId) || missionId < 1) {
        return res.status(400).json({ success: false, message: "Choose a valid mission." });
    }
    const mission = database.prepare(
        "SELECT id, target_members AS targetMembers FROM missions WHERE id = ? AND active = 1"
    ).get(missionId);
    if (!mission) return res.status(404).json({ success: false, message: "Mission not found." });
    const activeMembers = countActiveTeamMembers(req.session.user.id);
    if (activeMembers < mission.targetMembers) {
        return res.status(400).json({ success: false, message: "Your verified team has not reached this mission yet." });
    }
    const existing = database.prepare(
        "SELECT status FROM mission_claims WHERE user_id = ? AND mission_id = ?"
    ).get(req.session.user.id, missionId);
    if (existing && existing.status !== "rejected") {
        return res.status(409).json({
            success: false,
            message: existing.status === "approved" ? "This mission reward was already approved." : "This mission is already waiting for review."
        });
    }
    if (existing) {
        database.prepare(
            `UPDATE mission_claims SET status = 'pending', note = '', reviewed_by_admin_id = NULL,
             created_at = CURRENT_TIMESTAMP, reviewed_at = NULL WHERE user_id = ? AND mission_id = ?`
        ).run(req.session.user.id, missionId);
    } else {
        database.prepare(
            "INSERT INTO mission_claims (user_id, mission_id, status) VALUES (?, ?, 'pending')"
        ).run(req.session.user.id, missionId);
    }
    res.status(202).json({ success: true, message: "Mission claim submitted for admin verification." });
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 8,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { success: false, message: "Too many admin login attempts. Try again later." }
});

app.get("/api/admin/session", (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!req.session.admin || req.session.impersonation) {
        return res.status(401).json({ success: false, configured: database.prepare("SELECT COUNT(*) AS count FROM admins").get().count > 0 });
    }
    const admin = database.prepare(
        "SELECT username, password_change_required AS passwordChangeRequired FROM admins WHERE id = ?"
    ).get(req.session.admin.id);
    if (!admin) return res.status(401).json({ success: false });
    res.json({ success: true, admin, csrfToken: req.session.csrfToken });
});

app.post("/api/admin/login", adminLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const admin = database.prepare(
        "SELECT id, username, password_hash, password_change_required FROM admins WHERE username = ? COLLATE NOCASE"
    ).get(username);
    const passwordMatches = admin
        ? await bcrypt.compare(password, admin.password_hash)
        : await bcrypt.compare(password, dummyPasswordHash);
    if (!admin || !passwordMatches || !password) {
        return res.status(401).json({ success: false, message: "Invalid admin username or password." });
    }

    await new Promise((resolve, reject) => {
        req.session.regenerate(error => error ? reject(error) : resolve());
    });
    req.session.admin = { id: admin.id, username: admin.username };
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => {
        req.session.save(error => error ? reject(error) : resolve());
    });
    database.prepare("UPDATE admins SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?").run(admin.id);
    auditAdmin(admin.id, "login", "admin", admin.id, {});
    res.json({
        success: true,
        admin: { username: admin.username, passwordChangeRequired: Boolean(admin.password_change_required) },
        csrfToken: req.session.csrfToken
    });
}));

app.post("/api/admin/logout", requireCsrf, requireAdmin, asyncRoute(async (req, res) => {
    if (req.session.impersonation) {
        return res.status(403).json({ success:false, message:"Return to admin before signing out." });
    }
    auditAdmin(req.session.admin.id, "logout", "admin", req.session.admin.id, {});
    await new Promise((resolve, reject) => {
        req.session.destroy(error => error ? reject(error) : resolve());
    });
    res.clearCookie("kingfisher.sid", {
        httpOnly: true,
        secure: isProduction,
        sameSite: "strict"
    });
    res.json({ success: true });
}));

app.post("/api/admin/impersonation/stop", requireCsrf, requireAdmin, asyncRoute(async (req, res) => {
    const impersonation = req.session.impersonation;
    if (!impersonation) {
        return res.status(409).json({ success:false, message:"No user support session is active." });
    }
    auditAdmin(req.session.admin.id, "stop_user_support_access", "user", impersonation.userId, {
        startedAt:impersonation.startedAt
    });
    delete req.session.user;
    delete req.session.impersonation;
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => {
        req.session.save(error => error ? reject(error) : resolve());
    });
    res.json({ success:true, message:"Returned to admin panel." });
}));

app.post("/api/admin/change-password", requireCsrf, requireAdmin, asyncRoute(async (req, res) => {
    const currentPassword = typeof req.body.currentPassword === "string" ? req.body.currentPassword : "";
    const newPassword = typeof req.body.newPassword === "string" ? req.body.newPassword : "";
    const admin = database.prepare("SELECT password_hash FROM admins WHERE id = ?").get(req.session.admin.id);
    if (!admin || !(await bcrypt.compare(currentPassword, admin.password_hash))) {
        return res.status(400).json({ success: false, message: "Current password is incorrect." });
    }
    if (newPassword.length < 12 || newPassword.length > 128) {
        return res.status(400).json({ success: false, message: "New password must be 12 to 128 characters." });
    }
    database.prepare(
        "UPDATE admins SET password_hash = ?, password_change_required = 0 WHERE id = ?"
    ).run(await bcrypt.hash(newPassword, 12), req.session.admin.id);
    auditAdmin(req.session.admin.id, "change_password", "admin", req.session.admin.id, {});
    res.json({ success: true, message: "Admin password updated." });
}));

app.use("/api/admin", (req, res, next) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
    requireCsrf(req, res, next);
}, requireAdmin, (req, res, next) => {
    if (req.session.impersonation) {
        return res.status(403).json({ success:false, message:"Admin actions are unavailable during user support access." });
    }
    next();
});

app.post("/api/admin/media/:kind", express.raw({
    type: ["image/png", "image/jpeg", "image/webp"],
    limit: "3mb"
}), (req, res) => {
    const kind = req.params.kind;
    const mimeTypes = {
        "image/png": { extension:"png", signature:buffer => buffer.length >= 8
            && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) },
        "image/jpeg": { extension:"jpg", signature:buffer => buffer.length >= 3
            && buffer[0] === 255 && buffer[1] === 216 && buffer[2] === 255 },
        "image/webp": { extension:"webp", signature:buffer => buffer.length >= 12
            && buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP" }
    };
    const mediaType = mimeTypes[req.get("Content-Type")];
    const image = req.body;
    if (!["logo", "banner", "spinner", "product"].includes(kind)) {
        return res.status(400).json({ success:false, message:"Choose a valid image type." });
    }
    if (!Buffer.isBuffer(image) || image.length === 0 || !mediaType || !mediaType.signature(image)) {
        return res.status(400).json({ success:false, message:"Upload a valid PNG, JPEG, or WebP image." });
    }

    const filename = `${randomBytes(16).toString("hex")}.${mediaType.extension}`;
    const imageUrl = `/uploads/media/${filename}`;
    try {
        fs.writeFileSync(path.join(mediaDirectory, filename), image, { flag:"wx", mode:0o644 });
        if (kind === "logo" || kind === "banner" || kind === "spinner") {
            const settingKey = `site_${kind}_url`;
            database.prepare(
                `INSERT INTO site_settings (key, value, updated_at, updated_by_admin_id)
                 VALUES (?, ?, CURRENT_TIMESTAMP, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                 updated_at = CURRENT_TIMESTAMP, updated_by_admin_id = excluded.updated_by_admin_id`
            ).run(settingKey, imageUrl, req.session.admin.id);
            auditAdmin(req.session.admin.id, `update_${kind}_image`, "setting", settingKey, { imageUrl });
        } else {
            auditAdmin(req.session.admin.id, "upload_product_image", "media", filename, {});
        }
    } catch (error) {
        console.error("Admin media upload failed:", error);
        return res.status(500).json({ success:false, message:"Could not save the image. Please try again." });
    }
    res.status(201).json({ success:true, imageUrl });
});

app.get("/api/admin/overview", (req, res) => {
    const summary = {
        users: database.prepare("SELECT COUNT(*) AS count FROM users").get().count,
        activeUsers: database.prepare("SELECT COUNT(*) AS count FROM users WHERE status = 'active'").get().count,
        suspendedUsers: database.prepare("SELECT COUNT(*) AS count FROM users WHERE status = 'suspended'").get().count,
        walletPaise: database.prepare("SELECT COALESCE(SUM(balance_paise), 0) AS total FROM users").get().total,
        pendingTransactions: database.prepare("SELECT COUNT(*) AS count FROM wallet_transactions WHERE status IN ('pending', 'processing')").get().count,
        pendingMissionClaims: database.prepare("SELECT COUNT(*) AS count FROM mission_claims WHERE status = 'pending'").get().count,
        pendingProductRequests: database.prepare("SELECT COUNT(*) AS count FROM product_requests WHERE status = 'pending'").get().count,
        activeProducts: database.prepare("SELECT COUNT(*) AS count FROM products WHERE active = 1").get().count,
        activeMissions: database.prepare("SELECT COUNT(*) AS count FROM missions WHERE active = 1").get().count
    };
    res.json({ success: true, summary });
});

app.get("/api/admin/users", (req, res) => {
    const search = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 80) : "";
    const page = Math.max(1, Math.min(10000, Number.parseInt(req.query.page, 10) || 1));
    const limit = 25;
    const filter = `%${search.replace(/[\\%_]/g, "\\$&")}%`;
    const users = database.prepare(
        `SELECT id, name, phone, status, balance_paise AS balancePaise, created_at AS createdAt,
                EXISTS(SELECT 1 FROM bank_accounts b WHERE b.user_id = users.id) AS bankConfigured
         FROM users
         WHERE (? = '' OR name LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\')
         ORDER BY id DESC LIMIT ? OFFSET ?`
    ).all(search, filter, filter, limit, (page - 1) * limit);
    const total = database.prepare(
        "SELECT COUNT(*) AS count FROM users WHERE (? = '' OR name LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\')"
    ).get(search, filter, filter).count;
    res.json({ success: true, users, total, page, pageSize: limit });
});

app.get("/api/admin/demo-accounts", (req, res) => {
    const accounts = database.prepare(
        `SELECT id, demo_code AS demoCode, name, balance_paise AS balancePaise,
                created_at AS createdAt
         FROM demo_accounts ORDER BY id DESC LIMIT 200`
    ).all();
    const transactions = database.prepare(
        `SELECT t.id, t.demo_account_id AS demoAccountId, a.demo_code AS demoCode,
                a.name AS accountName, t.type, t.amount_paise AS amountPaise,
                t.note, t.created_at AS createdAt
         FROM demo_wallet_transactions t
         JOIN demo_accounts a ON a.id = t.demo_account_id
         ORDER BY t.id DESC LIMIT 200`
    ).all();
    res.set("Cache-Control", "no-store");
    res.json({ success: true, accounts, transactions });
});

app.post("/api/admin/demo-accounts", (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    if (!name || name.length > 80) {
        return res.status(400).json({ success: false, message: "Enter a demo account name up to 80 characters." });
    }
    let demoCode;
    do {
        demoCode = `DEMO-${randomBytes(4).toString("hex").toUpperCase()}`;
    } while (database.prepare("SELECT 1 FROM demo_accounts WHERE demo_code = ?").get(demoCode));

    const result = database.prepare(
        "INSERT INTO demo_accounts (demo_code, name, created_by_admin_id) VALUES (?, ?, ?)"
    ).run(demoCode, name, req.session.admin.id);
    auditAdmin(req.session.admin.id, "create_demo_account", "demo_account", result.lastInsertRowid,
        { demoCode, name });
    res.status(201).json({
        success: true,
        account: { id: result.lastInsertRowid, demoCode, name, balancePaise: 0 },
        message: "Demo account created. It is separate from real users and cannot receive or send real money."
    });
});

app.post("/api/admin/demo-accounts/:id/transactions", (req, res) => {
    const accountId = /^\d+$/.test(req.params.id) ? Number(req.params.id) : NaN;
    const type = req.body.type;
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(accountId) || accountId < 1
        || !["deposit", "withdrawal"].includes(type)
        || !Number.isSafeInteger(amountPaise) || amountPaise <= 0 || !note) {
        return res.status(400).json({ success: false, message: "Enter a valid demo account, transaction type, amount and note." });
    }

    const operation = database.transaction(() => {
        const account = database.prepare(
            "SELECT id, demo_code AS demoCode, balance_paise AS balancePaise FROM demo_accounts WHERE id = ?"
        ).get(accountId);
        if (!account) return { error: "Demo account not found.", status: 404 };
        if (type === "withdrawal" && account.balancePaise < amountPaise) {
            return { error: "Demo withdrawal exceeds the demo balance.", status: 400 };
        }

        const balancePaise = account.balancePaise
            + (type === "deposit" ? amountPaise : -amountPaise);
        database.prepare(
            "UPDATE demo_accounts SET balance_paise = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).run(balancePaise, accountId);
        const result = database.prepare(
            `INSERT INTO demo_wallet_transactions
             (demo_account_id, type, amount_paise, note, created_by_admin_id)
             VALUES (?, ?, ?, ?, ?)`
        ).run(accountId, type === "deposit" ? "demo_deposit" : "demo_withdrawal",
            amountPaise, note, req.session.admin.id);
        auditAdmin(req.session.admin.id, `demo_${type}`, "demo_account", accountId,
            { demoCode: account.demoCode, amountPaise, balancePaise, note });
        return { balancePaise, transactionId: result.lastInsertRowid };
    });
    const result = operation();
    if (result.error) {
        return res.status(result.status).json({ success: false, message: result.error });
    }
    res.status(201).json({
        success: true,
        ...result,
        message: `Simulated demo ${type} recorded. No real wallet or payment was changed.`
    });
});

app.patch("/api/admin/users/:id/status", (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    const status = req.body.status;
    if (!Number.isSafeInteger(userId) || !["active", "suspended"].includes(status)) {
        return res.status(400).json({ success: false, message: "Invalid user status." });
    }
    const result = database.prepare(
        "UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    ).run(status, userId);
    if (!result.changes) return res.status(404).json({ success: false, message: "User not found." });
    auditAdmin(req.session.admin.id, "set_user_status", "user", userId, { status });
    res.json({ success: true });
});

app.post("/api/admin/users/:id/impersonate", asyncRoute(async (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    const target = database.prepare("SELECT id, name, status FROM users WHERE id = ?").get(userId);
    if (!Number.isSafeInteger(userId) || !target) {
        return res.status(404).json({ success:false, message:"User not found." });
    }
    if (target.status !== "active") {
        return res.status(409).json({ success:false, message:"Activate this account before starting support access." });
    }
    const admin = req.session.admin;
    if (!admin || req.session.impersonation) {
        return res.status(403).json({ success:false, message:"Admin support access is unavailable." });
    }
    await new Promise((resolve, reject) => {
        req.session.regenerate(error => error ? reject(error) : resolve());
    });
    const startedAt = new Date().toISOString();
    req.session.admin = admin;
    req.session.user = { id:target.id, name:target.name };
    req.session.impersonation = { userId:target.id, startedAt };
    req.session.csrfToken = createCsrfToken();
    auditAdmin(admin.id, "start_user_support_access", "user", target.id, { startedAt });
    await new Promise((resolve, reject) => {
        req.session.save(error => error ? reject(error) : resolve());
    });
    res.json({ success:true, destination:"/home.html" });
}));

app.delete("/api/admin/users/:id/bank-account", (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(userId) || userId < 1) {
        return res.status(400).json({ success:false, message:"Invalid user." });
    }
    const hasPendingWithdrawal = database.prepare(
        "SELECT 1 FROM wallet_transactions WHERE user_id = ? AND type = 'withdrawal' AND status IN ('pending', 'processing') LIMIT 1"
    ).get(userId);
    if (hasPendingWithdrawal) {
        return res.status(409).json({ success:false, message:"Bank details cannot be removed while a withdrawal is pending." });
    }
    const result = database.prepare("DELETE FROM bank_accounts WHERE user_id = ?").run(userId);
    if (!result.changes) return res.status(404).json({ success:false, message:"This user has no saved bank account." });
    auditAdmin(req.session.admin.id, "remove_user_bank_account", "user", userId, {});
    res.json({ success:true, message:"Saved bank details removed." });
});

app.post("/api/admin/users/:id/reset-password", asyncRoute(async (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!Number.isSafeInteger(userId) || password.length < 8 || password.length > 128) {
        return res.status(400).json({ success: false, message: "User password must be 8 to 128 characters." });
    }
    const result = database.prepare(
        "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    ).run(await bcrypt.hash(password, 12), userId);
    if (!result.changes) return res.status(404).json({ success: false, message: "User not found." });
    auditAdmin(req.session.admin.id, "reset_user_password", "user", userId, {});
    res.json({ success: true, message: "User password reset. Share the temporary password securely." });
}));

app.post("/api/admin/users/:id/adjust-balance", (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(userId) || !amountPaise || !note) {
        return res.status(400).json({ success: false, message: "Enter a valid non-zero amount and reason." });
    }
    const operation = database.transaction(() => {
        const user = database.prepare("SELECT balance_paise FROM users WHERE id = ?").get(userId);
        if (!user) return { error: "User not found.", status: 404 };
        if (user.balance_paise + amountPaise < 0) return { error: "Adjustment would make the wallet negative.", status: 400 };
        database.prepare(
            "UPDATE users SET balance_paise = balance_paise + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).run(amountPaise, userId);
        database.prepare(
            `INSERT INTO wallet_transactions
             (user_id, type, amount_paise, status, note, created_by_admin_id, reviewed_by_admin_id, reviewed_at)
             VALUES (?, 'adjustment', ?, 'approved', ?, ?, ?, CURRENT_TIMESTAMP)`
        ).run(userId, amountPaise, note, req.session.admin.id, req.session.admin.id);
        auditAdmin(req.session.admin.id, "adjust_wallet", "user", userId, { amountPaise, note });
        return { balancePaise: user.balance_paise + amountPaise };
    });
    const result = operation();
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({ success: true, balancePaise: result.balancePaise });
});

app.get("/api/admin/products", (req, res) => {
    const products = database.prepare(
        `SELECT id, name, category, price_paise AS pricePaise, duration_days AS durationDays,
                daily_reward_paise AS dailyRewardPaise, total_reward_paise AS totalRewardPaise,
                purchase_limit AS purchaseLimit, active, image_url AS imageUrl
         FROM products ORDER BY category, id`
    ).all();
    res.json({ success: true, products });
});

function productValues(body) {
    const name = typeof body.name === "string" ? body.name.trim().slice(0, 80) : "";
    const category = body.category;
    const pricePaise = parseRupees(body.price);
    const durationDays = Number(body.durationDays);
    const dailyRewardPaise = parseRupees(body.dailyReward || 0);
    const totalRewardPaise = parseRupees(body.totalReward || 0);
    const purchaseLimit = Number(body.purchaseLimit);
    const imageUrl = typeof body.imageUrl === "string" ? body.imageUrl.trim() : "";
    if (!name || !["daily", "vip"].includes(category)
        || pricePaise === null || pricePaise < 0
        || !Number.isInteger(durationDays) || durationDays < 1 || durationDays > 3650
        || dailyRewardPaise === null || dailyRewardPaise < 0
        || totalRewardPaise === null || totalRewardPaise < 0
        || !Number.isInteger(purchaseLimit) || purchaseLimit < 1 || purchaseLimit > 10000
        || (imageUrl && !/^\/uploads\/media\/[a-f0-9]{32}\.(?:png|jpg|webp)$/.test(imageUrl))) {
        return null;
    }
    return [name, category, pricePaise, durationDays, dailyRewardPaise, totalRewardPaise, purchaseLimit, imageUrl];
}

app.post("/api/admin/products", (req, res) => {
    const values = productValues(req.body);
    if (!values) return res.status(400).json({ success: false, message: "Check product fields and try again." });
    const result = database.prepare(
        `INSERT INTO products
         (name, category, price_paise, duration_days, daily_reward_paise, total_reward_paise, purchase_limit, image_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(...values);
    auditAdmin(req.session.admin.id, "create_product", "product", result.lastInsertRowid, { name: values[0] });
    res.status(201).json({ success: true, id: result.lastInsertRowid });
});

app.put("/api/admin/products/:id", (req, res) => {
    const productId = Number.parseInt(req.params.id, 10);
    const values = productValues(req.body);
    const active = req.body.active === false || req.body.active === 0 ? 0 : 1;
    if (!Number.isSafeInteger(productId) || !values) {
        return res.status(400).json({ success: false, message: "Check product fields and try again." });
    }
    const result = database.prepare(
        `UPDATE products SET name = ?, category = ?, price_paise = ?, duration_days = ?,
         daily_reward_paise = ?, total_reward_paise = ?, purchase_limit = ?, image_url = ?, active = ?,
         updated_at = CURRENT_TIMESTAMP WHERE id = ?`
    ).run(...values, active, productId);
    if (!result.changes) return res.status(404).json({ success: false, message: "Product not found." });
    auditAdmin(req.session.admin.id, "update_product", "product", productId, { name: values[0], active });
    res.json({ success: true });
});

app.delete("/api/admin/products/:id", (req, res) => {
    const productId = Number.parseInt(req.params.id, 10);
    const result = database.prepare(
        "UPDATE products SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    ).run(productId);
    if (!result.changes) return res.status(404).json({ success: false, message: "Product not found." });
    auditAdmin(req.session.admin.id, "deactivate_product", "product", productId, {});
    res.json({ success: true });
});

app.get("/api/admin/missions", (req, res) => {
    const missions = database.prepare(
        `SELECT id, name, description, target_members AS targetMembers,
                reward_paise AS rewardPaise, active FROM missions ORDER BY target_members, id`
    ).all();
    res.json({ success: true, missions });
});

app.post("/api/admin/missions", (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim().slice(0, 100) : "";
    const description = typeof req.body.description === "string" ? req.body.description.trim().slice(0, 500) : "";
    const targetMembers = Number(req.body.targetMembers);
    const rewardPaise = parseRupees(req.body.reward);
    if (!name || !Number.isInteger(targetMembers) || targetMembers < 0 || targetMembers > 100000000
        || rewardPaise === null || rewardPaise < 0) {
        return res.status(400).json({ success: false, message: "Check mission fields and try again." });
    }
    const result = database.prepare(
        "INSERT INTO missions (name, description, target_members, reward_paise) VALUES (?, ?, ?, ?)"
    ).run(name, description, targetMembers, rewardPaise);
    auditAdmin(req.session.admin.id, "create_mission", "mission", result.lastInsertRowid, { name });
    res.status(201).json({ success: true, id: result.lastInsertRowid });
});

app.put("/api/admin/missions/:id", (req, res) => {
    const missionId = Number.parseInt(req.params.id, 10);
    const name = typeof req.body.name === "string" ? req.body.name.trim().slice(0, 100) : "";
    const description = typeof req.body.description === "string" ? req.body.description.trim().slice(0, 500) : "";
    const targetMembers = Number(req.body.targetMembers);
    const rewardPaise = parseRupees(req.body.reward);
    const active = req.body.active === false || req.body.active === 0 ? 0 : 1;
    if (!Number.isSafeInteger(missionId) || !name || !Number.isInteger(targetMembers)
        || targetMembers < 0 || targetMembers > 100000000 || rewardPaise === null || rewardPaise < 0) {
        return res.status(400).json({ success: false, message: "Check mission fields and try again." });
    }
    const result = database.prepare(
        `UPDATE missions SET name = ?, description = ?, target_members = ?, reward_paise = ?,
         active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
    ).run(name, description, targetMembers, rewardPaise, active, missionId);
    if (!result.changes) return res.status(404).json({ success: false, message: "Mission not found." });
    auditAdmin(req.session.admin.id, "update_mission", "mission", missionId, { name, active });
    res.json({ success: true });
});

app.get("/api/admin/transactions", (req, res) => {
    const status = typeof req.query.status === "string" ? req.query.status : "";
    const validStatus = ["pending", "processing", "approved", "rejected"].includes(status) ? status : "";
    const transactions = database.prepare(
        `SELECT t.id, t.user_id AS userId, u.name AS userName, u.phone,
                t.type, t.amount_paise AS amountPaise, t.status, t.reference,
                t.note, t.created_at AS createdAt, t.reviewed_at AS reviewedAt,
                b.holder_name AS bankHolderName, b.bank_name AS bankName,
                b.account_last4 AS bankAccountLast4, b.ifsc AS bankIfsc
         FROM wallet_transactions t JOIN users u ON u.id = t.user_id
         LEFT JOIN bank_accounts b ON b.user_id = t.user_id
         WHERE (? = '' OR t.status = ?)
         ORDER BY CASE t.status WHEN 'pending' THEN 0 WHEN 'processing' THEN 1 ELSE 2 END, t.id DESC LIMIT 300`
    ).all(validStatus, validStatus);
    res.json({ success: true, transactions });
});

app.post("/api/admin/transactions/:id/payout-details", (req, res) => {
    const transactionId = /^\d+$/.test(req.params.id) ? Number(req.params.id) : NaN;
    if (!Number.isSafeInteger(transactionId) || transactionId < 1) {
        return res.status(400).json({ success:false, message:"Invalid transaction ID." });
    }
    const transaction = database.prepare(
        "SELECT user_id AS userId, type, status FROM wallet_transactions WHERE id = ?"
    ).get(transactionId);
    if (!transaction || transaction.type !== "withdrawal" || !["pending", "processing"].includes(transaction.status)) {
        return res.status(409).json({ success:false, message:"Only active withdrawal requests can reveal payout details." });
    }
    const account = database.prepare(
        `SELECT holder_name AS holderName, bank_name AS bankName,
                account_ciphertext AS accountCiphertext, account_iv AS accountIv,
                account_tag AS accountTag, ifsc
         FROM bank_accounts WHERE user_id = ?`
    ).get(transaction.userId);
    if (!account) {
        return res.status(404).json({ success:false, message:"The customer has not configured a bank account." });
    }
    let accountNumber;
    try {
        accountNumber = decryptBankAccount({
            account_ciphertext:account.accountCiphertext,
            account_iv:account.accountIv,
            account_tag:account.accountTag
        });
    } catch (error) {
        console.error("Bank account decryption failed for withdrawal", transactionId, error);
        return res.status(500).json({ success:false, message:"Could not decrypt payout details. Check the bank encryption key." });
    }
    auditAdmin(req.session.admin.id, "reveal_withdrawal_bank_details", "transaction", transactionId,
        { userId:transaction.userId });
    res.set("Cache-Control", "no-store");
    res.json({
        success:true,
        payoutDetails:{
            holderName:account.holderName,
            bankName:account.bankName,
            accountNumber,
            ifsc:account.ifsc
        }
    });
});

app.get("/api/admin/mission-claims", (req, res) => {
    const status = typeof req.query.status === "string" && ["pending", "approved", "rejected"].includes(req.query.status)
        ? req.query.status : "";
    const claims = database.prepare(
        `SELECT c.id, c.user_id AS userId, u.name AS userName, u.phone,
                c.mission_id AS missionId, m.name AS missionName,
                m.target_members AS targetMembers, m.reward_paise AS rewardPaise,
                c.status, c.note, c.created_at AS createdAt, c.reviewed_at AS reviewedAt
         FROM mission_claims c
         JOIN users u ON u.id = c.user_id
         JOIN missions m ON m.id = c.mission_id
         WHERE (? = '' OR c.status = ?)
         ORDER BY CASE c.status WHEN 'pending' THEN 0 ELSE 1 END, c.id DESC LIMIT 300`
    ).all(status, status);
    res.json({ success: true, claims });
});

app.get("/api/admin/product-requests", (req, res) => {
    const status = typeof req.query.status === "string" && ["pending", "approved", "rejected"].includes(req.query.status)
        ? req.query.status : "";
    const requests = database.prepare(
        `SELECT r.id, r.user_id AS userId, u.name AS userName, u.phone,
                r.product_id AS productId, r.product_name AS productName,
                r.price_paise AS pricePaise, r.status, r.note,
                r.created_at AS createdAt, r.reviewed_at AS reviewedAt
         FROM product_requests r JOIN users u ON u.id = r.user_id
         WHERE (? = '' OR r.status = ?)
         ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.id DESC LIMIT 300`
    ).all(status, status);
    res.json({ success:true, requests });
});

app.post("/api/admin/product-requests/:id/review", (req, res) => {
    const requestId = Number.parseInt(req.params.id, 10);
    const decision = req.body.decision;
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(requestId) || !["approved", "rejected"].includes(decision) || !note) {
        return res.status(400).json({ success:false, message:"Choose a decision and enter a review note." });
    }
    const result = database.prepare(
        `UPDATE product_requests SET status = ?, note = ?, reviewed_by_admin_id = ?,
         reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'`
    ).run(decision, note, req.session.admin.id, requestId);
    if (!result.changes) return res.status(409).json({ success:false, message:"Request not found or already reviewed." });
    auditAdmin(req.session.admin.id, `product_request_${decision}`, "product_request", requestId, { note });
    res.json({ success:true, message:"Request reviewed. Product purchase and rewards remain inactive pending a configured fulfilment flow." });
});

app.post("/api/admin/mission-claims/:id/review", (req, res) => {
    const claimId = Number.parseInt(req.params.id, 10);
    const decision = req.body.decision;
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(claimId) || !["approved", "rejected"].includes(decision) || !note) {
        return res.status(400).json({ success: false, message: "Choose a decision and enter a review note." });
    }
    const operation = database.transaction(() => {
        const claim = database.prepare(
            `SELECT c.id, c.user_id AS userId, c.mission_id AS missionId, c.status,
                    m.target_members AS targetMembers, m.reward_paise AS rewardPaise, m.active
             FROM mission_claims c JOIN missions m ON m.id = c.mission_id WHERE c.id = ?`
        ).get(claimId);
        if (!claim) return { error: "Mission claim not found.", status: 404 };
        if (claim.status !== "pending") return { error: "This claim has already been reviewed.", status: 409 };
        if (decision === "approved" && (!claim.active || countActiveTeamMembers(claim.userId) < claim.targetMembers)) {
            return { error: "The mission is inactive or the member no longer meets its team requirement.", status: 409 };
        }
        if (decision === "approved") {
            database.prepare(
                "UPDATE users SET balance_paise = balance_paise + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            ).run(claim.rewardPaise, claim.userId);
            if (claim.rewardPaise > 0) {
                database.prepare(
                    `INSERT INTO wallet_transactions
                     (user_id, type, amount_paise, status, note, created_by_admin_id, reviewed_by_admin_id, reviewed_at)
                     VALUES (?, 'adjustment', ?, 'approved', ?, ?, ?, CURRENT_TIMESTAMP)`
                ).run(claim.userId, claim.rewardPaise, `Mission claim #${claimId}: ${note}`,
                    req.session.admin.id, req.session.admin.id);
            }
        }
        database.prepare(
            `UPDATE mission_claims SET status = ?, note = ?, reviewed_by_admin_id = ?,
             reviewed_at = CURRENT_TIMESTAMP WHERE id = ?`
        ).run(decision, note, req.session.admin.id, claimId);
        auditAdmin(req.session.admin.id, `mission_claim_${decision}`, "mission_claim", claimId,
            { userId: claim.userId, missionId: claim.missionId, rewardPaise: decision === "approved" ? claim.rewardPaise : 0, note });
        return { success: true };
    });
    const result = operation();
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({ success: true });
});

app.post("/api/admin/transactions", (req, res) => {
    const userId = Number.parseInt(req.body.userId, 10);
    const type = req.body.type;
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    const reference = typeof req.body.reference === "string" ? req.body.reference.trim().slice(0, 120) : "";
    if (!Number.isSafeInteger(userId) || !["recharge", "withdrawal"].includes(type)
        || !amountPaise || amountPaise < 0 || !note) {
        return res.status(400).json({ success: false, message: "Check transaction fields and try again." });
    }
    const user = database.prepare("SELECT id FROM users WHERE id = ?").get(userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });
    const result = database.prepare(
        `INSERT INTO wallet_transactions
         (user_id, type, amount_paise, status, reference, note, created_by_admin_id)
         VALUES (?, ?, ?, 'pending', ?, ?, ?)`
    ).run(userId, type, amountPaise, reference, note, req.session.admin.id);
    auditAdmin(req.session.admin.id, "create_transaction", "transaction", result.lastInsertRowid, { userId, type, amountPaise });
    res.status(201).json({ success: true, id: result.lastInsertRowid });
});

app.post("/api/admin/transactions/:id/review", (req, res) => {
    const transactionId = Number.parseInt(req.params.id, 10);
    const decision = req.body.decision;
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(transactionId) || !["processing", "approved", "rejected"].includes(decision) || !note) {
        return res.status(400).json({ success: false, message: "Choose a valid decision and enter a review note." });
    }
    const operation = database.transaction(() => {
        const transaction = database.prepare(
            "SELECT id, user_id, type, amount_paise, status FROM wallet_transactions WHERE id = ?"
        ).get(transactionId);
        if (!transaction) return { error: "Transaction not found.", status: 404 };
        if (decision === "processing") {
            if (transaction.type !== "withdrawal" || transaction.status !== "pending") {
                return { error:"Only pending withdrawal requests can be moved to processing.", status:409 };
            }
            const bankAccount = database.prepare(
                "SELECT 1 FROM bank_accounts WHERE user_id = ?"
            ).get(transaction.user_id);
            if (!bankAccount) {
                return { error:"Customer has not configured a bank account.", status:409 };
            }
        } else if (!["pending", "processing"].includes(transaction.status)
            || (transaction.type !== "withdrawal" && transaction.status !== "pending")) {
            return { error: "This transaction has already been reviewed.", status: 409 };
        }
        if (decision === "approved" && transaction.type === "withdrawal") {
            const bankAccount = database.prepare(
                "SELECT 1 FROM bank_accounts WHERE user_id = ?"
            ).get(transaction.user_id);
            if (!bankAccount) {
                return { error:"Customer has not configured a bank account.", status:409 };
            }
            const user = database.prepare("SELECT balance_paise FROM users WHERE id = ?").get(transaction.user_id);
            const otherReservedWithdrawals = database.prepare(
                `SELECT COALESCE(SUM(amount_paise), 0) AS total FROM wallet_transactions
                 WHERE user_id = ? AND type = 'withdrawal' AND status IN ('pending', 'processing') AND id != ?`
            ).get(transaction.user_id, transactionId).total;
            if (user.balance_paise < transaction.amount_paise + otherReservedWithdrawals) {
                return { error: "Insufficient available balance for this withdrawal.", status: 409 };
            }
            database.prepare(
                "UPDATE users SET balance_paise = balance_paise - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            ).run(transaction.amount_paise, transaction.user_id);
        } else if (decision === "approved" && transaction.type === "recharge") {
            database.prepare(
                "UPDATE users SET balance_paise = balance_paise + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            ).run(transaction.amount_paise, transaction.user_id);
        }
        database.prepare(
            `UPDATE wallet_transactions SET status = ?, reference = CASE WHEN ? = '' THEN reference ELSE ? END,
             note = ?, reviewed_by_admin_id = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?`
        ).run(decision, note, note, note, req.session.admin.id, transactionId);
        auditAdmin(req.session.admin.id, `transaction_${decision}`, "transaction", transactionId, {
            userId: transaction.user_id, type: transaction.type, amountPaise: transaction.amount_paise, note
        });
        return { success: true };
    });
    const result = operation();
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({ success: true });
});

app.get("/api/admin/settings", (req, res) => {
    const settings = database.prepare(
        "SELECT key, value, updated_at AS updatedAt FROM site_settings ORDER BY key"
    ).all();
    res.json({ success: true, settings });
});

app.put("/api/admin/settings/:key", (req, res) => {
    const key = req.params.key;
    const value = typeof req.body.value === "string" ? req.body.value.trim() : "";
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(key) || value.length > 500) {
        return res.status(400).json({ success: false, message: "Invalid setting key or value." });
    }
    if (["minimum_recharge_rupees", "minimum_withdrawal_rupees"].includes(key)) {
        const numericValue = Number(value);
        if (!Number.isFinite(numericValue) || numericValue < 0 || numericValue > 10000000) {
            return res.status(400).json({ success: false, message: "Setting must be a valid non-negative amount." });
        }
    }
    if (key === "maintenance_mode" && !["true", "false"].includes(value)) {
        return res.status(400).json({ success: false, message: "Maintenance mode must be true or false." });
    }
    if (["site_logo_url", "site_banner_url", "site_spinner_url"].includes(key)
        && !/^\/(?:assets\/images\/[a-zA-Z0-9_-]+\.(?:svg|png|jpe?g|webp)|uploads\/media\/[a-f0-9]{32}\.(?:png|jpg|webp))$/.test(value)) {
        return res.status(400).json({ success:false, message:"Choose a valid image from the site image library or upload one." });
    }
    database.prepare(
        `INSERT INTO site_settings (key, value, updated_at, updated_by_admin_id) VALUES (?, ?, CURRENT_TIMESTAMP, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP,
         updated_by_admin_id = excluded.updated_by_admin_id`
    ).run(key, value, req.session.admin.id);
    auditAdmin(req.session.admin.id, "update_setting", "setting", key, { value });
    res.json({ success: true });
});

app.get("/api/admin/audit", (req, res) => {
    const events = database.prepare(
        `SELECT a.id, a.action, a.entity_type AS entityType, a.entity_id AS entityId,
                a.details_json AS details, a.created_at AS createdAt, d.username
         FROM admin_audit a JOIN admins d ON d.id = a.admin_id
         ORDER BY a.id DESC LIMIT 200`
    ).all();
    res.json({ success: true, events });
});

app.get("/assets/images/kingfisher-logo.svg", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(siteImagePath("site_logo_url", "kingfisher-logo.svg"));
});
app.get("/assets/images/hero.svg", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(siteImagePath("site_banner_url", "money-hero.svg"));
});
app.get("/assets/images/Speener.svg", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(siteImagePath("site_spinner_url", "Speener.svg"));
});
app.use("/uploads", express.static(path.join(__dirname, "uploads"), {
    dotfiles: "deny"
}));
app.use("/assets", express.static(path.join(__dirname, "assets"), {
    dotfiles: "deny"
}));

const protectedPages = new Set([
    "home.html", "mine.html", "invite.html", "account.html", "my-products.html", "bank-setup.html", "transactions.html", "spin.html",
    "recharge.html", "mission.html", "team.html", "withdrawal.html"
]);
const legacyPageAliases = new Map([
    ["/pages/home", "home.html"],
    ["/pages/recharge", "recharge.html"],
    ["/pages/withdrawal", "withdrawal.html"],
    ["/pages/mission", "mission.html"],
    ["/pages/invite", "invite.html"],
    ["/pages/spin", "spin.html"],
    ["/pages/team", "team.html"],
    ["/pages/mine", "mine.html"],
    ["/pages/account", "account.html"],
    ["/pages/my-products", "my-products.html"],
    ["/pages/transactions", "transactions.html"]
]);
function sendPage(req, res, page) {
    const filepath = path.join(__dirname, page);
    if (!req.session.impersonation) {
        return res.sendFile(filepath);
    }
    fs.readFile(filepath, "utf8", (error, html) => {
        if (error) {
            console.error(`Could not load support-access page ${page}:`, error);
            return res.status(500).type("text").send("Could not load this page.");
        }
        const target = database.prepare("SELECT name FROM users WHERE id = ?")
            .get(req.session.impersonation.userId);
        if (!target) return res.status(401).redirect("/admin/");
        const safeName = target.name.replace(/[&<>"']/g, character => ({
            "&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#39;"
        })[character]);
        const csrfToken = req.session.csrfToken;
        const bar = `<aside id="supportAccessBar" style="position:sticky;top:0;z-index:99999;background:#261b0d;color:#fff;padding:11px 16px;text-align:center;font:14px system-ui,sans-serif">Admin support access for <strong>${safeName}</strong> — user actions are visible. <button id="returnToAdmin" type="button" style="margin-left:12px;border:0;border-radius:6px;padding:8px 12px;background:#f2c14e;color:#261b0d;font-weight:700;cursor:pointer">Return to admin</button><span id="supportAccessError" role="status" style="margin-left:8px"></span></aside><script>(function(){const button=document.getElementById("returnToAdmin");button.addEventListener("click",async function(){button.disabled=true;try{const response=await fetch("/api/admin/impersonation/stop",{method:"POST",headers:{"X-CSRF-Token":"${csrfToken}"}});const result=await response.json();if(!response.ok)throw new Error(result.message||"Could not return to admin.");window.location.replace("/admin/");}catch(error){document.getElementById("supportAccessError").textContent=error.message;button.disabled=false;}});})();</script>`;
        const bodyTag = /<body\b[^>]*>/i;
        if (!bodyTag.test(html)) {
            return res.status(500).type("text").send("Support access page is missing a body element.");
        }
        res.set("Cache-Control", "no-store");
        res.type("html").send(html.replace(bodyTag, match => `${match}${bar}`));
    });
}
function sendLoginPage(req, res) {
    if (req.session.impersonation) return res.redirect(302, "/home.html");
    if (req.session.user) return res.redirect(302, "/home.html");
    sendPage(req, res, "index.html");
}
app.get("/", sendLoginPage);
app.get("/index.html", sendLoginPage);
app.get("/about.html", (req, res) => sendPage(req, res, "about.html"));
for (const page of protectedPages) {
    app.get(`/${page}`, (req, res) => {
        if (req.session.impersonation && !req.session.user) return res.redirect(302, "/admin/");
        if (!req.session.user) return res.redirect(302, "/index.html");
        const user = database.prepare("SELECT status FROM users WHERE id = ?").get(req.session.user.id);
        if (!user || user.status !== "active") {
            if (req.session.impersonation && req.session.admin) {
                delete req.session.user;
                delete req.session.impersonation;
                req.session.csrfToken = createCsrfToken();
                return req.session.save(error => {
                    if (error) {
                        console.error("Could not restore admin session:", error);
                        return res.status(500).send("Could not restore admin access.");
                    }
                    res.redirect(302, "/admin/");
                });
            }
            req.session.destroy(() => {});
            return res.redirect(302, "/index.html");
        }
        sendPage(req, res, page);
    });
}
for (const [alias, page] of legacyPageAliases) {
    app.get(alias, (req, res) => {
        if (req.session.impersonation && !req.session.user) return res.redirect(302, "/admin/");
        if (!req.session.user) return res.redirect(302, "/index.html");
        const user = database.prepare("SELECT status FROM users WHERE id = ?").get(req.session.user.id);
        if (!user || user.status !== "active") {
            if (req.session.impersonation && req.session.admin) {
                delete req.session.user;
                delete req.session.impersonation;
                req.session.csrfToken = createCsrfToken();
                return req.session.save(error => {
                    if (error) {
                        console.error("Could not restore admin session:", error);
                        return res.status(500).send("Could not restore admin access.");
                    }
                    res.redirect(302, "/admin/");
                });
            }
            req.session.destroy(() => {});
            return res.redirect(302, "/index.html");
        }
        sendPage(req, res, page);
    });
}
app.get(["/admin", "/admin.html"], (req, res) => {
    res.set("Cache-Control", "no-store");
    if (req.session.impersonation) return res.redirect(302, "/home.html");
    sendPage(req, res, "admin.html");
});

app.use((req, res) => {
    res.status(404).json({ success: false, message: "Not found." });
});

app.use((error, req, res, next) => {
    console.error("Request failed:", error);
    if (res.headersSent) {
        return next(error);
    }
    if (error.type === "entity.too.large") {
        return res.status(413).json({ success:false, message:"Image uploads must be 3 MB or smaller." });
    }
    if (error.type === "entity.parse.failed") {
        return res.status(400).json({ success:false, message:"Request body is invalid." });
    }
    res.status(500).json({ success: false, message: "Server error. Please try again." });
});

async function start() {
    const sessionCleanup = setInterval(() => {
        try {
            database.prepare("DELETE FROM sessions WHERE expires <= ?").run(Date.now());
        } catch (error) {
            console.error("Session cleanup failed:", error);
        }
    }, 15 * 60 * 1000);
    sessionCleanup.unref();
    app.listen(port, () => {
        console.log(`Finora server listening on port ${port}`);
    });
}

start().catch(error => {
    console.error("Could not start server:", error);
    process.exitCode = 1;
});
