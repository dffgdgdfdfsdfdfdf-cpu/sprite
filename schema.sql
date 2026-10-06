PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 50),
    phone TEXT NOT NULL UNIQUE CHECK (length(phone) = 10),
    password_hash TEXT NOT NULL,
    balance_paise INTEGER NOT NULL DEFAULT 0 CHECK (balance_paise >= 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    referral_code TEXT UNIQUE,
    referred_by_user_id INTEGER REFERENCES users(id),
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
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_status
    ON wallet_transactions(status, created_at);

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

-- Admin-only demo records are intentionally isolated from users and real wallet transactions.
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
