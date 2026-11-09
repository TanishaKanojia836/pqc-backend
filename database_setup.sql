BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS assets (
    asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name TEXT NOT NULL UNIQUE,
    asset_type TEXT NOT NULL,
    current_algorithm TEXT NOT NULL,
    data_sensitivity TEXT NOT NULL,
    internet_facing TEXT NOT NULL,
    data_retention_years INTEGER NOT NULL,
    owner TEXT NOT NULL,
    status TEXT DEFAULT 'Active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    auth_tag TEXT NOT NULL,
    status TEXT DEFAULT 'Encrypted',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (session_id) REFERENCES secure_sessions(session_id),
    FOREIGN KEY (sender_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    quantum_vulnerable TEXT NOT NULL,
    recommended_algorithm TEXT NOT NULL,
    migration_priority TEXT NOT NULL,
    reason TEXT NOT NULL,
    assessed_at TEXT DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);
CREATE TABLE IF NOT EXISTS secure_sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    public_key TEXT NOT NULL,
    status TEXT DEFAULT 'Active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,

    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO "assets" ("asset_id","asset_name","asset_type","current_algorithm","data_sensitivity","internet_facing","data_retention_years","owner","status","created_at") VALUES (1,'Customer Portal','Web Application','RSA-2048','High','Yes',10,'IT Security Team','Active','2026-11-09 19:19:47'),
 (2,'Corporate VPN Gateway','Network Security','RSA-2048','High','Yes',7,'Network Team','Active','2026-11-09 19:19:47'),
 (3,'Internal REST API','API Service','ECC P-256','Medium','No',3,'Backend Team','Active','2026-11-09 19:19:47'),
 (4,'Payment Gateway API','Financial API','RSA-3072','Critical','Yes',10,'Finance Security Team','Active','2026-11-09 19:19:47'),
 (5,'Email Gateway','Email Security','RSA-2048','High','Yes',5,'IT Operations','Active','2026-11-09 19:19:47'),
 (6,'Database Backup Service','Data Storage','AES-256','High','No',10,'Database Team','Active','2026-11-09 19:19:47'),
 (7,'Code Signing Service','Developer Tool','RSA-4096','High','No',5,'DevOps Team','Active','2026-11-09 19:19:47'),
 (8,'HR Portal','Web Application','ECC P-256','High','No',7,'HR IT Team','Active','2026-11-09 19:19:47'),
 (9,'IoT Device Management','IoT Platform','ECC P-256','Medium','Yes',3,'IoT Team','Active','2026-11-09 19:19:47'),
 (10,'Cloud Storage Gateway','Cloud Service','RSA-2048','Critical','Yes',10,'Cloud Security Team','Active','2026-11-09 19:19:47'),
 (11,'Legacy File Server','File Storage','RSA-1024','Medium','No',8,'IT Operations','Active','2026-11-09 19:19:47'),
 (12,'Quantum-Ready Messaging Service','Communication Service','ML-KEM-768','High','Yes',2,'Security Engineering','Active','2026-11-09 19:19:47');
INSERT INTO "messages" ("message_id","session_id","sender_id","ciphertext","nonce","auth_tag","status","created_at") VALUES (1,1,5,'BASE64_ENCRYPTED_MESSAGE_DEMO','BASE64_NONCE_DEMO','BASE64_AUTH_TAG_DEMO','Encrypted','2026-11-09 19:23:37');
INSERT INTO "risk_assessments" ("assessment_id","asset_id","risk_score","risk_level","quantum_vulnerable","recommended_algorithm","migration_priority","reason","assessed_at") VALUES (1,1,12,'Critical','Yes','ML-KEM','Immediate','Customer Portal uses RSA-2048, is internet-facing, handles high-sensitivity data, and retains data for 10 years.','2026-11-09 19:21:07'),
 (2,2,11,'Critical','Yes','ML-KEM','Immediate','VPN gateway uses RSA-2048, is internet-facing, and handles high-sensitivity data.','2026-11-09 19:21:07'),
 (3,3,6,'Medium','Yes','ML-KEM','Plan Migration','Internal API uses ECC P-256 but is not internet-facing and has shorter data retention.','2026-11-09 19:21:07'),
 (4,4,12,'Critical','Yes','ML-KEM','Immediate','Payment gateway uses RSA-3072, is internet-facing, and handles critical financial data.','2026-11-09 19:21:07'),
 (5,5,10,'Critical','Yes','ML-KEM','Immediate','Email gateway uses RSA-2048 and is internet-facing.','2026-11-09 19:21:07'),
 (6,6,4,'Medium','No','Key Management Review','Monitor','Database backup uses AES-256. Symmetric encryption has lower immediate quantum risk, but key management must be reviewed.','2026-11-09 19:21:07'),
 (7,7,8,'High','Yes','ML-DSA','Migrate Soon','Code-signing service uses RSA-4096 and requires a post-quantum signature migration.','2026-11-09 19:21:07'),
 (8,8,7,'High','Yes','ML-KEM','Migrate Soon','HR portal uses ECC and handles high-sensitivity employee data.','2026-11-09 19:21:07'),
 (9,9,6,'Medium','Yes','ML-KEM','Plan Migration','IoT platform uses ECC and is internet-facing but has shorter retention.','2026-11-09 19:21:07'),
 (10,10,12,'Critical','Yes','ML-KEM','Immediate','Cloud storage gateway uses RSA-2048, is internet-facing, and handles critical data.','2026-11-09 19:21:07'),
 (11,11,7,'High','Yes','ML-KEM','Migrate Soon','Legacy file server uses RSA-1024, which is outdated and must be upgraded.','2026-11-09 19:21:07'),
 (12,12,1,'Low','No','No Migration Required','Monitor','Messaging service already uses ML-KEM-768 and is considered quantum-ready.','2026-11-09 19:21:07');
INSERT INTO "secure_sessions" ("session_id","sender_id","receiver_id","algorithm","public_key","status","created_at","expires_at") VALUES (1,4,5,'ML-KEM-768','MLKEM_PUBLIC_KEY_DEMO_VALUE','Active','2026-11-09 19:22:46',NULL);
INSERT INTO "users" ("user_id","username","email","password_hash","role","created_at") VALUES (1,'admin','admin@pqcready.com','hashed_password_admin','admin','2026-11-09 19:19:15'),
 (2,'analyst','analyst@pqcready.com','hashed_password_analyst','analyst','2026-11-09 19:19:15'),
 (3,'engineer','engineer@pqcready.com','hashed_password_engineer','engineer','2026-11-09 19:19:15'),
 (4,'alice','alice@pqcready.com','hashed_password_alice','analyst','2026-11-09 19:21:53'),
 (5,'bob','bob@pqcready.com','hashed_password_bob','engineer','2026-11-09 19:21:53');
COMMIT;
