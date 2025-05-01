import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from 'ws';

neonConfig.webSocketConstructor = ws;

async function main() {
  console.log('Starting database setup...');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const db = drizzle(pool);

  console.log('Creating database schema from schema.ts...');
  try {
    const tablesQuery = `
      -- Create users table
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP,
        is_blocked BOOLEAN DEFAULT FALSE,
        block_reason TEXT,
        status TEXT,
        security_level TEXT,
        fraud_alert BOOLEAN DEFAULT FALSE,
        failed_login_attempts INTEGER DEFAULT 0,
        last_password_change TIMESTAMP,
        -- Feature restriction fields
        login_restricted BOOLEAN DEFAULT FALSE,
        transfer_restricted BOOLEAN DEFAULT FALSE,
        deposit_restricted BOOLEAN DEFAULT FALSE,
        withdrawal_restricted BOOLEAN DEFAULT FALSE,
        card_restricted BOOLEAN DEFAULT FALSE
      );

      -- Create accounts table
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        account_number TEXT NOT NULL UNIQUE,
        account_type TEXT NOT NULL,
        account_name TEXT NOT NULL,
        balance DECIMAL(10, 2) NOT NULL DEFAULT 0,
        available_balance DECIMAL(10, 2) NOT NULL DEFAULT 0,
        routing_number TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        opened_at TIMESTAMP DEFAULT NOW(),
        last_updated TIMESTAMP DEFAULT NOW()
      );

      -- Create transactions table
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        account_id INTEGER NOT NULL,
        transaction_type TEXT NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        description TEXT,
        category TEXT,
        transaction_date TIMESTAMP DEFAULT NOW(),
        status TEXT NOT NULL DEFAULT 'completed',
        merchant_name TEXT,
        to_account_id INTEGER,
        reference_number TEXT,
        method TEXT,
        admin_notes TEXT
      );

      -- Create cards table
      CREATE TABLE IF NOT EXISTS cards (
        id SERIAL PRIMARY KEY,
        account_id INTEGER NOT NULL,
        card_number TEXT NOT NULL,
        card_type TEXT NOT NULL,
        card_variant TEXT DEFAULT 'physical',
        expiry_date TEXT NOT NULL,
        cvv TEXT NOT NULL,
        cardholder_name TEXT NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        is_locked BOOLEAN DEFAULT FALSE,
        spending_limit DECIMAL(10, 2),
        purpose TEXT,
        contactless_enabled BOOLEAN DEFAULT TRUE,
        international_enabled BOOLEAN DEFAULT FALSE,
        last4 TEXT,
        card_network TEXT DEFAULT 'visa',
        card_brand TEXT DEFAULT 'standard',
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Create bills table
      CREATE TABLE IF NOT EXISTS bills (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        payee TEXT NOT NULL,
        account_number TEXT,
        amount DECIMAL(10, 2) NOT NULL,
        due_date TIMESTAMP NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        is_recurring BOOLEAN DEFAULT FALSE,
        frequency TEXT,
        category TEXT
      );

      -- Create support tickets table
      CREATE TABLE IF NOT EXISTS support_tickets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        priority TEXT NOT NULL DEFAULT 'medium',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- Create KYC verifications table
      CREATE TABLE IF NOT EXISTS kyc_verifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        id_type TEXT NOT NULL,
        id_number TEXT NOT NULL,
        document_front TEXT NOT NULL,
        document_back TEXT,
        selfie TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        submitted_at TIMESTAMP DEFAULT NOW(),
        reviewed_at TIMESTAMP,
        reviewer_id INTEGER,
        notes TEXT
      );

      -- Create WebAuthn credentials table
      CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        credential_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        counter INTEGER DEFAULT 0 NOT NULL,
        transports TEXT,
        attestation_format TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `;

    await pool.query(tablesQuery);
    console.log('Database tables created successfully!');

    // Create some sample data - optional
    const adminUser = await pool.query(`
      INSERT INTO users (username, password, email, first_name, last_name, role, is_verified) 
      VALUES ('admin', '$2b$10$EufbpvkxPD9aCWVQjxlBSuKPyTuxWfki.js9xpYwbIPkjMdlCUQ0W', 'admin@fortiscapital.com', 'Admin', 'User', 'admin', TRUE)
      ON CONFLICT (username) DO NOTHING
      RETURNING id;
    `);

    if (adminUser.rows.length > 0) {
      console.log('Admin user created successfully!');
    } else {
      console.log('Admin user already exists.');
    }

    const demoUser = await pool.query(`
      INSERT INTO users (username, password, email, first_name, last_name, role, is_verified) 
      VALUES ('sarahwilliams', '$2b$10$EufbpvkxPD9aCWVQjxlBSuKPyTuxWfki.js9xpYwbIPkjMdlCUQ0W', 'sarah@example.com', 'Sarah', 'Williams', 'user', TRUE)
      ON CONFLICT (username) DO NOTHING
      RETURNING id;
    `);

    if (demoUser.rows.length > 0) {
      const userId = demoUser.rows[0].id;
      console.log(`Demo user created with ID: ${userId}`);

      // Create sample accounts for demo user
      await pool.query(`
        INSERT INTO accounts (user_id, account_number, account_type, account_name, balance, available_balance, routing_number)
        VALUES 
          (${userId}, '1234567890', 'checking', 'Primary Checking', 5000.00, 5000.00, '021000021'),
          (${userId}, '0987654321', 'savings', 'Savings Account', 10000.00, 10000.00, '021000021'),
          (${userId}, '1122334455', 'credit', 'Credit Card', 500.00, 2500.00, NULL)
        ON CONFLICT (account_number) DO NOTHING;
      `);
      console.log('Sample accounts created for demo user.');
    } else {
      console.log('Demo user already exists.');
    }

  } catch (error) {
    console.error('Error setting up database:', error);
  } finally {
    await pool.end();
    console.log('Database setup completed.');
  }
}

main();