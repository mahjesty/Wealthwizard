import { pgTable, text, serial, integer, boolean, timestamp, decimal, jsonb, pgEnum } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// User schema
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  firstName: text("first_name").notNull(),
  lastName: text("last_name").notNull(),
  email: text("email").notNull().unique(),
  phoneNumber: text("phone_number"),
  role: text("role").notNull().default("user"),
  twoFactorEnabled: boolean("two_factor_enabled").default(false),
  createdAt: timestamp("created_at").defaultNow(),
  lastLogin: timestamp("last_login"),
  isActive: boolean("is_active").default(true),
  isVerified: boolean("is_verified").default(false),
  isBlocked: boolean("is_blocked").default(false),
  blockReason: text("block_reason"),
  fraudAlert: boolean("fraud_alert").default(false),
  securityLevel: text("security_level").default("standard"),
  lastPasswordChange: timestamp("last_password_change"),
  failedLoginAttempts: integer("failed_login_attempts").default(0),
  status: text("status").default("active"), // active, suspended, dormant, investigating
  
  // Feature restriction fields
  loginRestricted: boolean("login_restricted").default(false),
  loginRestrictionReason: text("login_restriction_reason"),
  transferRestricted: boolean("transfer_restricted").default(false),
  transferRestrictionReason: text("transfer_restriction_reason"),
  depositRestricted: boolean("deposit_restricted").default(false),
  depositRestrictionReason: text("deposit_restriction_reason"),
  withdrawalRestricted: boolean("withdrawal_restricted").default(false),
  withdrawalRestrictionReason: text("withdrawal_restriction_reason"),
  cardRestricted: boolean("card_restricted").default(false),
  cardRestrictionReason: text("card_restriction_reason"),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  firstName: true,
  lastName: true,
  email: true,
  phoneNumber: true,
});

// Account schema
export const accounts = pgTable("accounts", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  accountNumber: text("account_number").notNull().unique(),
  accountType: text("account_type").notNull(), // checking, savings, credit_card
  accountName: text("account_name").notNull(),
  balance: decimal("balance", { precision: 10, scale: 2 }).notNull().default("0"),
  availableBalance: decimal("available_balance", { precision: 10, scale: 2 }).notNull().default("0"),
  routingNumber: text("routing_number"),
  isActive: boolean("is_active").default(true),
  openedAt: timestamp("opened_at").defaultNow(),
  lastUpdated: timestamp("last_updated").defaultNow(),
});

export const insertAccountSchema = createInsertSchema(accounts).pick({
  userId: true,
  accountNumber: true,
  accountType: true,
  accountName: true,
  balance: true,
  availableBalance: true,
  routingNumber: true,
});

// Transaction schema
export const transactions = pgTable("transactions", {
  id: serial("id").primaryKey(),
  accountId: integer("account_id").notNull(),
  transactionType: text("transaction_type").notNull(), // credit, debit
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  description: text("description"),
  category: text("category"), // deposit, withdrawal, transfer, payment, groceries, utilities, etc.
  transactionDate: timestamp("transaction_date").defaultNow(),
  status: text("status").notNull().default("completed"), // pending, processing, completed, failed, cancelled, on_hold, disputed
  merchantName: text("merchant_name"),
  toAccountId: integer("to_account_id"), // for transfers
  referenceNumber: text("reference_number"),
  method: text("method"), // card, ach, wire, check, cash, internal, electronic, auto
  adminNotes: text("admin_notes"), // internal notes not visible to customers
});

export const insertTransactionSchema = createInsertSchema(transactions).pick({
  accountId: true,
  transactionType: true,
  amount: true,
  description: true,
  category: true,
  merchantName: true,
  toAccountId: true,
  transactionDate: true,
  status: true,
  referenceNumber: true,
  method: true,
  adminNotes: true,
});

// Card schema
export const cards = pgTable("cards", {
  id: serial("id").primaryKey(),
  accountId: integer("account_id").notNull(),
  cardNumber: text("card_number").notNull(),
  cardType: text("card_type").notNull(), // debit, credit
  cardVariant: text("card_variant").default("physical"), // physical, virtual
  expiryDate: text("expiry_date").notNull(),
  cvv: text("cvv").notNull(),
  cardholderName: text("cardholder_name").notNull(),
  isActive: boolean("is_active").default(true),
  isLocked: boolean("is_locked").default(false),
  spendingLimit: decimal("spending_limit", { precision: 10, scale: 2 }),
  purpose: text("purpose"), // online shopping, travel, subscriptions, etc.
  contactlessEnabled: boolean("contactless_enabled").default(true),
  internationalEnabled: boolean("international_enabled").default(false),
  last4: text("last4"), // Last 4 digits for display
  cardNetwork: text("card_network").default("visa"), // visa, mastercard, etc.
  cardBrand: text("card_brand").default("standard"), // standard, premium, platinum
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertCardSchema = createInsertSchema(cards).pick({
  accountId: true,
  cardNumber: true,
  cardType: true,
  cardVariant: true,
  expiryDate: true,
  cvv: true,
  cardholderName: true,
  spendingLimit: true,
  purpose: true,
  contactlessEnabled: true,
  internationalEnabled: true,
  cardNetwork: true,
  cardBrand: true,
});

// Bill schema
export const bills = pgTable("bills", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  payee: text("payee").notNull(),
  accountNumber: text("account_number"),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  dueDate: timestamp("due_date").notNull(),
  status: text("status").notNull().default("pending"), // pending, paid, overdue
  isRecurring: boolean("is_recurring").default(false),
  frequency: text("frequency"), // monthly, weekly, etc.
  category: text("category"), // utilities, rent, etc.
});

export const insertBillSchema = createInsertSchema(bills).pick({
  userId: true,
  payee: true,
  accountNumber: true,
  amount: true,
  dueDate: true,
  isRecurring: true,
  frequency: true,
  category: true,
});

// Support ticket schema
export const supportTickets = pgTable("support_tickets", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  subject: text("subject").notNull(),
  message: text("message").notNull(),
  status: text("status").notNull().default("open"), // open, in progress, closed
  priority: text("priority").notNull().default("medium"), // low, medium, high
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertSupportTicketSchema = createInsertSchema(supportTickets).pick({
  userId: true,
  subject: true,
  message: true,
  priority: true,
});

// KYC verification schema
export const kycVerifications = pgTable("kyc_verifications", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  idType: text("id_type").notNull(), // passport, driver_license, national_id, application_ssn
  idNumber: text("id_number").notNull(),
  documentFront: text("document_front"), // URL to stored document
  documentBack: text("document_back"), // URL to stored document
  selfie: text("selfie"), // URL to stored selfie
  status: text("status").notNull().default("pending"), // pending, approved, rejected
  submittedAt: timestamp("submitted_at").defaultNow(),
  reviewedAt: timestamp("reviewed_at"),
  reviewerId: integer("reviewer_id"),
  notes: text("notes"),
  applicationId: integer("application_id"), // Reference to account application
  documentData: jsonb("document_data"), // Additional data from the application
});

export const insertKycVerificationSchema = createInsertSchema(kycVerifications).pick({
  userId: true,
  idType: true,
  idNumber: true,
  documentFront: true,
  documentBack: true,
  selfie: true,
  status: true,
  submittedAt: true,
  notes: true,
  applicationId: true,
  documentData: true,
});

// Types for the schemas
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export type InsertAccount = z.infer<typeof insertAccountSchema>;
export type Account = typeof accounts.$inferSelect;

export type InsertTransaction = z.infer<typeof insertTransactionSchema>;
export type Transaction = typeof transactions.$inferSelect;

export type InsertCard = z.infer<typeof insertCardSchema>;
export type Card = typeof cards.$inferSelect;

export type InsertBill = z.infer<typeof insertBillSchema>;
export type Bill = typeof bills.$inferSelect;

export type InsertSupportTicket = z.infer<typeof insertSupportTicketSchema>;
export type SupportTicket = typeof supportTickets.$inferSelect;

export type InsertKycVerification = z.infer<typeof insertKycVerificationSchema>;
export type KycVerification = typeof kycVerifications.$inferSelect;

// Account application status enum
export const applicationStatusEnum = pgEnum('application_status', [
  'pending_review',   // Initial status, awaiting review
  'in_review',        // Currently being reviewed
  'additional_info',  // Requesting more information
  'approved',         // Application approved, account can be created
  'denied',           // Application rejected
  'cancelled'         // Cancelled by applicant
]);

// Account applications table for tracking bank account applications
export const accountApplications = pgTable("account_applications", {
  id: serial("id").primaryKey(),
  applicationNumber: text("application_number").notNull().unique(),
  status: text("status").notNull().default('pending_review'), // Using text instead of enum for compatibility
  submittedAt: timestamp("submitted_at").defaultNow(),
  lastUpdatedAt: timestamp("last_updated_at").defaultNow(),
  reviewedAt: timestamp("reviewed_at"),
  reviewerId: integer("reviewer_id"), // Admin who reviewed this application
  reviewNotes: text("review_notes"),
  reasonForDenial: text("reason_for_denial"),
  
  // Applicant data - stored as a JSON blob of the form data
  applicationData: jsonb("application_data").notNull(),
  
  // Account notification preference
  notifyViaEmail: boolean("notify_via_email").default(true),
  notifyViaSms: boolean("notify_via_sms").default(false),
  
  // Contact information for status updates
  contactEmail: text("contact_email").notNull(),
  contactPhone: text("contact_phone"),
  
  // Reference to created user if application is approved
  userId: integer("user_id"),
  
  // Tracking data
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  deviceInfo: text("device_info"),
});

export const insertAccountApplicationSchema = createInsertSchema(accountApplications)
  .pick({
    applicationData: true,
    contactEmail: true,
    contactPhone: true,
    notifyViaEmail: true,
    notifyViaSms: true,
    ipAddress: true,
    userAgent: true,
    deviceInfo: true,
  });

export type InsertAccountApplication = z.infer<typeof insertAccountApplicationSchema>;
export type AccountApplication = typeof accountApplications.$inferSelect;

// WebAuthn credentials table for storing biometric authentication data
export const webauthnCredentials = pgTable("webauthn_credentials", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id),
  credentialId: text("credential_id").notNull().unique(),
  publicKey: text("public_key").notNull(),
  counter: integer("counter").default(0).notNull(),
  transports: text("transports"),
  attestationFormat: text("attestation_format"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertWebauthnCredentialSchema = createInsertSchema(webauthnCredentials).pick({
  userId: true,
  credentialId: true,
  publicKey: true,
  counter: true,
  transports: true,
  attestationFormat: true,
});

export type InsertWebauthnCredential = z.infer<typeof insertWebauthnCredentialSchema>;
export type WebauthnCredential = typeof webauthnCredentials.$inferSelect;

// Document access log schema
export const documentAccessLogs = pgTable("document_access_logs", {
  id: serial("id").primaryKey(),
  accessId: text("access_id").notNull().unique(),
  documentPath: text("document_path").notNull(),
  documentType: text("document_type").notNull(),
  entityType: text("entity_type").notNull(), // user, application, account
  entityId: integer("entity_id").notNull(),
  accessedAt: timestamp("accessed_at").defaultNow().notNull(),
  accessedBy: integer("accessed_by").notNull(), // User ID of accessor
  isAdminAccess: boolean("is_admin_access").default(false),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  browserInfo: text("browser_info"),
  accessMethod: text("access_method"), // view, download, print
  accessStatus: text("access_status").notNull(), // success, failure, denied
  accessReason: text("access_reason"), // Optional reason provided for access
  sessionId: text("session_id"), // For tracking session continuity
  encryptionStatus: text("encryption_status").default("encrypted"), // encrypted, decrypted
  additionalInfo: text("additional_info"), // JSON or text for any additional context
  purpose: text("purpose"), // The purpose of the document access (verification, audit, review)
});

export const insertDocumentAccessLogSchema = createInsertSchema(documentAccessLogs).pick({
  accessId: true,
  documentPath: true,
  documentType: true,
  entityType: true,
  entityId: true,
  accessedBy: true,
  isAdminAccess: true,
  ipAddress: true,
  userAgent: true,
  browserInfo: true,
  accessMethod: true,
  accessStatus: true,
  accessReason: true,
  sessionId: true,
  encryptionStatus: true,
  additionalInfo: true,
  purpose: true,
});

export type InsertDocumentAccessLog = z.infer<typeof insertDocumentAccessLogSchema>;
export type DocumentAccessLog = typeof documentAccessLogs.$inferSelect;
