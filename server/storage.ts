import {
  users, accounts, transactions, cards, bills, supportTickets, kycVerifications, webauthnCredentials, accountApplications,
  documentAccessLogs,
  type User, type InsertUser, type Account, type InsertAccount,
  type Transaction, type InsertTransaction, type Card, type InsertCard,
  type Bill, type InsertBill, type SupportTicket, type InsertSupportTicket,
  type KycVerification, type InsertKycVerification, type WebauthnCredential,
  type InsertWebauthnCredential, type AccountApplication, type InsertAccountApplication,
  type DocumentAccessLog, type InsertDocumentAccessLog
} from "@shared/schema";
import * as crypto from 'crypto';

export interface IStorage {
  // User methods
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: number, data: Partial<User>): Promise<User | undefined>;
  getAllUsers(limit?: number, offset?: number): Promise<User[]>;
  blockUser(id: number, reason: string): Promise<User | undefined>;
  unblockUser(id: number): Promise<User | undefined>;
  updateUserStatus(id: number, status: string): Promise<User | undefined>;
  updateUserSecurityLevel(id: number, level: string): Promise<User | undefined>;
  setFraudAlert(id: number, hasAlert: boolean): Promise<User | undefined>;
  resetFailedLoginAttempts(id: number): Promise<User | undefined>;
  incrementFailedLoginAttempts(id: number): Promise<User | undefined>;
  
  // Feature restriction methods
  toggleLoginRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined>;
  toggleTransferRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined>;
  toggleDepositRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined>;
  toggleWithdrawalRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined>;
  toggleCardRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined>;
  removeAllRestrictions(id: number): Promise<User | undefined>;
  
  // Account methods
  getAccount(id: number): Promise<Account | undefined>;
  getAccountsByUserId(userId: number): Promise<Account[]>;
  createAccount(account: InsertAccount): Promise<Account>;
  updateAccount(id: number, data: Partial<Account>): Promise<Account | undefined>;
  
  // Transaction methods
  getTransaction(id: number): Promise<Transaction | undefined>;
  getTransactionsByAccountId(accountId: number, limit?: number, offset?: number): Promise<Transaction[]>;
  getRecentTransactions(userId: number, limit?: number): Promise<Transaction[]>;
  createTransaction(transaction: InsertTransaction): Promise<Transaction>;
  updateTransaction(id: number, data: Partial<Transaction>): Promise<Transaction | undefined>;
  
  // Card methods
  getCard(id: number): Promise<Card | undefined>;
  getCardsByAccountId(accountId: number): Promise<Card[]>;
  createCard(card: InsertCard): Promise<Card>;
  updateCard(id: number, data: Partial<Card>): Promise<Card | undefined>;
  
  // Bill methods
  getBill(id: number): Promise<Bill | undefined>;
  getBillsByUserId(userId: number): Promise<Bill[]>;
  createBill(bill: InsertBill): Promise<Bill>;
  updateBill(id: number, data: Partial<Bill>): Promise<Bill | undefined>;
  
  // Support ticket methods
  getSupportTicket(id: number): Promise<SupportTicket | undefined>;
  getSupportTicketsByUserId(userId: number): Promise<SupportTicket[]>;
  getAllSupportTickets(status?: string): Promise<SupportTicket[]>;
  createSupportTicket(ticket: InsertSupportTicket): Promise<SupportTicket>;
  updateSupportTicket(id: number, data: Partial<SupportTicket>): Promise<SupportTicket | undefined>;
  
  // KYC verification methods
  getKycVerification(id: number): Promise<KycVerification | undefined>;
  getKycVerificationByUserId(userId: number): Promise<KycVerification | undefined>;
  getKycVerificationsByApplicationId(applicationId: number): Promise<KycVerification[]>;
  getAllKycVerifications(status?: string): Promise<KycVerification[]>;
  createKycVerification(verification: InsertKycVerification): Promise<KycVerification>;
  updateKycVerification(id: number, data: Partial<KycVerification>): Promise<KycVerification | undefined>;
  
  // WebAuthn credential methods
  getWebauthnCredential(id: number): Promise<WebauthnCredential | undefined>;
  getWebauthnCredentialByCredentialId(credentialId: string): Promise<WebauthnCredential | undefined>;
  getWebauthnCredentialsByUserId(userId: number): Promise<WebauthnCredential[]>;
  createWebauthnCredential(credential: InsertWebauthnCredential): Promise<WebauthnCredential>;
  updateWebauthnCredential(id: number, data: Partial<WebauthnCredential>): Promise<WebauthnCredential | undefined>;
  deleteWebauthnCredential(id: number): Promise<boolean>;
  
  // Account Application methods
  getAccountApplication(id: number): Promise<AccountApplication | undefined>;
  getAccountApplicationByEmail(email: string): Promise<AccountApplication | undefined>;
  getAccountApplicationByApplicationNumber(applicationNumber: string): Promise<AccountApplication | undefined>;
  getAccountApplicationsByIPAddress(ipAddress: string): Promise<AccountApplication[]>;
  getAllAccountApplications(
    status?: string, 
    limit?: number, 
    offset?: number, 
    sortBy?: string, 
    sortOrder?: string,
    searchTerm?: string
  ): Promise<AccountApplication[]>;
  
  getAccountApplicationsCount(status?: string, searchTerm?: string): Promise<number>;
  createAccountApplication(application: InsertAccountApplication): Promise<AccountApplication>;
  updateAccountApplicationStatus(id: number, status: string, reviewerId?: number, notes?: string): Promise<AccountApplication | undefined>;
  convertApplicationToUser(applicationId: number, username: string, password: string): Promise<User>;
  
  // Document Access Logging methods
  getDocumentAccessLog(id: number): Promise<DocumentAccessLog | undefined>;
  getDocumentAccessLogByAccessId(accessId: string): Promise<DocumentAccessLog | undefined>;
  getDocumentAccessLogsByEntityId(entityType: string, entityId: number, limit?: number): Promise<DocumentAccessLog[]>;
  getDocumentAccessLogsByUserId(userId: number, limit?: number): Promise<DocumentAccessLog[]>;
  getAdminDocumentAccessLogs(limit?: number): Promise<DocumentAccessLog[]>;
  createDocumentAccessLog(log: InsertDocumentAccessLog): Promise<DocumentAccessLog>;
  
  // Document Encryption methods
  encryptDocument(data: Buffer, key?: string): Promise<{ encryptedData: Buffer, encryptionKey: string, iv: string }>;
  decryptDocument(encryptedData: Buffer, encryptionKey: string, iv: string): Promise<Buffer>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private accounts: Map<number, Account>;
  private transactions: Map<number, Transaction>;
  private cards: Map<number, Card>;
  private bills: Map<number, Bill>;
  private supportTickets: Map<number, SupportTicket>;
  private kycVerifications: Map<number, KycVerification>;
  private webauthnCredentials: Map<number, WebauthnCredential>;
  private accountApplications: Map<number, AccountApplication>;
  private documentAccessLogs: Map<number, DocumentAccessLog>;
  
  private userIdCounter: number;
  private accountIdCounter: number;
  private transactionIdCounter: number;
  private cardIdCounter: number;
  private billIdCounter: number;
  private supportTicketIdCounter: number;
  private kycVerificationIdCounter: number;
  private webauthnCredentialIdCounter: number;
  private accountApplicationIdCounter: number;
  private documentAccessLogIdCounter: number;

  constructor() {
    this.users = new Map();
    this.accounts = new Map();
    this.transactions = new Map();
    this.cards = new Map();
    this.bills = new Map();
    this.supportTickets = new Map();
    this.kycVerifications = new Map();
    this.webauthnCredentials = new Map();
    this.accountApplications = new Map();
    this.documentAccessLogs = new Map();
    
    this.userIdCounter = 1;
    this.accountIdCounter = 1;
    this.transactionIdCounter = 1;
    this.cardIdCounter = 1;
    this.billIdCounter = 1;
    this.supportTicketIdCounter = 1;
    this.kycVerificationIdCounter = 1;
    this.webauthnCredentialIdCounter = 1;
    this.accountApplicationIdCounter = 1;
    this.documentAccessLogIdCounter = 1;
    
    // Add some initial data
    this.initializeData();
  }

  private initializeData() {
    // Add a demo admin user
    const adminUser: User = {
      id: this.userIdCounter++,
      username: "admin",
      password: "$2b$10$dQmNkoJWJQw.51aIGJ9uBOzk14yCVxURQJaCjN5E9uVdHqG4Mw8KC", // "password"
      firstName: "Admin",
      lastName: "User",
      email: "admin@securebank.com",
      phoneNumber: "123-456-7890",
      role: "admin",
      twoFactorEnabled: false,
      createdAt: new Date(),
      lastLogin: null,
      isActive: true,
      isVerified: true,
    };
    this.users.set(adminUser.id, adminUser);

    // Add a demo regular user
    const demoUser: User = {
      id: this.userIdCounter++,
      username: "sarahwilliams",
      password: "$2b$10$dQmNkoJWJQw.51aIGJ9uBOzk14yCVxURQJaCjN5E9uVdHqG4Mw8KC", // "password"
      firstName: "Sarah",
      lastName: "Williams",
      email: "sarah@example.com",
      phoneNumber: "234-567-8901",
      role: "user",
      twoFactorEnabled: false,
      createdAt: new Date(),
      lastLogin: null,
      isActive: true,
      isVerified: true,
    };
    this.users.set(demoUser.id, demoUser);

    // Add demo accounts for the user
    const checkingAccount: Account = {
      id: this.accountIdCounter++,
      userId: demoUser.id,
      accountNumber: "4582",
      accountType: "checking",
      accountName: "Premium Checking",
      balance: "12538.42",
      availableBalance: "12538.42",
      routingNumber: "123456789",
      isActive: true,
      openedAt: new Date(),
      lastUpdated: new Date(),
    };
    this.accounts.set(checkingAccount.id, checkingAccount);

    const savingsAccount: Account = {
      id: this.accountIdCounter++,
      userId: demoUser.id,
      accountNumber: "6745",
      accountType: "savings",
      accountName: "Way2Save",
      balance: "24842.30",
      availableBalance: "24842.30",
      routingNumber: "123456789",
      isActive: true,
      openedAt: new Date(),
      lastUpdated: new Date(),
    };
    this.accounts.set(savingsAccount.id, savingsAccount);

    const creditAccount: Account = {
      id: this.accountIdCounter++,
      userId: demoUser.id,
      accountNumber: "3321",
      accountType: "credit_card",
      accountName: "Active Cash Visa",
      balance: "1842.55",
      availableBalance: "3157.45",
      routingNumber: null,
      isActive: true,
      openedAt: new Date(),
      lastUpdated: new Date(),
    };
    this.accounts.set(creditAccount.id, creditAccount);

    // Add demo transactions
    const transactions: Partial<Transaction>[] = [
      {
        accountId: checkingAccount.id,
        transactionType: "withdrawal",
        amount: "84.32",
        description: "Grocery purchase",
        category: "groceries",
        merchantName: "Whole Foods Market",
        status: "completed",
        transactionDate: new Date(2023, 9, 24), // October 24, 2023
      },
      {
        accountId: checkingAccount.id,
        transactionType: "deposit",
        amount: "3245.00",
        description: "Payroll deposit",
        category: "income",
        merchantName: "Direct Deposit",
        status: "completed",
        transactionDate: new Date(2023, 9, 22), // October 22, 2023
      },
      {
        accountId: checkingAccount.id,
        transactionType: "payment",
        amount: "142.15",
        description: "Monthly utility bill",
        category: "utilities",
        merchantName: "City Power & Light",
        status: "completed",
        transactionDate: new Date(2023, 9, 20), // October 20, 2023
      },
      {
        accountId: checkingAccount.id,
        transactionType: "withdrawal",
        amount: "5.75",
        description: "Coffee",
        category: "dining",
        merchantName: "Starbucks",
        status: "completed",
        transactionDate: new Date(2023, 9, 19), // October 19, 2023
      },
      {
        accountId: checkingAccount.id,
        transactionType: "payment",
        amount: "14.99",
        description: "Monthly subscription",
        category: "entertainment",
        merchantName: "Netflix",
        status: "completed",
        transactionDate: new Date(2023, 9, 18), // October 18, 2023
      },
    ];

    transactions.forEach(t => {
      const transaction: Transaction = {
        id: this.transactionIdCounter++,
        referenceNumber: `TX${Math.floor(Math.random() * 1000000)}`,
        toAccountId: null,
        ...t as Omit<Transaction, 'id' | 'referenceNumber' | 'toAccountId'>,
      };
      this.transactions.set(transaction.id, transaction);
    });

    // Add cards for the accounts
    const checkingCard: Card = {
      id: this.cardIdCounter++,
      accountId: checkingAccount.id,
      cardNumber: "****4582",
      cardType: "debit",
      expiryDate: "12/25",
      cvv: "***",
      cardholderName: `${demoUser.firstName} ${demoUser.lastName}`,
      isActive: true,
      isLocked: false,
    };
    this.cards.set(checkingCard.id, checkingCard);

    const creditCard: Card = {
      id: this.cardIdCounter++,
      accountId: creditAccount.id,
      cardNumber: "****3321",
      cardType: "credit",
      expiryDate: "10/27",
      cvv: "***",
      cardholderName: `${demoUser.firstName} ${demoUser.lastName}`,
      isActive: true,
      isLocked: false,
    };
    this.cards.set(creditCard.id, creditCard);
  }

  // User methods
  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.email === email,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.userIdCounter++;
    const now = new Date();
    const user: User = { 
      ...insertUser, 
      id,
      role: "user",
      twoFactorEnabled: false,
      createdAt: now,
      lastLogin: null,
      // Use provided values or defaults for these important fields
      isActive: insertUser.isActive !== undefined ? insertUser.isActive : true,
      isVerified: insertUser.isVerified !== undefined ? insertUser.isVerified : false,
      status: insertUser.status || "active",  // Set default status to active
    };
    this.users.set(id, user);
    
    // For debugging - log when we create a user with verified status
    if (user.isVerified) {
      console.log(`🔑 Created pre-verified user: ${user.username} (ID: ${user.id})`);
    }
    
    return user;
  }

  async updateUser(id: number, data: Partial<User>): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { ...user, ...data };
    this.users.set(id, updatedUser);
    return updatedUser;
  }

  async getAllUsers(limit = 100, offset = 0): Promise<User[]> {
    return Array.from(this.users.values())
      .sort((a, b) => b.id - a.id)
      .slice(offset, offset + limit);
  }
  
  async blockUser(id: number, reason: string): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      isBlocked: true, 
      blockReason: reason,
      status: "suspended",
      isActive: false
    };
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async unblockUser(id: number): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      isBlocked: false, 
      blockReason: null,
      status: "active",
      isActive: true
    };
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async updateUserStatus(id: number, status: string): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { ...user, status };
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async updateUserSecurityLevel(id: number, level: string): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { ...user, securityLevel: level };
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async setFraudAlert(id: number, hasAlert: boolean): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      fraudAlert: hasAlert, 
      status: hasAlert ? "investigating" : user.status 
    };
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async resetFailedLoginAttempts(id: number): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { ...user, failedLoginAttempts: 0 };
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async incrementFailedLoginAttempts(id: number): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const failedAttempts = (user.failedLoginAttempts || 0) + 1;
    const updatedUser = { 
      ...user, 
      failedLoginAttempts: failedAttempts,
      isBlocked: failedAttempts >= 5 ? true : user.isBlocked,
      blockReason: failedAttempts >= 5 ? "Multiple failed login attempts" : user.blockReason,
      status: failedAttempts >= 5 ? "suspended" : user.status
    };
    this.users.set(id, updatedUser);
    return updatedUser;
  }

  // Account methods
  async getAccount(id: number): Promise<Account | undefined> {
    return this.accounts.get(id);
  }

  async getAccountsByUserId(userId: number): Promise<Account[]> {
    return Array.from(this.accounts.values()).filter(
      (account) => account.userId === userId,
    );
  }

  async createAccount(insertAccount: InsertAccount): Promise<Account> {
    const id = this.accountIdCounter++;
    const now = new Date();
    const account: Account = { 
      ...insertAccount, 
      id,
      isActive: true,
      openedAt: now,
      lastUpdated: now,
    };
    this.accounts.set(id, account);
    return account;
  }

  async updateAccount(id: number, data: Partial<Account>): Promise<Account | undefined> {
    const account = await this.getAccount(id);
    if (!account) return undefined;
    
    const updatedAccount = { 
      ...account, 
      ...data,
      lastUpdated: new Date(), 
    };
    this.accounts.set(id, updatedAccount);
    return updatedAccount;
  }

  // Transaction methods
  async getTransaction(id: number): Promise<Transaction | undefined> {
    return this.transactions.get(id);
  }

  async getTransactionsByAccountId(accountId: number, limit = 100, offset = 0): Promise<Transaction[]> {
    return Array.from(this.transactions.values())
      .filter((transaction) => transaction.accountId === accountId)
      .sort((a, b) => new Date(b.transactionDate).getTime() - new Date(a.transactionDate).getTime())
      .slice(offset, offset + limit);
  }

  async getRecentTransactions(userId: number, limit = 5): Promise<Transaction[]> {
    const userAccounts = await this.getAccountsByUserId(userId);
    const accountIds = userAccounts.map(account => account.id);
    
    return Array.from(this.transactions.values())
      .filter((transaction) => accountIds.includes(transaction.accountId))
      .sort((a, b) => new Date(b.transactionDate).getTime() - new Date(a.transactionDate).getTime())
      .slice(0, limit);
  }

  async createTransaction(insertTransaction: InsertTransaction): Promise<Transaction> {
    const id = this.transactionIdCounter++;
    const now = new Date();
    const transaction: Transaction = { 
      ...insertTransaction, 
      id,
      status: insertTransaction.status || "pending", // Default to pending for approval system
      transactionDate: now,
      referenceNumber: `TX${Math.floor(Math.random() * 1000000)}`,
      method: insertTransaction.method || null,
      description: insertTransaction.description || null,
      category: insertTransaction.category || null,
      merchantName: insertTransaction.merchantName || null,
      toAccountId: insertTransaction.toAccountId || null,
      adminNotes: null
    };
    this.transactions.set(id, transaction);
    return transaction;
  }
  
  async updateTransaction(id: number, data: Partial<Transaction>): Promise<Transaction | undefined> {
    const transaction = await this.getTransaction(id);
    if (!transaction) return undefined;
    
    const updatedTransaction = { ...transaction, ...data };
    this.transactions.set(id, updatedTransaction);
    return updatedTransaction;
  }

  // Card methods
  async getCard(id: number): Promise<Card | undefined> {
    return this.cards.get(id);
  }

  async getCardsByAccountId(accountId: number): Promise<Card[]> {
    return Array.from(this.cards.values()).filter(
      (card) => card.accountId === accountId,
    );
  }

  async createCard(insertCard: InsertCard): Promise<Card> {
    const id = this.cardIdCounter++;
    const card: Card = { 
      ...insertCard, 
      id,
      isActive: true,
      isLocked: false,
    };
    this.cards.set(id, card);
    return card;
  }

  async updateCard(id: number, data: Partial<Card>): Promise<Card | undefined> {
    const card = await this.getCard(id);
    if (!card) return undefined;
    
    const updatedCard = { ...card, ...data };
    this.cards.set(id, updatedCard);
    return updatedCard;
  }

  // Bill methods
  async getBill(id: number): Promise<Bill | undefined> {
    return this.bills.get(id);
  }

  async getBillsByUserId(userId: number): Promise<Bill[]> {
    return Array.from(this.bills.values())
      .filter((bill) => bill.userId === userId)
      .sort((a, b) => new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime());
  }

  async createBill(insertBill: InsertBill): Promise<Bill> {
    const id = this.billIdCounter++;
    const bill: Bill = { 
      ...insertBill, 
      id,
      status: "pending",
    };
    this.bills.set(id, bill);
    return bill;
  }

  async updateBill(id: number, data: Partial<Bill>): Promise<Bill | undefined> {
    const bill = await this.getBill(id);
    if (!bill) return undefined;
    
    const updatedBill = { ...bill, ...data };
    this.bills.set(id, updatedBill);
    return updatedBill;
  }

  // Support ticket methods
  async getSupportTicket(id: number): Promise<SupportTicket | undefined> {
    return this.supportTickets.get(id);
  }

  async getSupportTicketsByUserId(userId: number): Promise<SupportTicket[]> {
    return Array.from(this.supportTickets.values())
      .filter((ticket) => ticket.userId === userId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  async getAllSupportTickets(status?: string): Promise<SupportTicket[]> {
    let tickets = Array.from(this.supportTickets.values())
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    
    if (status) {
      tickets = tickets.filter(ticket => ticket.status === status);
    }
    
    return tickets;
  }

  async createSupportTicket(insertTicket: InsertSupportTicket): Promise<SupportTicket> {
    const id = this.supportTicketIdCounter++;
    const now = new Date();
    const ticket: SupportTicket = { 
      ...insertTicket, 
      id,
      status: "open",
      createdAt: now,
      updatedAt: now,
    };
    this.supportTickets.set(id, ticket);
    return ticket;
  }

  async updateSupportTicket(id: number, data: Partial<SupportTicket>): Promise<SupportTicket | undefined> {
    const ticket = await this.getSupportTicket(id);
    if (!ticket) return undefined;
    
    const updatedTicket = { 
      ...ticket, 
      ...data,
      updatedAt: new Date(), 
    };
    this.supportTickets.set(id, updatedTicket);
    return updatedTicket;
  }

  // KYC verification methods
  async getKycVerification(id: number): Promise<KycVerification | undefined> {
    return this.kycVerifications.get(id);
  }

  async getKycVerificationByUserId(userId: number): Promise<KycVerification | undefined> {
    return Array.from(this.kycVerifications.values()).find(
      (verification) => verification.userId === userId,
    );
  }
  
  async getKycVerificationsByApplicationId(applicationId: number): Promise<KycVerification[]> {
    return Array.from(this.kycVerifications.values())
      .filter(verification => verification.applicationId === applicationId)
      .sort((a, b) => {
        if (a.submittedAt && b.submittedAt) {
          return new Date(b.submittedAt).getTime() - new Date(a.submittedAt).getTime();
        }
        return 0;
      });
  }

  async getAllKycVerifications(status?: string): Promise<KycVerification[]> {
    let verifications = Array.from(this.kycVerifications.values())
      .sort((a, b) => new Date(b.submittedAt).getTime() - new Date(a.submittedAt).getTime());
    
    if (status) {
      verifications = verifications.filter(v => v.status === status);
    }
    
    return verifications;
  }

  async createKycVerification(insertVerification: InsertKycVerification): Promise<KycVerification> {
    const id = this.kycVerificationIdCounter++;
    const now = new Date();
    const verification: KycVerification = { 
      ...insertVerification, 
      id,
      status: "pending",
      submittedAt: now,
      reviewedAt: null,
      reviewerId: null,
      notes: null,
    };
    this.kycVerifications.set(id, verification);
    return verification;
  }

  async updateKycVerification(id: number, data: Partial<KycVerification>): Promise<KycVerification | undefined> {
    const verification = await this.getKycVerification(id);
    if (!verification) return undefined;
    
    const updatedVerification = { ...verification, ...data };
    this.kycVerifications.set(id, updatedVerification);
    return updatedVerification;
  }

  // WebAuthn credential methods
  async getWebauthnCredential(id: number): Promise<WebauthnCredential | undefined> {
    return this.webauthnCredentials.get(id);
  }

  async getWebauthnCredentialByCredentialId(credentialId: string): Promise<WebauthnCredential | undefined> {
    return Array.from(this.webauthnCredentials.values()).find(
      (credential) => credential.credentialId === credentialId,
    );
  }

  async getWebauthnCredentialsByUserId(userId: number): Promise<WebauthnCredential[]> {
    return Array.from(this.webauthnCredentials.values()).filter(
      (credential) => credential.userId === userId,
    );
  }

  async createWebauthnCredential(insertCredential: InsertWebauthnCredential): Promise<WebauthnCredential> {
    const id = this.webauthnCredentialIdCounter++;
    const now = new Date();
    const credential: WebauthnCredential = {
      ...insertCredential,
      id,
      createdAt: now,
    };
    this.webauthnCredentials.set(id, credential);
    return credential;
  }

  async updateWebauthnCredential(id: number, data: Partial<WebauthnCredential>): Promise<WebauthnCredential | undefined> {
    const credential = await this.getWebauthnCredential(id);
    if (!credential) return undefined;
    
    const updatedCredential = { ...credential, ...data };
    this.webauthnCredentials.set(id, updatedCredential);
    return updatedCredential;
  }

  async deleteWebauthnCredential(id: number): Promise<boolean> {
    const credential = await this.getWebauthnCredential(id);
    if (!credential) return false;
    
    return this.webauthnCredentials.delete(id);
  }

  // Account Application methods
  async getAccountApplication(id: number): Promise<AccountApplication | undefined> {
    return this.accountApplications.get(id);
  }

  async getAccountApplicationByEmail(email: string): Promise<AccountApplication | undefined> {
    return Array.from(this.accountApplications.values()).find(
      (application) => application.contactEmail === email
    );
  }

  async getAccountApplicationByApplicationNumber(applicationNumber: string): Promise<AccountApplication | undefined> {
    return Array.from(this.accountApplications.values()).find(
      (application) => application.applicationNumber === applicationNumber
    );
  }
  
  async getAccountApplicationsByIPAddress(ipAddress: string): Promise<AccountApplication[]> {
    return Array.from(this.accountApplications.values()).filter(
      (application) => application.ipAddress === ipAddress
    );
  }

  async getAllAccountApplications(
    status?: string,
    limit: number = 50,
    offset: number = 0,
    sortBy: string = 'submittedAt',
    sortOrder: string = 'desc',
    searchTerm?: string
  ): Promise<AccountApplication[]> {
    let applications = Array.from(this.accountApplications.values());
    
    // Apply status filter if provided
    if (status) {
      applications = applications.filter(app => app.status === status);
    }
    
    // Apply search term filter if provided
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      applications = applications.filter(app => 
        app.applicationNumber.toLowerCase().includes(searchLower) ||
        app.contactEmail.toLowerCase().includes(searchLower) ||
        (app.contactPhone && app.contactPhone.toLowerCase().includes(searchLower)) ||
        (app.ipAddress && app.ipAddress.toLowerCase().includes(searchLower)) ||
        // Also search in JSON application data
        JSON.stringify(app.applicationData).toLowerCase().includes(searchLower)
      );
    }
    
    // Sort applications
    applications.sort((a, b) => {
      // Default sort by submittedAt
      if (sortBy === 'submittedAt') {
        const dateA = a.submittedAt ? new Date(a.submittedAt).getTime() : 0;
        const dateB = b.submittedAt ? new Date(b.submittedAt).getTime() : 0;
        return sortOrder === 'desc' ? dateB - dateA : dateA - dateB;
      }
      
      // Sort by application number
      if (sortBy === 'applicationNumber') {
        return sortOrder === 'desc' 
          ? b.applicationNumber.localeCompare(a.applicationNumber)
          : a.applicationNumber.localeCompare(b.applicationNumber);
      }
      
      // Sort by status
      if (sortBy === 'status') {
        return sortOrder === 'desc'
          ? b.status.localeCompare(a.status)
          : a.status.localeCompare(b.status);
      }
      
      // Sort by email
      if (sortBy === 'email') {
        return sortOrder === 'desc'
          ? b.contactEmail.localeCompare(a.contactEmail)
          : a.contactEmail.localeCompare(b.contactEmail);
      }
      
      return 0;
    });
    
    // Apply pagination
    return applications.slice(offset, offset + limit);
  }
  
  async getAccountApplicationsCount(status?: string, searchTerm?: string): Promise<number> {
    let applications = Array.from(this.accountApplications.values());
    
    // Apply status filter if provided
    if (status) {
      applications = applications.filter(app => app.status === status);
    }
    
    // Apply search term filter if provided
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      applications = applications.filter(app => 
        app.applicationNumber.toLowerCase().includes(searchLower) ||
        app.contactEmail.toLowerCase().includes(searchLower) ||
        (app.contactPhone && app.contactPhone.toLowerCase().includes(searchLower)) ||
        (app.ipAddress && app.ipAddress.toLowerCase().includes(searchLower)) ||
        // Also search in JSON application data
        JSON.stringify(app.applicationData).toLowerCase().includes(searchLower)
      );
    }
    
    return applications.length;
  }

  async createAccountApplication(insertApplication: InsertAccountApplication): Promise<AccountApplication> {
    const id = this.accountApplicationIdCounter++;
    const now = new Date();
    
    // Generate a unique application number with "APP" prefix followed by timestamp and random digits
    const timestamp = Date.now().toString().slice(-6);
    const randomDigits = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    const applicationNumber = `APP-${timestamp}-${randomDigits}`;
    
    const application: AccountApplication = {
      ...insertApplication,
      id,
      applicationNumber,
      status: 'pending_review',
      submittedAt: now,
      lastUpdatedAt: now,
      reviewedAt: null,
      reviewerId: null,
      reviewNotes: null,
      reasonForDenial: null,
      userId: null
    };
    
    this.accountApplications.set(id, application);
    return application;
  }

  async updateAccountApplicationStatus(
    id: number, 
    status: string, 
    reviewerId?: number, 
    notes?: string
  ): Promise<AccountApplication | undefined> {
    const application = await this.getAccountApplication(id);
    if (!application) return undefined;
    
    const now = new Date();
    const updatedApplication: AccountApplication = { 
      ...application, 
      status,
      lastUpdatedAt: now,
      reviewedAt: status !== 'pending_review' ? now : application.reviewedAt,
      reviewerId: reviewerId || application.reviewerId,
      reviewNotes: notes || application.reviewNotes,
      reasonForDenial: status === 'denied' ? (notes || 'Application denied') : application.reasonForDenial
    };
    
    this.accountApplications.set(id, updatedApplication);
    return updatedApplication;
  }

  async convertApplicationToUser(applicationId: number, username: string, password: string): Promise<User> {
    const application = await this.getAccountApplication(applicationId);
    if (!application) {
      throw new Error('Application not found');
    }
    
    if (application.status !== 'approved') {
      throw new Error('Cannot create user from non-approved application');
    }
    
    // Ensure username is unique
    const existingUser = await this.getUserByUsername(username);
    if (existingUser) {
      throw new Error('Username already exists');
    }
    
    // Extract user data from application
    const appData = application.applicationData as any;
    
    // Create the user
    const user = await this.createUser({
      username,
      password,
      firstName: appData.firstName,
      lastName: appData.lastName,
      email: application.contactEmail,
      phoneNumber: application.contactPhone || appData.phoneNumber,
    });
    
    // Mark the user as verified and active since they've gone through the application process
    const verifiedUser = await this.updateUser(user.id, {
      isVerified: true,
      status: "active"
    });
    
    // Update application with reference to the created user
    await this.updateAccountApplicationStatus(
      applicationId, 
      'approved', 
      application.reviewerId
    );
    
    const updatedApplication = await this.getAccountApplication(applicationId);
    if (updatedApplication) {
      updatedApplication.userId = user.id;
      this.accountApplications.set(applicationId, updatedApplication);
    }
    
    // Return the verified user instead of the original user
    return verifiedUser || user;
  }
  
  // Feature restriction methods
  async toggleLoginRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      loginRestricted: isRestricted,
      // Set or clear the reason based on restriction status
      loginRestrictionReason: isRestricted ? reason || null : null
    };
    
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async toggleTransferRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      transferRestricted: isRestricted,
      transferRestrictionReason: isRestricted ? reason || null : null
    };
    
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async toggleDepositRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      depositRestricted: isRestricted,
      depositRestrictionReason: isRestricted ? reason || null : null
    };
    
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async toggleWithdrawalRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      withdrawalRestricted: isRestricted,
      withdrawalRestrictionReason: isRestricted ? reason || null : null
    };
    
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async toggleCardRestriction(id: number, isRestricted: boolean, reason?: string): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      cardRestricted: isRestricted,
      cardRestrictionReason: isRestricted ? reason || null : null
    };
    
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  async removeAllRestrictions(id: number): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;
    
    const updatedUser = { 
      ...user, 
      // Remove all restrictions
      loginRestricted: false,
      loginRestrictionReason: null,
      transferRestricted: false,
      transferRestrictionReason: null,
      depositRestricted: false,
      depositRestrictionReason: null,
      withdrawalRestricted: false,
      withdrawalRestrictionReason: null,
      cardRestricted: false,
      cardRestrictionReason: null
    };
    
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  
  // Document Access Logging methods
  async getDocumentAccessLog(id: number): Promise<DocumentAccessLog | undefined> {
    return this.documentAccessLogs.get(id);
  }

  async getDocumentAccessLogByAccessId(accessId: string): Promise<DocumentAccessLog | undefined> {
    return Array.from(this.documentAccessLogs.values()).find(
      (log) => log.accessId === accessId
    );
  }

  async getDocumentAccessLogsByEntityId(entityType: string, entityId: number, limit = 50): Promise<DocumentAccessLog[]> {
    return Array.from(this.documentAccessLogs.values())
      .filter((log) => log.entityType === entityType && log.entityId === entityId)
      .sort((a, b) => new Date(b.accessedAt).getTime() - new Date(a.accessedAt).getTime())
      .slice(0, limit);
  }

  async getDocumentAccessLogsByUserId(userId: number, limit = 50): Promise<DocumentAccessLog[]> {
    return Array.from(this.documentAccessLogs.values())
      .filter((log) => log.accessedBy === userId)
      .sort((a, b) => new Date(b.accessedAt).getTime() - new Date(a.accessedAt).getTime())
      .slice(0, limit);
  }

  async getAdminDocumentAccessLogs(limit = 100): Promise<DocumentAccessLog[]> {
    return Array.from(this.documentAccessLogs.values())
      .filter((log) => log.isAdminAccess)
      .sort((a, b) => new Date(b.accessedAt).getTime() - new Date(a.accessedAt).getTime())
      .slice(0, limit);
  }

  async createDocumentAccessLog(insertLog: InsertDocumentAccessLog): Promise<DocumentAccessLog> {
    const id = this.documentAccessLogIdCounter++;
    const log: DocumentAccessLog = {
      ...insertLog,
      id,
      accessedAt: new Date()
    };
    this.documentAccessLogs.set(id, log);
    return log;
  }

  // Document Encryption methods
  async encryptDocument(data: Buffer, key?: string): Promise<{ encryptedData: Buffer, encryptionKey: string, iv: string }> {
    // Generate a secure random encryption key if not provided
    const encryptionKey = key || crypto.randomBytes(32).toString('hex');
    
    // Generate initialization vector
    const iv = crypto.randomBytes(16);
    
    // Create a cipher using AES-256-GCM (Galois/Counter Mode)
    const cipher = crypto.createCipheriv(
      'aes-256-gcm', 
      Buffer.from(encryptionKey, 'hex'), 
      iv
    );
    
    // Encrypt the data
    const encryptedBuffer = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
    
    // Get the auth tag for integrity verification (GCM mode)
    const authTag = cipher.getAuthTag();
    
    // Combine the encrypted data with the auth tag
    const encryptedData = Buffer.concat([encryptedBuffer, authTag]);
    
    return {
      encryptedData,
      encryptionKey,
      iv: iv.toString('hex')
    };
  }

  async decryptDocument(encryptedData: Buffer, encryptionKey: string, iv: string): Promise<Buffer> {
    try {
      // Convert hex iv back to buffer
      const ivBuffer = Buffer.from(iv, 'hex');
      
      // Extract auth tag from the end of the encrypted data (last 16 bytes for GCM)
      const authTag = encryptedData.slice(encryptedData.length - 16);
      const encryptedBuffer = encryptedData.slice(0, encryptedData.length - 16);
      
      // Create a decipher
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        Buffer.from(encryptionKey, 'hex'),
        ivBuffer
      );
      
      // Set the auth tag for integrity verification
      decipher.setAuthTag(authTag);
      
      // Decrypt the document
      const decryptedBuffer = Buffer.concat([
        decipher.update(encryptedBuffer),
        decipher.final()
      ]);
      
      return decryptedBuffer;
    } catch (error) {
      console.error('Document decryption error:', error);
      throw new Error('Failed to decrypt document - data may be corrupted or key is invalid');
    }
  }
}

export const storage = new MemStorage();
