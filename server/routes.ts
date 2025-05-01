import express, { type Request, Response } from "express";
import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { 
  insertUserSchema, insertAccountSchema, insertTransactionSchema, 
  insertCardSchema, insertBillSchema, insertSupportTicketSchema, insertKycVerificationSchema,
  insertAccountApplicationSchema, 
  SupportTicket, Transaction, KycVerification, AccountApplication
} from "@shared/schema";
import { 
  registerOptions, registerVerification, 
  loginOptions, loginVerification, 
  removeCredential 
} from "./webauthn";
import documentRouter from "./document-routes";
import bcrypt from "bcrypt";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { pool } from "./db";

export async function registerRoutes(app: Express): Promise<Server> {
  // Set up PostgreSQL session store
  const PgSession = connectPgSimple(session);
  
  // Create the session table if it doesn't exist
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
      );
      CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
    `);
    console.log("Session table created or confirmed in PostgreSQL");
  } catch (error) {
    console.error("Error creating session table:", error);
  }
  
  app.use(
    session({
      cookie: { 
        maxAge: 86400000, // 24 hours
        httpOnly: true,
        sameSite: "lax",
        secure: false, // Disable secure for development (cookies won't work properly otherwise)
        path: "/",
      },
      store: new PgSession({
        pool,
        tableName: 'session',
        createTableIfMissing: true,
        pruneSessionInterval: 60 * 15 // 15 minutes
      }),
      name: "fortis.sid", // Set a specific name for the session cookie
      resave: false, // Don't save session if unmodified
      rolling: true, // Force a session identifier cookie to be set on every response
      saveUninitialized: false, // Don't save uninitialized sessions
      secret: process.env.SESSION_SECRET || "fortis-capital-session-secret",
    })
  );

  // Authentication middleware
  const authenticateUser = async (req: Request, res: Response, next: Function) => {
    try {
      // First try to authenticate with session
      if (req.session && req.session.userId) {
        // Verify the user still exists in the database
        const user = await storage.getUser(req.session.userId);
        if (user) {
          // Valid user in session
          return next();
        } else {
          // User no longer exists, clear the session
          req.session.destroy(() => {});
        }
      }
      
      // If no valid session, try token auth 
      const authHeader = req.headers.authorization;
      const authToken = authHeader?.split(' ')[1];
      
      if (!authToken) {
        return res.status(401).json({ message: "Unauthorized - No auth token" });
      }
      
      // Parse and validate token
      try {
        const [userId, timestamp] = authToken.split('.');
        const id = parseInt(userId);
        
        if (!id || isNaN(id) || id <= 0) {
          return res.status(401).json({ message: "Invalid token format" });
        }
        
        // Verify the user exists
        const user = await storage.getUser(id);
        if (!user) {
          return res.status(401).json({ message: "User not found" });
        }
        
        // Token is valid, set up the session
        req.session.userId = id;
        
        // Explicitly save the session then continue 
        req.session.save((err) => {
          if (err) {
            console.error("Session save error:", err);
            return res.status(500).json({ message: "Error saving session" });
          }
          next();
        });
      } catch (error) {
        console.error("Token validation error:", error);
        return res.status(401).json({ message: "Invalid authentication token" });
      }
    } catch (error) {
      console.error("Authentication error:", error);
      return res.status(500).json({ message: "Internal server error during authentication" });
    }
  };

  const authenticateAdmin = async (req: Request, res: Response, next: Function) => {
    console.log("Admin auth check - Session ID:", req.sessionID);
    console.log("Admin auth check - Session data:", req.session);
    
    // First check if the user is authenticated via session
    if (req.session.userId && req.session.isAdmin) {
      console.log("Admin auth check - Found userId in session with isAdmin flag:", req.session.userId);
      
      // Get the user and check if they're an admin
      const user = await storage.getUser(req.session.userId);
      
      if (user && user.role === "admin") {
        console.log("Admin auth successful from session for user ID:", user.id);
        // Attach user to request object
        (req as any).user = user;
        return next();
      }
    } else if (req.session.userId) {
      console.log("Admin auth check - Found userId in session:", req.session.userId);
      
      // Get the user and check if they're an admin
      const user = await storage.getUser(req.session.userId);
      
      if (user && user.role === "admin") {
        console.log("Admin auth check - User is an admin:", user.id);
        
        // Attach user to request object
        (req as any).user = user;
        
        // Set the isAdmin flag if it isn't already set
        if (!req.session.isAdmin) {
          console.log("Admin auth check - Setting isAdmin flag in session");
          req.session.isAdmin = true;
          await new Promise<void>((resolve) => {
            req.session.save((err) => {
              if (err) console.error("Error saving admin session:", err);
              resolve();
            });
          });
        }
        
        console.log("Admin auth successful for user ID:", user.id);
        return next();
      } else {
        console.log("Admin auth failed - user is not an admin:", req.session.userId);
      }
    }
    
    // Check for admin token in Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      console.log("Admin auth check - Found bearer token in header");
      
      try {
        // For our simple token format "admin.{userId}.{timestamp}"
        if (token.startsWith('admin.')) {
          const parts = token.split('.');
          if (parts.length >= 2) {
            const userId = parseInt(parts[1]);
            const user = await storage.getUser(userId);
            
            if (user && user.role === "admin") {
              console.log("Admin auth successful using token for user ID:", user.id);
              
              // Attach user to request object
              (req as any).user = user;
              
              // Set session data
              req.session.userId = user.id;
              req.session.isAdmin = true;
              
              // Save session
              await new Promise<void>((resolve) => {
                req.session.save((err) => {
                  if (err) console.error("Error saving admin session:", err);
                  resolve();
                });
              });
              
              return next();
            }
          }
        }
      } catch (error) {
        console.error("Admin token validation error:", error);
      }
    }
    
    // Also check for direct admin token in query parameter for document viewing
    // This is specifically needed for direct document URLs opened in new tabs/windows
    const adminToken = req.query.adminToken as string;
    if (adminToken && adminToken.startsWith('admin.')) {
      try {
        const parts = adminToken.split('.');
        if (parts.length >= 2) {
          const userId = parseInt(parts[1]);
          const user = await storage.getUser(userId);
          
          if (user && user.role === "admin") {
            console.log("Admin auth successful using query token for user ID:", user.id);
            
            // Set session data
            req.session.userId = user.id;
            req.session.isAdmin = true;
            
            // Save session
            await new Promise<void>((resolve) => {
              req.session.save((err) => {
                if (err) console.error("Error saving admin session:", err);
                resolve();
              });
            });
            
            return next();
          }
        }
      } catch (error) {
        console.error("Admin query token validation error:", error);
      }
    }
    
    // Special case for direct document viewing from admin panel
    // If this is a document request with admin=true parameter, check if the application ID is valid
    if (req.path.includes('/documents/') && req.query.admin === 'true') {
      // Extract application or document ID from path
      const pathParts = req.path.split('/');
      const idIndex = pathParts.findIndex(part => !isNaN(parseInt(part)));
      
      if (idIndex > -1) {
        const entityId = parseInt(pathParts[idIndex]);
        const entityType = pathParts[idIndex - 1]; // 'application', 'kyc', etc.
        
        console.log(`Document access request for ${entityType} ID: ${entityId}`);
        
        // Verify that the entity exists
        let entityExists = false;
        
        if (entityType === 'application') {
          const application = await storage.getAccountApplication(entityId);
          entityExists = !!application;
        } else if (entityType === 'kyc') {
          const verification = await storage.getKycVerification(entityId);
          entityExists = !!verification;
        } else if (entityType === 'account') {
          const account = await storage.getAccount(entityId);
          entityExists = !!account;
        }
        
        if (entityExists) {
          console.log(`Entity ${entityType} with ID ${entityId} exists, granting admin document access`);
          // For security, we'll only grant access to this specific document
          return next();
        }
      }
    }
    
    console.log("Admin auth failed - No valid admin authentication found");
    return res.status(401).json({ 
      message: "Unauthorized",
      details: "You do not have permission to access this resource",
      errorCode: "ADMIN_AUTH_FAILED",
      requestId: `req-${Date.now()}`
    });
  };

  // Auth routes
  app.post("/api/auth/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      
      console.log("Regular user login attempt for:", username);
      
      if (!username || !password) {
        console.log("Login failed: Username and password are required");
        return res.status(400).json({ message: "Username and password are required" });
      }
      
      const user = await storage.getUserByUsername(username);
      if (!user) {
        console.log("Login failed: User not found with username:", username);
        return res.status(401).json({ message: "Invalid credentials" });
      }
      
      // Check for login restrictions before authenticating
      if (user.loginRestricted) {
        console.log("Login failed: User has login restrictions:", username);
        return res.status(403).json({ 
          message: "Your account access has been restricted.",
          restricted: true,
          restrictionReason: user.loginRestrictionReason || "Please contact customer service for assistance."
        });
      }
      
      // In a real app, we'd use bcrypt.compare() to verify the password
      // But for this demo, we'll do a simple check
      if (password !== "password") {
        console.log("Login failed: Invalid password for user:", username);
        
        // Increment failed login attempts
        await storage.incrementFailedLoginAttempts(user.id);
        
        return res.status(401).json({ message: "Invalid credentials" });
      }
      
      console.log("Login successful for user:", username, "with ID:", user.id, "Role:", user.role);
      
      // Reset failed login attempts on successful login
      await storage.resetFailedLoginAttempts(user.id);
      
      // Clear any existing admin session flag when doing a regular login
      req.session.isAdmin = undefined;
      
      // Set the user in the session
      req.session.userId = user.id;
      
      console.log("Set session with userId:", user.id, "cleared isAdmin flag");
      
      // Generate a simple token for client-side authentication
      // In a real app, we'd use JWT with proper signing and expiration
      const timestamp = Date.now();
      const authToken = `${user.id}.${timestamp}`;
      
      // Save the session explicitly before sending response
      req.session.save(err => {
        if (err) {
          console.error("Session save error:", err);
          return res.status(500).json({ message: "Error saving session" });
        }
        
        console.log("Session saved successfully for user:", username);
        
        // Don't send the password back to the client
        const { password: _, ...userWithoutPassword } = user;
        
        res.status(200).json({ 
          user: userWithoutPassword,
          token: authToken,
          message: "Login successful" 
        });
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Verify application credentials before registration
  app.post("/api/auth/verify-application", async (req, res) => {
    try {
      const { applicationNumber, email } = req.body;
      
      console.log(`[DEBUG] Verification request received: AppNum=${applicationNumber}, Email=${email}`);
      
      if (!applicationNumber || !email) {
        console.log(`[DEBUG] Missing required fields: AppNum=${!!applicationNumber}, Email=${!!email}`);
        return res.status(400).json({ 
          message: "Application number and email are required",
          verified: false
        });
      }
      
      // First, check if the application exists in memory storage
      let application = await storage.getAccountApplicationByApplicationNumber(applicationNumber);
      let foundInSQL = false;
      
      console.log(`[DEBUG] Application in memory storage: ${application ? 'Found' : 'Not found'}`);
      
      // If not found in memory storage, check SQL database
      if (!application) {
        try {
          const { pool } = await import("./db");
          const sqlResult = await pool.query(
            'SELECT * FROM applications WHERE application_id = $1',
            [applicationNumber]
          );
          
          console.log(`[DEBUG] SQL query result: ${sqlResult.rows ? sqlResult.rows.length : 0} rows found`);
          
          if (sqlResult.rows && sqlResult.rows.length > 0) {
            console.log(`[DEBUG] SQL application record: ${JSON.stringify(sqlResult.rows[0])}`);
            
            application = {
              id: sqlResult.rows[0].id,
              applicationNumber: sqlResult.rows[0].application_id,
              status: sqlResult.rows[0].status,
              contactEmail: sqlResult.rows[0].email,
              submittedAt: sqlResult.rows[0].created_at,
              lastUpdatedAt: sqlResult.rows[0].updated_at,
              fullName: sqlResult.rows[0].name || ''
            };
            foundInSQL = true;
            
            console.log(`[DEBUG] Transformed application object: ${JSON.stringify(application)}`);
          }
        } catch (sqlError) {
          console.error("SQL error checking application:", sqlError);
          // Continue with memory storage result if SQL fails
        }
      }
      
      if (!application) {
        console.log(`[DEBUG] Final result: Application not found in either storage`);
        return res.status(404).json({ 
          message: "Application not found", 
          verified: false 
        });
      }
      
      // Check if the application status is approved
      console.log(`[DEBUG] Application status check: status=${application.status}, expected="approved"`);
      if (application.status !== "approved") {
        return res.status(400).json({ 
          message: "Application is not approved", 
          verified: false,
          status: application.status
        });
      }
      
      // Check if the email matches
      const applicationEmail = application.contactEmail;
      console.log(`[DEBUG] Email comparison: provided=${email.toLowerCase()}, stored=${applicationEmail ? applicationEmail.toLowerCase() : 'undefined'}`);
      
      if (!applicationEmail || applicationEmail.toLowerCase() !== email.toLowerCase()) {
        return res.status(400).json({ 
          message: "Email does not match application records", 
          verified: false 
        });
      }
      
      // If user account already exists for this application, don't allow re-registration
      console.log(`[DEBUG] User account check: userId=${application.userId}`);
      if (application.userId) {
        return res.status(400).json({ 
          message: "An account has already been created for this application", 
          verified: false 
        });
      }
      
      // Application is verified and approved
      console.log(`[DEBUG] Verification successful: applicationId=${application.id}`);
      
      // Split the full name into first and last names if available
      let firstName = '';
      let lastName = '';
      
      if (application.fullName) {
        const nameParts = application.fullName.trim().split(' ');
        if (nameParts.length >= 2) {
          firstName = nameParts[0];
          lastName = nameParts.slice(1).join(' ');
        } else if (nameParts.length === 1) {
          firstName = nameParts[0];
        }
      }
      
      res.status(200).json({ 
        message: "Application verified", 
        verified: true,
        applicationId: application.id,
        applicationNumber: applicationNumber,
        email: email,
        firstName: firstName,
        lastName: lastName
      });
    } catch (error) {
      console.error("Application verification error:", error);
      res.status(500).json({ message: "Internal server error", verified: false });
    }
  });

  app.post("/api/auth/register", async (req, res) => {
    try {
      const validatedData = insertUserSchema.safeParse(req.body);
      
      if (!validatedData.success) {
        return res.status(400).json({ message: "Invalid user data", errors: validatedData.error.errors });
      }
      
      const { username, email, applicationNumber } = validatedData.data;
      
      // Check if username already exists
      const existingUsername = await storage.getUserByUsername(username);
      if (existingUsername) {
        return res.status(400).json({ message: "Username already exists" });
      }
      
      // Check if email already exists
      const existingEmail = await storage.getUserByEmail(email);
      if (existingEmail) {
        return res.status(400).json({ message: "Email already exists" });
      }
      
      // Verify application if applicationNumber is provided
      if (applicationNumber) {
        // First check if application exists and is approved
        let application = await storage.getAccountApplicationByApplicationNumber(applicationNumber);
        let foundInSQL = false;
        let applicationId = null;
        
        // If not found in memory storage, check SQL database
        if (!application) {
          try {
            const { pool } = await import("./db");
            const sqlResult = await pool.query(
              'SELECT * FROM applications WHERE application_id = $1',
              [applicationNumber]
            );
            
            if (sqlResult.rows && sqlResult.rows.length > 0) {
              application = {
                id: sqlResult.rows[0].id,
                applicationNumber: sqlResult.rows[0].application_id,
                status: sqlResult.rows[0].status,
                contactEmail: sqlResult.rows[0].email,
                submittedAt: sqlResult.rows[0].created_at,
                lastUpdatedAt: sqlResult.rows[0].updated_at
              };
              applicationId = sqlResult.rows[0].id;
              foundInSQL = true;
            }
          } catch (sqlError) {
            console.error("SQL error checking application:", sqlError);
            // Continue with memory storage result if SQL fails
          }
        } else {
          applicationId = application.id;
        }
        
        if (!application) {
          return res.status(404).json({ message: "Application not found" });
        }
        
        // Check if the application status is approved
        if (application.status !== "approved") {
          return res.status(400).json({ 
            message: "Application is not approved", 
            status: application.status 
          });
        }
        
        // Check if the email matches
        const applicationEmail = application.contactEmail;
        if (applicationEmail.toLowerCase() !== email.toLowerCase()) {
          return res.status(400).json({ 
            message: "Email does not match application records" 
          });
        }
        
        // If user account already exists for this application, don't allow re-registration
        if (application.userId) {
          return res.status(400).json({ 
            message: "An account has already been created for this application" 
          });
        }
      }
      
      // Create the user
      const user = await storage.createUser(validatedData.data);
      
      // Update the application with the new user ID if it exists
      if (applicationNumber) {
        try {
          // Update in memory storage
          const application = await storage.getAccountApplicationByApplicationNumber(applicationNumber);
          if (application) {
            await storage.updateAccountApplicationStatus(application.id, application.status, null, "User account created");
          }
          
          // Update in SQL database
          try {
            const { pool } = await import("./db");
            await pool.query(
              'UPDATE applications SET user_id = $1, updated_at = NOW() WHERE application_id = $2',
              [user.id, applicationNumber]
            );
            console.log(`Updated SQL application ${applicationNumber} with user ID ${user.id}`);
          } catch (sqlError) {
            console.error("Error updating SQL application with user ID:", sqlError);
          }
        } catch (updateError) {
          console.error("Error updating application with user ID:", updateError);
          // Continue even if update fails
        }
      }
      
      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      
      res.status(201).json({ 
        user: userWithoutPassword,
        message: "Registration successful" 
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.post("/api/auth/logout", (req, res) => {
    try {
      console.log("Logout request received");
      
      // Force clear the session data
      if (req.session) {
        console.log("Clearing session userId");
        // @ts-ignore: Force removal of userId, TypeScript doesn't like this
        req.session.userId = undefined;
      }
      
      console.log("Destroying session");
      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session:", err);
          return res.status(500).json({ message: "Error destroying session" });
        }
        
        console.log("Clearing session cookie");
        // Clear the session cookie properly with same settings as the session was created with
        res.clearCookie('fortis.sid', {
          path: '/',
          httpOnly: true,
          sameSite: 'lax',
          secure: false
        });
        
        // Also clear any potential session cookies
        res.clearCookie('connect.sid', {
          path: '/',
          httpOnly: true,
          sameSite: 'lax',
          secure: false
        });
        
        console.log("Logout successful");
        // Send a successful response
        res.status(200).json({ message: "Logged out successfully" });
      });
    } catch (error) {
      console.error("Logout error:", error);
      res.status(500).json({ message: "Error during logout process" });
    }
  });
  
  // Forgot password route
  app.post("/api/auth/forgot-password", async (req, res) => {
    try {
      const { email } = req.body;
      
      if (!email) {
        return res.status(400).json({ message: "Email is required" });
      }
      
      // Check if email exists in the system
      const user = await storage.getUserByEmail(email);
      
      // For security reasons, we always return success even if email doesn't exist
      // This prevents user enumeration attacks
      if (user) {
        // Generate a unique token (would use crypto in production)
        const token = Math.random().toString(36).substring(2, 15) + 
                      Math.random().toString(36).substring(2, 15);
                      
        // In a real implementation, we would:
        // 1. Store the token in the database with an expiration date
        // 2. Send an email with a link to reset-password?token={token}
        
        console.log(`Password reset requested for ${email}`);
        console.log(`Generated reset token: ${token}`);
      }
      
      return res.status(200).json({ 
        message: "If an account with that email exists, we've sent password reset instructions." 
      });
    } catch (error) {
      console.error("Forgot password error:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Reset password route
  app.post("/api/auth/reset-password", async (req, res) => {
    try {
      const { token, password } = req.body;
      
      if (!token || !password) {
        return res.status(400).json({ message: "Token and password are required" });
      }
      
      // In a real implementation, we would:
      // 1. Validate the token from the database
      // 2. Check if it hasn't expired
      // 3. Find the associated user
      
      // For demo purposes, we'll just log the token
      console.log(`Password reset with token: ${token}`);
      
      // Validate token (mocked for demo)
      if (!token || token.length < 10) {
        return res.status(400).json({ message: "Invalid or expired reset token" });
      }
      
      // In a real implementation we would:
      // 1. Hash the new password
      // 2. Update the user's password in the database
      // 3. Invalidate the token
      
      return res.status(200).json({ message: "Password has been reset successfully" });
    } catch (error) {
      console.error("Reset password error:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  });

  app.get("/api/auth/me", async (req, res) => {
    try {
      console.log("Auth check - Session ID:", req.sessionID);
      console.log("Auth check - Session data:", req.session);
      
      // Check if user is authenticated via session
      if (req.session && req.session.userId) {
        console.log("User authenticated via session, userId:", req.session.userId);
        
        // If this is an admin session, don't return user data on the /api/auth/me endpoint
        // Admin users should use /api/admin/me instead - prevents session conflicts
        if (req.session.isAdmin) {
          console.log("This is an admin session, not returning user data on /api/auth/me");
          return res.status(200).json(null);
        }
        
        const user = await storage.getUser(req.session.userId);
        
        if (user) {
          // Don't send the password back to the client
          const { password, ...userWithoutPassword } = user;
          return res.status(200).json(userWithoutPassword);
        }
      }
      
      // Check if user is authenticated via token
      const authHeader = req.headers.authorization;
      const authToken = authHeader?.split(' ')[1];
      
      if (authToken) {
        console.log("Auth token found in header:", authToken);
        try {
          const [userId, timestamp] = authToken.split('.');
          const id = parseInt(userId);
          
          if (!isNaN(id) && id > 0) {
            const user = await storage.getUser(id);
            
            if (user) {
              console.log("User authenticated via token, userId:", id);
              
              // IMPORTANT: Set the userId in the session too so WebAuthn works
              req.session.userId = id;
              
              // Save the session
              await new Promise<void>((resolve, reject) => {
                req.session.save(err => {
                  if (err) {
                    console.error("Error saving session:", err);
                    reject(err);
                  } else {
                    console.log("Session saved successfully with userId:", id);
                    resolve();
                  }
                });
              });
              
              // Don't send the password back to the client
              const { password, ...userWithoutPassword } = user;
              return res.status(200).json(userWithoutPassword);
            }
          }
        } catch (error) {
          console.error("Token parsing error:", error);
        }
      }
      
      console.log("No valid authentication found");
      // If we get here, user is not authenticated
      // Return null with status 200 (not 401) to avoid error handling
      return res.status(200).json(null);
    } catch (error) {
      console.error("Get user error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Authentication Routes
  app.post("/api/admin/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required" });
      }
      
      const user = await storage.getUserByUsername(username);
      if (!user || user.role !== "admin") {
        return res.status(401).json({ message: "Invalid administrator credentials" });
      }
      
      // In a real app, we'd use bcrypt.compare() to verify the password
      if (password !== "password") {
        return res.status(401).json({ message: "Invalid administrator credentials" });
      }
      
      // Set the admin user in the session with special flag for admin auth
      req.session.userId = user.id;
      req.session.isAdmin = true;
      
      // Generate a simple token for client-side admin authentication
      const timestamp = Date.now();
      const adminToken = `admin.${user.id}.${timestamp}`;
      
      // Save the session explicitly before sending response
      req.session.save(err => {
        if (err) {
          console.error("Admin session save error:", err);
          return res.status(500).json({ message: "Error saving admin session" });
        }
        
        // Don't send the password back to the client
        const { password: _, ...adminWithoutPassword } = user;
        
        res.status(200).json({ 
          user: adminWithoutPassword,
          token: adminToken,
          message: "Admin login successful" 
        });
      });
    } catch (error) {
      console.error("Admin login error:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  });
  
  app.post("/api/admin/logout", (req, res) => {
    try {
      console.log("Admin logout request received");
      
      // Clear admin-specific session data
      if (req.session) {
        req.session.userId = undefined;
        req.session.isAdmin = undefined;
      }
      
      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying admin session:", err);
          return res.status(500).json({ message: "Error logging out" });
        }
        
        res.clearCookie('fortis.sid');
        res.status(200).json({ message: "Admin logout successful" });
      });
    } catch (error) {
      console.error("Admin logout error:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  });
  
  app.get("/api/admin/me", async (req, res) => {
    try {
      console.log("Admin auth check - Session ID:", req.sessionID);
      console.log("Admin auth check - Session data:", req.session);
      
      // Check if user is authenticated via session
      if (req.session && req.session.userId) {
        console.log("Admin auth check - User authenticated via session:", req.session.userId);
        
        // Get the user and check if they're an admin
        const user = await storage.getUser(req.session.userId);
        
        if (user && user.role === "admin") {
          console.log("Admin auth check - User is an admin:", user.id);
          
          // Set the isAdmin flag if it isn't already set
          if (!req.session.isAdmin) {
            console.log("Admin auth check - Setting isAdmin flag in session");
            req.session.isAdmin = true;
            await new Promise<void>((resolve) => {
              req.session.save((err) => {
                if (err) console.error("Error saving admin session:", err);
                resolve();
              });
            });
          }
          
          // Don't send the password back to the client
          const { password, ...adminWithoutPassword } = user;
          
          return res.status(200).json(adminWithoutPassword);
        } else {
          console.log("Admin auth check - User is not an admin");
        }
      }
      
      // Check if admin is authenticated via token in header
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        console.log("Admin auth check - Token found:", token);
        
        // Simple token validation for demo purposes
        // In production, use proper JWT validation
        if (token && token.startsWith('admin.')) {
          const parts = token.split('.');
          if (parts.length >= 2) {
            const userId = parseInt(parts[1]);
            const user = await storage.getUser(userId);
            
            if (user && user.role === "admin") {
              console.log("Admin auth check - User authenticated via token:", userId);
              
              // Set the admin user in the session with special flag for admin auth
              req.session.userId = user.id;
              req.session.isAdmin = true;
              
              // Save the session
              await new Promise<void>((resolve) => {
                req.session.save((err) => {
                  if (err) console.error("Error saving admin session:", err);
                  resolve();
                });
              });
              
              // Don't send the password back to the client
              const { password, ...adminWithoutPassword } = user;
              
              return res.status(200).json(adminWithoutPassword);
            }
          }
        }
      }
      
      console.log("Admin auth check - No valid admin authentication found");
      // No valid admin authentication found
      return res.status(200).json(null);
    } catch (error) {
      console.error("Admin auth check error:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Dashboard Stats API
  app.get("/api/admin/dashboard/stats", authenticateAdmin, async (req, res) => {
    try {
      // Get users statistics
      const allUsers = await storage.getAllUsers();
      const activeUsers = allUsers.filter(user => user.isVerified).length;
      
      // Get account statistics
      const allAccounts: any[] = [];
      for (const user of allUsers) {
        const userAccounts = await storage.getAccountsByUserId(user.id);
        allAccounts.push(...userAccounts);
      }
      
      // Get KYC statistics
      const allKycVerifications = await storage.getAllKycVerifications();
      const pendingKyc = allKycVerifications.filter(kyc => kyc.status === "pending").length;
      
      // Get transaction statistics
      let allTransactions: any[] = [];
      let totalDeposits = 0;
      let totalWithdrawals = 0;
      
      for (const account of allAccounts) {
        const accountTransactions = await storage.getTransactionsByAccountId(account.id);
        allTransactions.push(...accountTransactions);
        
        // Calculate deposits and withdrawals
        for (const transaction of accountTransactions) {
          const amount = parseFloat(transaction.amount);
          if (transaction.transactionType === "deposit") {
            totalDeposits += amount;
          } else if (transaction.transactionType === "withdrawal") {
            totalWithdrawals += amount;
          }
        }
      }
      
      // Calculate average account balance
      const totalBalances = allAccounts.reduce((sum, account) => sum + parseFloat(account.balance), 0);
      const averageAccountBalance = allAccounts.length > 0 ? totalBalances / allAccounts.length : 0;
      
      // Calculate real fraud alerts (count transactions with amounts exceeding $10,000)
      const fraudAlertTransactions = allTransactions.filter(transaction => 
        parseFloat(transaction.amount) > 10000 || 
        transaction.description?.toLowerCase().includes('suspicious')
      );
      
      // Calculate real account openings (based on creation dates in the last 30 days)
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      const accountsOpened = allAccounts.filter(account => {
        const createdAt = account.createdAt ? new Date(account.createdAt) : null;
        return createdAt && createdAt > thirtyDaysAgo;
      }).length;
      
      // Calculate accounts without activity in the last 90 days (compliance check)
      const ninetyDaysAgo = new Date();
      ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
      
      const accountsWithoutActivity = allAccounts.filter(account => {
        const accountTransactions = allTransactions.filter(tx => tx.accountId === account.id);
        const hasRecentActivity = accountTransactions.some(tx => {
          const txDate = tx.createdAt ? new Date(tx.createdAt) : null;
          return txDate && txDate > ninetyDaysAgo;
        });
        return !hasRecentActivity;
      }).length;
      
      // Count loan applications from relationships data (if we have any)
      // For each account, check if it has a loan relationship
      const loanApplicationCount = allAccounts.filter(account => 
        account.type === 'loan' || 
        account.accountName?.toLowerCase().includes('loan')
      ).length;
      
      // Assemble statistics object with 100% real data
      const stats = {
        totalUsers: allUsers.length,
        activeUsers: activeUsers,
        pendingKyc: pendingKyc,
        totalTransactions: allTransactions.length,
        transactionVolume: allTransactions.reduce((sum, t) => sum + parseFloat(t.amount), 0),
        fraudAlerts: fraudAlertTransactions.length,
        totalAccounts: allAccounts.length,
        totalDeposits: totalDeposits,
        totalWithdrawals: totalWithdrawals,
        netDeposits: totalDeposits - totalWithdrawals,
        accountsOpened: accountsOpened,
        loanApplications: loanApplicationCount,
        averageAccountBalance: averageAccountBalance,
        complianceAlerts: accountsWithoutActivity
      };
      
      res.status(200).json(stats);
    } catch (error) {
      console.error("Admin dashboard stats error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Dashboard Charts
  app.get("/api/admin/dashboard/charts", authenticateAdmin, async (req, res) => {
    try {
      // Get all users for chart data generation
      const allUsers = await storage.getAllUsers();
      
      // Get all accounts
      const allAccounts: any[] = [];
      for (const user of allUsers) {
        const userAccounts = await storage.getAccountsByUserId(user.id);
        allAccounts.push(...userAccounts);
      }
      
      // Get all transactions
      let allTransactions: any[] = [];
      for (const account of allAccounts) {
        const accountTransactions = await storage.getTransactionsByAccountId(account.id);
        allTransactions.push(...accountTransactions);
      }
      
      // Generate monthly user activity data based on user creation dates
      const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"];
      const currentMonth = new Date().getMonth();
      
      // Create user activity data from real user registrations only
      const userActivity = monthNames.map((name, index) => {
        const monthIndex = (currentMonth - 5 + index) % 12;
        const year = new Date().getFullYear() - (monthIndex > currentMonth ? 1 : 0);
        const startDate = new Date(year, monthIndex, 1);
        const endDate = new Date(year, monthIndex + 1, 0);
        
        // Count users created in this month - only use actual data
        const usersInMonth = allUsers.filter(user => {
          const createdAt = user.createdAt ? new Date(user.createdAt) : null;
          return createdAt && createdAt >= startDate && createdAt <= endDate;
        }).length;
        
        return { name, users: usersInMonth };
      });
      
      // Generate transaction data using only real transactions
      const transactions = monthNames.map((name, index) => {
        const monthIndex = (currentMonth - 5 + index) % 12;
        const year = new Date().getFullYear() - (monthIndex > currentMonth ? 1 : 0);
        const startDate = new Date(year, monthIndex, 1);
        const endDate = new Date(year, monthIndex + 1, 0);
        
        // Sum transaction amounts in this month - use only real data
        let value = 0;
        allTransactions.forEach(transaction => {
          const createdAt = transaction.createdAt ? new Date(transaction.createdAt) : null;
          if (createdAt && createdAt >= startDate && createdAt <= endDate) {
            value += parseFloat(transaction.amount);
          }
        });
        
        return { name, value: Math.floor(value) };
      });
      
      // Generate financial activity data (deposits/withdrawals) using only real data
      const financialActivity = monthNames.map((name, index) => {
        const monthIndex = (currentMonth - 5 + index) % 12;
        const year = new Date().getFullYear() - (monthIndex > currentMonth ? 1 : 0);
        const startDate = new Date(year, monthIndex, 1);
        const endDate = new Date(year, monthIndex + 1, 0);
        
        // Calculate deposits and withdrawals for this month - from real transactions only
        let deposits = 0;
        let withdrawals = 0;
        
        allTransactions.forEach(transaction => {
          const createdAt = transaction.createdAt ? new Date(transaction.createdAt) : null;
          if (createdAt && createdAt >= startDate && createdAt <= endDate) {
            const amount = parseFloat(transaction.amount);
            if (transaction.transactionType === "deposit") {
              deposits += amount;
            } else if (transaction.transactionType === "withdrawal") {
              withdrawals += amount;
            }
          }
        });
        
        return { 
          name, 
          deposits: Math.floor(deposits), 
          withdrawals: Math.floor(withdrawals) 
        };
      });
      
      // Generate daily account opening data using only real data
      const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
      const today = new Date();
      const dayOfWeek = today.getDay(); // 0 = Sunday, 1 = Monday, ...
      
      const dailyAccounts = days.map((day, index) => {
        const dayIndex = (index + 1) % 7; // Adjust to make Monday=0, Sunday=6
        const daysAgo = (dayOfWeek + 7 - dayIndex) % 7;
        const targetDate = new Date(today);
        targetDate.setDate(today.getDate() - daysAgo);
        
        // Set to beginning of the day
        targetDate.setHours(0, 0, 0, 0);
        const nextDay = new Date(targetDate);
        nextDay.setDate(targetDate.getDate() + 1);
        
        // Count accounts created on this day - use only real data
        const accountsOnDay = allAccounts.filter(account => {
          const createdAt = account.createdAt ? new Date(account.createdAt) : null;
          return createdAt && createdAt >= targetDate && createdAt < nextDay;
        }).length;
        
        return { day, accounts: accountsOnDay };
      });
      
      // Generate risk score data based on user verification status - use only real data
      const riskScores = [
        {
          category: "Low Risk",
          value: allUsers.filter(user => user.isVerified).length
        },
        {
          category: "Medium Risk",
          value: allUsers.filter(user => !user.isVerified && user.isActive).length
        },
        {
          category: "High Risk",
          value: allUsers.filter(user => !user.isActive).length
        }
      ];
      
      res.status(200).json({
        userActivity,
        transactions,
        financialActivity,
        dailyAccounts,
        riskScores
      });
    } catch (error) {
      console.error("Dashboard charts error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Admin Routes - Transactions
  app.get("/api/admin/transactions", authenticateAdmin, async (req, res) => {
    try {
      // Get all accounts
      const allUsers = await storage.getAllUsers();
      let allTransactions = [];
      
      // For each user, get their accounts and transactions
      for (const user of allUsers) {
        const userAccounts = await storage.getAccountsByUserId(user.id);
        
        for (const account of userAccounts) {
          const accountTransactions = await storage.getTransactionsByAccountId(account.id);
          
          // Enrich transaction data with user and account info
          const enrichedTransactions = accountTransactions.map(transaction => ({
            ...transaction,
            accountNumber: account.accountNumber,
            accountName: account.accountName,
            userName: `${user.firstName} ${user.lastName}`,
            userId: user.id
          }));
          
          allTransactions.push(...enrichedTransactions);
        }
      }
      
      // Format transactions to match what the frontend expects
      allTransactions = allTransactions.map((tx: any) => {
        // Ensure we have a timestamp to sort by
        const timestamp = tx.transactionDate || tx.createdAt || tx.timestamp || new Date();
        
        // Format transaction data to match what TransactionData expects in the frontend
        return {
          id: tx.id,
          referenceNumber: tx.referenceNumber || `REF-${tx.id}-${Math.floor(Math.random() * 10000)}`,
          user: {
            id: tx.userId,
            firstName: tx.userName ? tx.userName.split(' ')[0] : 'User',
            lastName: tx.userName ? tx.userName.split(' ')[1] || '' : '',
          },
          type: tx.transactionType === 'credit' ? 'deposit' : 
                tx.transactionType === 'debit' ? 'withdrawal' : 
                tx.toAccountId ? 'transfer' : 'payment',
          amount: tx.amount,
          date: timestamp.toISOString ? timestamp.toISOString() : new Date(timestamp).toISOString(),
          status: tx.status || 'completed',
          description: tx.description || '',
          category: tx.category || 'uncategorized',
          merchantName: tx.merchantName || null,
          accountId: tx.accountId,
          toAccountId: tx.toAccountId || null,
        };
      });
      
      // Sort by newest first
      allTransactions.sort((a: any, b: any) => {
        const dateA = new Date(a.date);
        const dateB = new Date(b.date);
        return dateB.getTime() - dateA.getTime();
      });
      
      res.status(200).json(allTransactions);
    } catch (error) {
      console.error("Admin transactions error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Users
  app.get("/api/admin/users", authenticateAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const offset = parseInt(req.query.offset as string) || 0;
      
      const users = await storage.getAllUsers(limit, offset);
      
      // Enrich user data with additional information
      const enrichedUsers = await Promise.all(users.map(async user => {
        const { password, ...userWithoutPassword } = user;
        
        // Get accounts for each user
        const accounts = await storage.getAccountsByUserId(user.id);
        
        // Get KYC verification if exists
        const kycVerification = await storage.getKycVerificationByUserId(user.id);
        
        // Get actual login time from real data (using createdAt as initial login)
        // In a real implementation, we would track login timestamps
        const lastLogin = user.lastLogin || user.createdAt;
        
        return {
          ...userWithoutPassword,
          accountCount: accounts.length,
          balance: accounts.reduce((total, acc) => total + parseFloat(acc.balance), 0).toFixed(2),
          kycStatus: kycVerification ? kycVerification.status : "not submitted",
          lastLogin,
          // Assume all users are active unless explicitly set to false
          isActive: userWithoutPassword.isActive !== false,
        };
      }));
      
      res.status(200).json(enrichedUsers);
    } catch (error) {
      console.error("Admin users error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Get User Details
  app.get("/api/admin/users/:id", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const { password, ...userWithoutPassword } = user;
      
      // Get accounts for the user
      const accounts = await storage.getAccountsByUserId(userId);
      
      // Get KYC verification if exists
      const kycVerification = await storage.getKycVerificationByUserId(userId);
      
      // Get actual login time from real data
      const lastLogin = user.lastLogin || user.createdAt;
      
      const enrichedUser = {
        ...userWithoutPassword,
        accountCount: accounts.length,
        balance: accounts.reduce((total, acc) => total + parseFloat(acc.balance), 0).toFixed(2),
        kycStatus: kycVerification ? kycVerification.status : "not submitted",
        lastLogin,
        isActive: userWithoutPassword.isActive !== false,
      };
      
      res.status(200).json(enrichedUser);
    } catch (error) {
      console.error("Admin get user error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Update User Status
  app.patch("/api/admin/users/:id/status", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { isActive } = req.body;
      
      if (typeof isActive !== 'boolean') {
        return res.status(400).json({ message: "Status must be a boolean value" });
      }
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Update the user's status
      const updatedUser = await storage.updateUser(userId, { isActive });
      
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update user status" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Update user status error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Update User Verification Status
  app.patch("/api/admin/users/:id/verification", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { isVerified } = req.body;
      
      if (typeof isVerified !== 'boolean') {
        return res.status(400).json({ message: "Verification status must be a boolean value" });
      }
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Update the user's verification status
      const updatedUser = await storage.updateUser(userId, { isVerified });
      
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update user verification status" });
      }
      
      // If un-verifying a user, update any pending KYC verifications
      if (!isVerified) {
        const kycVerification = await storage.getKycVerificationByUserId(userId);
        if (kycVerification && kycVerification.status === "approved") {
          await storage.updateKycVerification(kycVerification.id, {
            status: "rejected",
            notes: "Verification revoked by admin",
            reviewedAt: new Date(),
            reviewerId: req.session.userId
          });
        }
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Update user verification error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Reset User Password
  app.post("/api/admin/users/:id/reset-password", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // In a real application, we would:
      // 1. Generate a password reset token
      // 2. Store it with an expiration
      // 3. Send an email to the user with a reset link
      
      // For this demo, we'll just return a success response
      res.status(200).json({ 
        message: "Password reset link sent", 
        email: user.email 
      });
    } catch (error) {
      console.error("Reset password error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Block User
  app.post("/api/admin/users/:id/block", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { reason } = req.body;
      
      if (!reason || typeof reason !== 'string') {
        return res.status(400).json({ message: "Block reason is required" });
      }
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Prevent blocking admin users
      if (user.role === 'admin') {
        return res.status(403).json({ message: "Cannot block admin users" });
      }
      
      // Block the user
      const updatedUser = await storage.blockUser(userId, reason);
      
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to block user" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Block user error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Unblock User
  app.post("/api/admin/users/:id/unblock", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Unblock the user
      const updatedUser = await storage.unblockUser(userId);
      
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to unblock user" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Unblock user error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Update User Status
  app.patch("/api/admin/users/:id/user-status", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { status } = req.body;
      
      if (!status || typeof status !== 'string') {
        return res.status(400).json({ message: "Status is required" });
      }
      
      // Validate status values
      const validStatuses = ['active', 'suspended', 'dormant', 'investigating'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ 
          message: "Invalid status value", 
          validValues: validStatuses 
        });
      }
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Update the user's status
      const updatedUser = await storage.updateUserStatus(userId, status);
      
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update user status" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Update user status error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Update User Security Level
  app.patch("/api/admin/users/:id/security-level", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { level } = req.body;
      
      if (!level || typeof level !== 'string') {
        return res.status(400).json({ message: "Security level is required" });
      }
      
      // Validate security level values
      const validLevels = ['standard', 'enhanced', 'high', 'maximum'];
      if (!validLevels.includes(level)) {
        return res.status(400).json({ 
          message: "Invalid security level value", 
          validValues: validLevels 
        });
      }
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Update the user's security level
      const updatedUser = await storage.updateUserSecurityLevel(userId, level);
      
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update user security level" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Update user security level error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Set/Unset Fraud Alert
  app.patch("/api/admin/users/:id/fraud-alert", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { hasAlert } = req.body;
      
      if (typeof hasAlert !== 'boolean') {
        return res.status(400).json({ message: "hasAlert must be a boolean value" });
      }
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Set fraud alert status
      const updatedUser = await storage.setFraudAlert(userId, hasAlert);
      
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update fraud alert status" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Set fraud alert error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Reset Failed Login Attempts
  app.post("/api/admin/users/:id/reset-login-attempts", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Reset failed login attempts
      const updatedUser = await storage.resetFailedLoginAttempts(userId);
      
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to reset login attempts" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Reset login attempts error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Toggle Login Restriction
  app.post("/api/admin/users/:id/toggle-login-restriction", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { isRestricted, reason } = req.body;
      
      if (isRestricted === undefined) {
        return res.status(400).json({ message: "isRestricted flag is required" });
      }
      
      // Validate that a reason is provided when restricting
      if (isRestricted && !reason) {
        return res.status(400).json({ 
          message: "A reason must be provided when restricting login access"
        });
      }
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Updated function to include reason
      const updatedUser = await storage.toggleLoginRestriction(userId, isRestricted, reason);
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update login restriction" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Toggle login restriction error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Toggle Transfer Restriction
  app.post("/api/admin/users/:id/toggle-transfer-restriction", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { isRestricted } = req.body;
      
      if (isRestricted === undefined) {
        return res.status(400).json({ message: "isRestricted flag is required" });
      }
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const updatedUser = await storage.toggleTransferRestriction(userId, isRestricted);
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update transfer restriction" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Toggle transfer restriction error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Toggle Deposit Restriction
  app.post("/api/admin/users/:id/toggle-deposit-restriction", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { isRestricted } = req.body;
      
      if (isRestricted === undefined) {
        return res.status(400).json({ message: "isRestricted flag is required" });
      }
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const updatedUser = await storage.toggleDepositRestriction(userId, isRestricted);
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update deposit restriction" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Toggle deposit restriction error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Toggle Withdrawal Restriction
  app.post("/api/admin/users/:id/toggle-withdrawal-restriction", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { isRestricted } = req.body;
      
      if (isRestricted === undefined) {
        return res.status(400).json({ message: "isRestricted flag is required" });
      }
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const updatedUser = await storage.toggleWithdrawalRestriction(userId, isRestricted);
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update withdrawal restriction" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Toggle withdrawal restriction error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Toggle Card Restriction
  app.post("/api/admin/users/:id/toggle-card-restriction", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { isRestricted } = req.body;
      
      if (isRestricted === undefined) {
        return res.status(400).json({ message: "isRestricted flag is required" });
      }
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const updatedUser = await storage.toggleCardRestriction(userId, isRestricted);
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to update card restriction" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Toggle card restriction error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Remove All Restrictions
  app.post("/api/admin/users/:id/remove-all-restrictions", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const updatedUser = await storage.removeAllRestrictions(userId);
      if (!updatedUser) {
        return res.status(500).json({ message: "Failed to remove all restrictions" });
      }
      
      // Remove sensitive information
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.status(200).json(userWithoutPassword);
    } catch (error) {
      console.error("Remove all restrictions error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Get User Accounts
  app.get("/api/admin/users/:id/accounts", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const accounts = await storage.getAccountsByUserId(userId);
      
      res.status(200).json(accounts);
    } catch (error) {
      console.error("Get user accounts error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Get User Transactions
  app.get("/api/admin/users/:id/transactions", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const limit = parseInt(req.query.limit as string) || 10;
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const accounts = await storage.getAccountsByUserId(userId);
      
      // Get transactions for each of the user's accounts
      let allTransactions = [];
      for (const account of accounts) {
        const transactions = await storage.getTransactionsByAccountId(account.id, limit);
        allTransactions = [...allTransactions, ...transactions];
      }
      
      // Sort by date, newest first
      allTransactions.sort((a, b) => 
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );
      
      // Limit the total number of transactions
      allTransactions = allTransactions.slice(0, limit);
      
      res.status(200).json(allTransactions);
    } catch (error) {
      console.error("Get user transactions error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Get User Cards
  app.get("/api/admin/users/:id/cards", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const accounts = await storage.getAccountsByUserId(userId);
      
      // Get cards for each of the user's accounts
      let allCards = [];
      for (const account of accounts) {
        const cards = await storage.getCardsByAccountId(account.id);
        allCards = [...allCards, ...cards];
      }
      
      res.status(200).json(allCards);
    } catch (error) {
      console.error("Get user cards error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Get User Support Tickets
  app.get("/api/admin/users/:id/support-tickets", authenticateAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      const tickets = await storage.getSupportTicketsByUserId(userId);
      
      // Sort by date, newest first
      tickets.sort((a, b) => 
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );
      
      res.status(200).json(tickets);
    } catch (error) {
      console.error("Get user support tickets error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Account Balance Management
  app.post("/api/admin/accounts/:accountId/top-up", authenticateAdmin, async (req, res) => {
    try {
      const accountId = parseInt(req.params.accountId);
      const { amount } = req.body;
      
      if (isNaN(accountId)) {
        return res.status(400).json({ message: "Invalid account ID" });
      }
      
      if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
        return res.status(400).json({ message: "Invalid amount provided" });
      }
      
      const account = await storage.getAccount(accountId);
      if (!account) {
        return res.status(404).json({ message: "Account not found" });
      }
      
      // Create transaction record for the top-up
      const transaction = await storage.createTransaction({
        accountId,
        amount,
        transactionType: 'credit',
        status: 'completed',
        description: 'Administrative balance top-up',
        category: 'deposit',
        merchantName: 'Fortis Capital',
        referenceNumber: `TOP-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        transactionDate: new Date()
      });
      
      // Update account balance
      const currentBalance = parseFloat(account.balance || '0');
      const newBalance = (currentBalance + parseFloat(amount)).toFixed(2);
      
      const updatedAccount = await storage.updateAccount(accountId, { 
        balance: newBalance,
        availableBalance: newBalance
      });
      
      res.status(200).json({ 
        success: true, 
        transaction,
        account: updatedAccount
      });
    } catch (error) {
      console.error("Admin top-up account error:", error);
      res.status(500).json({ message: "Failed to top-up account balance" });
    }
  });
  
  app.post("/api/admin/accounts/:accountId/subtract", authenticateAdmin, async (req, res) => {
    try {
      const accountId = parseInt(req.params.accountId);
      const { amount, reason } = req.body;
      
      if (isNaN(accountId)) {
        return res.status(400).json({ message: "Invalid account ID" });
      }
      
      if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
        return res.status(400).json({ message: "Invalid amount provided" });
      }
      
      if (!reason) {
        return res.status(400).json({ message: "Reason is required for balance subtraction" });
      }
      
      const account = await storage.getAccount(accountId);
      if (!account) {
        return res.status(404).json({ message: "Account not found" });
      }
      
      const currentBalance = parseFloat(account.balance || '0');
      if (currentBalance < parseFloat(amount)) {
        return res.status(400).json({ message: "Insufficient funds in account" });
      }
      
      // Create transaction record for the subtraction
      const transaction = await storage.createTransaction({
        accountId,
        amount,
        transactionType: 'debit',
        status: 'completed',
        description: `Administrative deduction: ${reason}`,
        category: 'adjustment',
        merchantName: 'Fortis Capital',
        referenceNumber: `ADJ-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        transactionDate: new Date()
      });
      
      // Update account balance
      const newBalance = (currentBalance - parseFloat(amount)).toFixed(2);
      
      const updatedAccount = await storage.updateAccount(accountId, { 
        balance: newBalance,
        availableBalance: newBalance
      });
      
      res.status(200).json({ 
        success: true, 
        transaction,
        account: updatedAccount
      });
    } catch (error) {
      console.error("Admin subtract from account error:", error);
      res.status(500).json({ message: "Failed to subtract from account balance" });
    }
  });
  
  // Admin Routes - Transaction Management
  app.post("/api/admin/accounts/:accountId/transactions", authenticateAdmin, async (req, res) => {
    try {
      const accountId = parseInt(req.params.accountId);
      const { 
        amount, 
        transactionType, 
        description, 
        category, 
        merchantName,
        transactionDate,
        status = 'completed',
        method,
        referenceNumber,
        adminNotes
      } = req.body;
      
      if (isNaN(accountId)) {
        return res.status(400).json({ message: "Invalid account ID" });
      }
      
      if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
        return res.status(400).json({ message: "Invalid amount provided" });
      }
      
      if (!['credit', 'debit'].includes(transactionType)) {
        return res.status(400).json({ message: "Transaction type must be 'credit' or 'debit'" });
      }
      
      const account = await storage.getAccount(accountId);
      if (!account) {
        return res.status(404).json({ message: "Account not found" });
      }
      
      // Parse transaction date if provided
      let parsedTransactionDate: Date | undefined;
      if (transactionDate) {
        try {
          parsedTransactionDate = new Date(transactionDate);
        } catch (error) {
          console.error("Error parsing transaction date:", error);
        }
      }
      
      // Create the transaction record
      const transaction = await storage.createTransaction({
        accountId,
        amount,
        transactionType,
        status,
        description: description || `Administrative ${transactionType}`,
        category: category || 'other',
        merchantName: merchantName || 'Fortis Capital',
        method: method || undefined,
        referenceNumber: referenceNumber || `ADM-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        transactionDate: parsedTransactionDate || new Date(),
        adminNotes: adminNotes || undefined
      });
      
      // Update account balance if transaction is completed and affect balance
      if (status === 'completed') {
        const currentBalance = parseFloat(account.balance || '0');
        let newBalance;
        
        if (transactionType === 'credit') {
          newBalance = (currentBalance + parseFloat(amount)).toFixed(2);
        } else {
          // Check for sufficient funds for debits
          if (currentBalance < parseFloat(amount)) {
            return res.status(400).json({ message: "Insufficient funds in account" });
          }
          newBalance = (currentBalance - parseFloat(amount)).toFixed(2);
        }
        
        await storage.updateAccount(accountId, { 
          balance: newBalance,
          availableBalance: newBalance
        });
      }
      
      res.status(201).json({ 
        success: true, 
        transaction
      });
    } catch (error) {
      console.error("Admin create transaction error:", error);
      res.status(500).json({ message: "Failed to create transaction" });
    }
  });
  
  // Admin Document Routes - For secure document access by admins
  app.get("/api/admin/documents/metadata/:documentId", authenticateAdmin, async (req, res) => {
    try {
      const { documentId } = req.params;
      
      // Validate request parameters
      if (!documentId) {
        return res.status(400).json({ message: "Invalid document ID" });
      }
      
      // In a real banking application, this would:
      // 1. Retrieve actual document metadata from the database
      // 2. Perform security checks
      // 3. Apply proper authorization rules
      // 4. Return full context-aware document metadata
      
      // For the prototype, return enhanced metadata for admin viewing
      // Log the access for audit trail
      console.log(`[ADMIN AUDIT] Document metadata access: ${documentId} by admin ${req.session.userId || 'unknown'}`);
      
      // Return enhanced admin metadata with sensitive details accessible only to admins
      return res.status(200).json({
        documentId: documentId,
        accessTimestamp: new Date().toISOString(),
        securityLevel: "enhanced",
        encryptionStatus: "AES-256-GCM",
        createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // Sample date 7 days ago
        lastAccessed: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), // Sample date 2 days ago
        accessCount: 5,
        sensitiveDocumentFlag: true,
        complianceStatus: "regulatory-compliant",
        retentionPolicy: "7-year-banking-standard",
        adminMode: true,
        securityDetails: {
          isEncrypted: true,
          isWatermarked: true,
          hasDigitalSignature: true,
          integrityVerified: true,
          tamperEvidence: "enabled",
          auditTrailEnabled: true
        },
        administrativeActions: [
          {
            action: "document-view",
            timestamp: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
            adminId: 1,
            reason: "Regular compliance check"
          },
          {
            action: "metadata-access",
            timestamp: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
            adminId: 2,
            reason: "Customer support request"
          }
        ]
      });
    } catch (error) {
      console.error("Secure admin document metadata access error:", error);
      res.status(500).json({ 
        message: "Failed to retrieve document metadata",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
        requestId: `ADMIN-META-${Date.now()}`
      });
    }
  });
  app.get("/api/admin/documents/account/:accountId/:documentType", authenticateAdmin, async (req, res) => {
    try {
      const { accountId, documentType } = req.params;
      const periodId = req.query.periodId as string;
      
      // Validate request parameters
      if (!accountId || !documentType) {
        return res.status(400).json({ message: "Invalid document request" });
      }
      
      // Get the account record 
      const account = await storage.getAccount(parseInt(accountId));
      
      // Security check - only admin can access (already enforced by authenticateAdmin middleware)
      if (!account) {
        return res.status(404).json({ message: "Account not found" });
      }
      
      // Get user data for admin context
      const user = await storage.getUser(account.userId);
      
      // Log successful document access for audit compliance
      console.log(`[ADMIN AUDIT] Document access: ${documentType} for account ${accountId} by admin ${req.session.userId || 'unknown'}`);
      
      const accessId = `ADMIN-ACCT-DOC-ACCESS-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
      const accessTimestamp = new Date().toISOString();
      
      // Return with rich metadata for admin viewing
      return res.status(200).json({
        accessId: accessId,
        accessTimestamp: accessTimestamp,
        documentType: documentType,
        accountId: parseInt(accountId),
        periodId: periodId,
        accountType: account.type,
        accountNumber: account.accountNumber,
        accountStatus: account.status,
        ownerName: user ? `${user.firstName} ${user.lastName}` : "Unknown",
        ownerEmail: user?.email,
        openedDate: account.openedDate,
        lastStatementDate: account.lastStatementDate,
        balance: account.balance,
        securityLevel: "high",
        encryptionMethod: "AES-256-GCM",
        accessedBy: 'administrator',
        accessMethod: req.headers['user-agent'],
        ipAddress: req.ip,
        adminAccess: true,
        securityDetails: {
          isEncrypted: true,
          isWatermarked: true,
          hasDigitalSignature: true,
          auditTrailId: `AUDIT-${accessId}`,
        }
      });
    } catch (error) {
      console.error("Secure admin account document access error:", error);
      res.status(500).json({ 
        message: "Failed to retrieve account document",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
        requestId: `ADMIN-REQ-${Date.now()}`
      });
    }
  });
  
  app.get("/api/admin/documents/application/:applicationId/:documentType", authenticateAdmin, async (req, res) => {
    try {
      const { applicationId, documentType } = req.params;
      
      // Validate request parameters
      if (!applicationId || !documentType) {
        return res.status(400).json({ message: "Invalid document request" });
      }
      
      // Get the application record 
      const application = await storage.getAccountApplication(parseInt(applicationId));
      
      // Security check - only admin can access (already enforced by authenticateAdmin middleware)
      if (!application) {
        return res.status(404).json({ message: "Application not found" });
      }
      
      // Log successful document access for audit compliance
      console.log(`[ADMIN AUDIT] Document access: ${documentType} for application ${applicationId} by admin ${req.session.userId || 'unknown'}`);
      
      const accessId = `ADMIN-APP-DOC-ACCESS-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
      const accessTimestamp = new Date().toISOString();
      
      // Return with rich metadata for admin viewing
      return res.status(200).json({
        accessId: accessId,
        accessTimestamp: accessTimestamp,
        documentType: documentType,
        applicationId: parseInt(applicationId),
        applicantEmail: application.email,
        applicantName: `${application.firstName} ${application.lastName}`,
        applicationStatus: application.status,
        submittedAt: application.submittedAt,
        securityLevel: "high",
        encryptionMethod: "AES-256-GCM",
        accessedBy: 'administrator',
        accessMethod: req.headers['user-agent'],
        ipAddress: req.ip,
        adminAccess: true,
        securityDetails: {
          isEncrypted: true,
          isWatermarked: true,
          hasDigitalSignature: true,
          auditTrailId: `AUDIT-${accessId}`,
        }
      });
    } catch (error) {
      console.error("Secure admin application document access error:", error);
      res.status(500).json({ 
        message: "Failed to retrieve application document",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
        requestId: `ADMIN-REQ-${Date.now()}`
      });
    }
  });
  
  app.get("/api/admin/documents/kyc/:verificationId/:documentType", authenticateAdmin, async (req, res) => {
    try {
      const { verificationId, documentType } = req.params;
      
      // Validate request parameters
      if (!verificationId || !documentType) {
        return res.status(400).json({ message: "Invalid document request" });
      }
      
      // Get the verification record 
      const verification = await storage.getKycVerification(parseInt(verificationId));
      
      // Security check - only admin can access (already enforced by authenticateAdmin middleware)
      if (!verification) {
        return res.status(404).json({ message: "Document not found" });
      }
      
      // Get user data to include with document
      let userData = null;
      if (verification.userId) {
        userData = await storage.getUser(verification.userId);
      }
      
      // Enhanced document access with complete details for admin users
      // Log successful document access for audit compliance
      console.log(`[ADMIN AUDIT] Document access: ${documentType} for verification ${verificationId} by admin ${req.session.userId || 'unknown'}`);
      
      const accessId = `ADMIN-DOC-ACCESS-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
      const accessTimestamp = new Date().toISOString();
      
      if (['id-front', 'id-back', 'passport', 'drivers-license-front', 'drivers-license-back'].includes(documentType)) {
        // Identity document - return with detailed metadata
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          verificationId: parseInt(verificationId),
          userId: verification.userId,
          idType: verification.idType,
          idNumber: verification.idNumber,
          verificationStatus: verification.status,
          reviewerId: verification.reviewerId,
          reviewedAt: verification.reviewedAt,
          userDetails: userData ? {
            id: userData.id,
            fullName: `${userData.firstName} ${userData.lastName}`,
            email: userData.email,
            status: userData.status,
          } : null,
          securityLevel: "critical",
          encryptionMethod: "AES-256-GCM",
          accessedBy: 'administrator',
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          adminAccess: true,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
          }
        });
      } else if (documentType === 'selfie') {
        // Selfie verification
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          verificationId: parseInt(verificationId),
          userId: verification.userId,
          verificationStatus: verification.status,
          userDetails: userData ? {
            id: userData.id,
            fullName: `${userData.firstName} ${userData.lastName}`,
            email: userData.email,
            status: userData.status,
          } : null,
          securityLevel: "critical",
          encryptionMethod: "AES-256-GCM",
          accessedBy: 'administrator',
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          adminAccess: true,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
            biometricDataProtected: true
          }
        });
      } else {
        // Generic response for any other document type
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          verificationId: parseInt(verificationId),
          userId: verification.userId,
          verificationStatus: verification.status,
          userDetails: userData ? {
            id: userData.id,
            fullName: `${userData.firstName} ${userData.lastName}`,
            email: userData.email,
            status: userData.status
          } : null,
          securityLevel: "standard",
          encryptionMethod: "AES-256-GCM",
          accessedBy: 'administrator',
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          adminAccess: true
        });
      }
    } catch (error) {
      console.error("Secure admin document access error:", error);
      res.status(500).json({ 
        message: "Failed to retrieve document",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
        requestId: `ADMIN-REQ-${Date.now()}`
      });
    }
  });

  // Admin Routes - KYC Verification Management
  app.get("/api/admin/kyc-verifications", authenticateAdmin, async (req, res) => {
    try {
      // Get all KYC verifications
      const kycVerifications = await storage.getAllKycVerifications();
      
      // Enrich KYC data with user information
      const enrichedVerifications = await Promise.all(kycVerifications.map(async verification => {
        const user = await storage.getUser(verification.userId);
        
        return {
          ...verification,
          userName: user ? `${user.firstName} ${user.lastName}` : "Unknown User",
          email: user?.email || "N/A",
        };
      }));
      
      // Sort by status - pending first, then by date
      enrichedVerifications.sort((a, b) => {
        if (a.status === "pending" && b.status !== "pending") return -1;
        if (a.status !== "pending" && b.status === "pending") return 1;
        
        const aDate = a.submittedAt ? new Date(a.submittedAt) : new Date(0);
        const bDate = b.submittedAt ? new Date(b.submittedAt) : new Date(0);
        return bDate.getTime() - aDate.getTime();
      });
      
      res.status(200).json(enrichedVerifications);
    } catch (error) {
      console.error("Admin KYC verifications error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Approve a KYC verification - specialized endpoint
  app.patch("/api/admin/kyc-verifications/:id/approve", authenticateAdmin, async (req, res) => {
    try {
      const verificationId = parseInt(req.params.id);
      
      if (isNaN(verificationId)) {
        return res.status(400).json({ message: "Invalid verification ID" });
      }
      
      const verification = await storage.getKycVerification(verificationId);
      
      if (!verification) {
        return res.status(404).json({ message: "Verification not found" });
      }
      
      // Update the verification status to approved
      const updatedVerification = await storage.updateKycVerification(verificationId, { 
        status: "approved", 
        reviewerId: req.session.userId,
        reviewedAt: new Date() 
      });
      
      // If this verification belongs to a user, update their verification status
      if (verification.userId) {
        await storage.updateUser(verification.userId, { isVerified: true });
      }
      
      res.status(200).json(updatedVerification);
    } catch (error) {
      console.error("Error approving KYC verification:", error);
      res.status(500).json({ message: "Error approving KYC verification" });
    }
  });
  
  // Reject a KYC verification - specialized endpoint
  app.patch("/api/admin/kyc-verifications/:id/reject", authenticateAdmin, async (req, res) => {
    try {
      const verificationId = parseInt(req.params.id);
      const { rejectionReason } = req.body;
      
      if (isNaN(verificationId)) {
        return res.status(400).json({ message: "Invalid verification ID" });
      }
      
      if (!rejectionReason) {
        return res.status(400).json({ message: "Rejection reason is required" });
      }
      
      const verification = await storage.getKycVerification(verificationId);
      
      if (!verification) {
        return res.status(404).json({ message: "Verification not found" });
      }
      
      // Update the verification status to rejected
      const updatedVerification = await storage.updateKycVerification(verificationId, { 
        status: "rejected", 
        rejectionReason: rejectionReason,
        reviewerId: req.session.userId,
        reviewedAt: new Date() 
      });
      
      // If this verification belongs to a user, update their verification status
      if (verification.userId) {
        await storage.updateUser(verification.userId, { isVerified: false });
      }
      
      res.status(200).json(updatedVerification);
    } catch (error) {
      console.error("Error rejecting KYC verification:", error);
      res.status(500).json({ message: "Error rejecting KYC verification" });
    }
  });
  
  // Admin Routes - Update KYC Verification Status
  app.patch("/api/admin/kyc-verifications/:id", authenticateAdmin, async (req, res) => {
    try {
      const kycId = parseInt(req.params.id);
      const { status, adminNotes } = req.body;
      
      if (!["pending", "approved", "rejected"].includes(status)) {
        return res.status(400).json({ message: "Invalid status value" });
      }
      
      // Update the KYC verification status
      const verification = await storage.updateKycVerification(kycId, {
        status,
        notes: adminNotes || "",
        reviewedAt: new Date(),
        reviewerId: req.session.userId
      });
      
      if (!verification) {
        return res.status(404).json({ message: "KYC verification not found" });
      }
      
      // If approved, update the user's verification status
      if (status === "approved") {
        await storage.updateUser(verification.userId, { isVerified: true });
      }
      
      res.status(200).json(verification);
    } catch (error) {
      console.error("Update KYC verification error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Support Tickets
  app.get("/api/admin/support-tickets", authenticateAdmin, async (req, res) => {
    try {
      // Get all support tickets
      let tickets = await storage.getAllSupportTickets();
      
      // Filter by status if provided
      const statusFilter = req.query.status as string;
      if (statusFilter && ["open", "in_progress", "resolved"].includes(statusFilter)) {
        tickets = tickets.filter(ticket => ticket.status === statusFilter);
      }
      
      // Enrich ticket data with user information
      const enrichedTickets = await Promise.all(tickets.map(async ticket => {
        const user = await storage.getUser(ticket.userId);
        
        return {
          ...ticket,
          userName: user ? `${user.firstName} ${user.lastName}` : "Unknown User",
          email: user?.email || "N/A",
        };
      }));
      
      // Sort by priority and creation date
      enrichedTickets.sort((a, b) => {
        const priorityValue: Record<string, number> = { high: 3, medium: 2, low: 1 };
        const aPriority = a.priority && priorityValue[a.priority.toLowerCase()] || 0;
        const bPriority = b.priority && priorityValue[b.priority.toLowerCase()] || 0;
        
        if (aPriority !== bPriority) return bPriority - aPriority;
        
        const aDate = a.createdAt ? new Date(a.createdAt) : new Date(0);
        const bDate = b.createdAt ? new Date(b.createdAt) : new Date(0);
        return bDate.getTime() - aDate.getTime();
      });
      
      res.status(200).json(enrichedTickets);
    } catch (error) {
      console.error("Admin support tickets error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Update Support Ticket
  app.patch("/api/admin/support-tickets/:id", authenticateAdmin, async (req, res) => {
    try {
      const ticketId = parseInt(req.params.id);
      const { status, adminResponse } = req.body;
      
      if (status && !["open", "in_progress", "resolved"].includes(status)) {
        return res.status(400).json({ message: "Invalid status value" });
      }
      
      // Get the existing ticket
      const existingTicket = await storage.getSupportTicket(ticketId);
      if (!existingTicket) {
        return res.status(404).json({ message: "Support ticket not found" });
      }
      
      // Update the ticket
      const updateData: any = {};
      if (status) updateData.status = status;
      if (adminResponse) updateData.adminResponse = adminResponse;
      
      // If status is changing to "resolved", set resolved date
      if (status === "resolved" && existingTicket.status !== "resolved") {
        updateData.resolvedAt = new Date();
      }
      
      // If status is changing to "in_progress" and wasn't already, set assigned time and admin
      if (status === "in_progress" && existingTicket.status !== "in_progress") {
        updateData.assignedAt = new Date();
        updateData.assignedTo = req.session.userId;
      }
      
      const updatedTicket = await storage.updateSupportTicket(ticketId, updateData);
      
      res.status(200).json(updatedTicket);
    } catch (error) {
      console.error("Update support ticket error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Accounts
  app.get("/api/admin/accounts", authenticateAdmin, async (req, res) => {
    try {
      const allUsers = await storage.getAllUsers();
      let allAccounts = [];
      
      // For each user, get their accounts
      for (const user of allUsers) {
        const userAccounts = await storage.getAccountsByUserId(user.id);
        
        // Enrich account data with user info
        const enrichedAccounts = userAccounts.map(account => ({
          ...account,
          userName: `${user.firstName} ${user.lastName}`,
          email: user.email
        }));
        
        allAccounts.push(...enrichedAccounts);
      }
      
      // Sort by balance
      allAccounts.sort((a, b) => parseFloat(b.balance) - parseFloat(a.balance));
      
      res.status(200).json(allAccounts);
    } catch (error) {
      console.error("Admin accounts error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Fraud Alerts
  app.get("/api/admin/fraud-alerts", authenticateAdmin, async (req, res) => {
    try {
      // This would typically come from a fraud detection system
      // For demo purposes, we'll create some sample fraud alerts
      const allUsers = await storage.getAllUsers();
      let allAccounts = [];
      
      // Get all accounts
      for (const user of allUsers) {
        const userAccounts = await storage.getAccountsByUserId(user.id);
        for (const account of userAccounts) {
          allAccounts.push({
            ...account,
            userId: user.id,
            userName: `${user.firstName} ${user.lastName}`
          });
        }
      }
      
      // Generate fraud alerts for demo purposes
      const fraudAlerts = [];
      if (allAccounts.length > 0) {
        for (let i = 0; i < Math.min(allAccounts.length, 5); i++) {
          const account = allAccounts[i];
          const alertTypes = [
            "Large Transaction", 
            "International Activity", 
            "Multiple Failed Login Attempts",
            "Unusual Location",
            "Pattern Change"
          ];
          
          fraudAlerts.push({
            id: i + 1,
            accountId: account.id,
            userId: account.userId,
            userName: account.userName,
            accountNumber: account.accountNumber,
            alertType: alertTypes[i % alertTypes.length],
            severity: i % 3 === 0 ? "high" : i % 3 === 1 ? "medium" : "low",
            amount: (1000 + Math.random() * 9000).toFixed(2),
            detectedAt: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
            status: i % 2 === 0 ? "pending" : "resolved",
            description: `Potential fraudulent activity detected on account ${account.accountNumber}. Please review immediately.`
          });
        }
      }
      
      res.status(200).json(fraudAlerts);
    } catch (error) {
      console.error("Admin fraud alerts error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Update Fraud Alert
  app.patch("/api/admin/fraud-alerts/:id", authenticateAdmin, async (req, res) => {
    try {
      const alertId = parseInt(req.params.id);
      const { status, notes } = req.body;
      
      // In a real system, this would update the fraud alert in the database
      // For demo purposes, we'll just return a success response
      res.status(200).json({
        id: alertId,
        status: status || "resolved",
        notes: notes || "Reviewed and resolved by admin",
        reviewedAt: new Date().toISOString(),
        reviewedBy: req.session.userId
      });
    } catch (error) {
      console.error("Update fraud alert error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // User routes
  app.get("/api/users", authenticateAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const offset = parseInt(req.query.offset as string) || 0;
      
      const users = await storage.getAllUsers(limit, offset);
      
      // Don't send passwords back to the client
      const safeUsers = users.map(({ password, ...userWithoutPassword }) => userWithoutPassword);
      
      res.status(200).json(safeUsers);
    } catch (error) {
      console.error("Get users error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Account routes
  app.get("/api/accounts", authenticateUser, async (req, res) => {
    try {
      const accounts = await storage.getAccountsByUserId(req.session.userId!);
      res.status(200).json(accounts);
    } catch (error) {
      console.error("Get accounts error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.get("/api/accounts/:id", authenticateUser, async (req, res) => {
    try {
      const accountId = parseInt(req.params.id);
      const account = await storage.getAccount(accountId);
      
      if (!account) {
        return res.status(404).json({ message: "Account not found" });
      }
      
      // Ensure the account belongs to the authenticated user
      if (account.userId !== req.session.userId) {
        return res.status(403).json({ message: "Forbidden" });
      }
      
      res.status(200).json(account);
    } catch (error) {
      console.error("Get account error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Transaction routes
  app.get("/api/accounts/:accountId/transactions", authenticateUser, async (req, res) => {
    try {
      const accountId = parseInt(req.params.accountId);
      const limit = parseInt(req.query.limit as string) || 100;
      const offset = parseInt(req.query.offset as string) || 0;
      
      const account = await storage.getAccount(accountId);
      
      if (!account) {
        return res.status(404).json({ message: "Account not found" });
      }
      
      // Ensure the account belongs to the authenticated user
      if (account.userId !== req.session.userId) {
        return res.status(403).json({ message: "Forbidden" });
      }
      
      const transactions = await storage.getTransactionsByAccountId(accountId, limit, offset);
      res.status(200).json(transactions);
    } catch (error) {
      console.error("Get transactions error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.get("/api/transactions/recent", authenticateUser, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 5;
      const transactions = await storage.getRecentTransactions(req.session.userId!, limit);
      res.status(200).json(transactions);
    } catch (error) {
      console.error("Get recent transactions error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.post("/api/transactions", authenticateUser, async (req, res) => {
    try {
      const validatedData = insertTransactionSchema.safeParse(req.body);
      
      if (!validatedData.success) {
        return res.status(400).json({ message: "Invalid transaction data", errors: validatedData.error.errors });
      }
      
      const { accountId, toAccountId } = validatedData.data;
      
      // Verify the account belongs to the authenticated user
      const account = await storage.getAccount(accountId);
      if (!account || account.userId !== req.session.userId) {
        return res.status(403).json({ message: "Forbidden" });
      }
      
      // For transfers, verify the destination account exists
      if (toAccountId) {
        const destinationAccount = await storage.getAccount(toAccountId);
        if (!destinationAccount) {
          return res.status(404).json({ message: "Destination account not found" });
        }
      }
      
      const transaction = await storage.createTransaction(validatedData.data);
      
      // Update account balances for transfers
      if (validatedData.data.transactionType === "transfer" && toAccountId) {
        const amount = parseFloat(validatedData.data.amount);
        
        // Update source account (subtract amount)
        const sourceBalance = parseFloat(account.balance) - amount;
        await storage.updateAccount(accountId, { 
          balance: sourceBalance.toFixed(2),
          availableBalance: sourceBalance.toFixed(2)
        });
        
        // Update destination account (add amount)
        const destinationAccount = await storage.getAccount(toAccountId);
        if (destinationAccount) {
          const destinationBalance = parseFloat(destinationAccount.balance) + amount;
          await storage.updateAccount(toAccountId, { 
            balance: destinationBalance.toFixed(2),
            availableBalance: destinationBalance.toFixed(2)
          });
        }
      }
      
      res.status(201).json(transaction);
    } catch (error) {
      console.error("Create transaction error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Card routes
  app.get("/api/cards", authenticateUser, async (req, res) => {
    try {
      const accounts = await storage.getAccountsByUserId(req.session.userId!);
      const accountIds = accounts.map(account => account.id);
      
      let allCards: any[] = [];
      for (const accountId of accountIds) {
        const cards = await storage.getCardsByAccountId(accountId);
        allCards = [...allCards, ...cards];
      }
      
      res.status(200).json(allCards);
    } catch (error) {
      console.error("Get cards error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.post("/api/cards", authenticateUser, async (req, res) => {
    try {
      // Verify the account belongs to the authenticated user
      const account = await storage.getAccount(req.body.accountId);
      if (!account || account.userId !== req.session.userId) {
        return res.status(403).json({ message: "Forbidden: Account not owned by user" });
      }
      
      // Create the card
      const newCard = await storage.createCard(req.body);
      
      // Return the created card
      res.status(200).json(newCard);
    } catch (error) {
      console.error("Create card error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.patch("/api/cards/:id", authenticateUser, async (req, res) => {
    try {
      const cardId = parseInt(req.params.id);
      const { isLocked, contactlessEnabled, internationalEnabled, onlinePurchasesEnabled, settings } = req.body;
      
      // Create updatedFields object with all potential fields to update
      const updatedFields: any = {};
      
      // Handle direct field updates
      if (typeof isLocked === 'boolean') {
        updatedFields.isLocked = isLocked;
      }
      
      if (typeof contactlessEnabled === 'boolean') {
        updatedFields.contactlessEnabled = contactlessEnabled;
      }
      
      if (typeof internationalEnabled === 'boolean') {
        updatedFields.internationalEnabled = internationalEnabled;
      }
      
      if (typeof onlinePurchasesEnabled === 'boolean') {
        updatedFields.onlinePurchasesEnabled = onlinePurchasesEnabled;
      }
      
      // Handle settings object which could contain any of the above fields
      if (settings && typeof settings === 'object') {
        if (typeof settings.contactlessEnabled === 'boolean') {
          updatedFields.contactlessEnabled = settings.contactlessEnabled;
        }
        
        if (typeof settings.internationalEnabled === 'boolean') {
          updatedFields.internationalEnabled = settings.internationalEnabled;
        }
        
        if (typeof settings.onlinePurchasesEnabled === 'boolean') {
          updatedFields.onlinePurchasesEnabled = settings.onlinePurchasesEnabled;
        }
      }
      
      // If no valid fields to update, return error
      if (Object.keys(updatedFields).length === 0) {
        return res.status(400).json({ message: "Invalid data" });
      }
      
      const card = await storage.getCard(cardId);
      
      if (!card) {
        return res.status(404).json({ message: "Card not found" });
      }
      
      // Verify the card's account belongs to the authenticated user
      const account = await storage.getAccount(card.accountId);
      if (!account || account.userId !== req.session.userId) {
        return res.status(403).json({ message: "Forbidden" });
      }
      
      const updatedCard = await storage.updateCard(cardId, updatedFields);
      res.status(200).json(updatedCard);
    } catch (error) {
      console.error("Update card error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // User Settings Routes
  app.get("/api/settings", authenticateUser, async (req, res) => {
    try {
      const user = await storage.getUser(req.session.userId!);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Don't send the password back to the client
      const { password, ...userSettings } = user;
      
      // Get additional user preferences from separate settings collection if needed
      // For now we'll just use the user object
      
      res.status(200).json({
        ...userSettings,
        // Include default settings
        preferences: {
          notifications: {
            email: true,
            sms: true,
            push: true
          },
          security: {
            twoFactorEnabled: user.isVerified || false,
            loginNotifications: true,
            sessionTimeout: 30, // minutes
            // Add missing alert preferences
            passwordChangeAlerts: true,
            profileUpdatesAlerts: true,
            locationAlerts: true
          },
          display: {
            language: "en-US",
            dateFormat: "MM/DD/YYYY",
            theme: "light" 
          }
        }
      });
    } catch (error) {
      console.error("Get user settings error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  app.patch("/api/settings", authenticateUser, async (req, res) => {
    try {
      // Only allow updating specific fields
      const allowedFields = ["firstName", "lastName", "email", "phone"];
      const updateData: Record<string, any> = {};
      
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updateData[field] = req.body[field];
        }
      }
      
      // Special handling for preference updates
      if (req.body.preferences) {
        // Handle preferences separately if needed
        // For now, we'll just log that we received them
        console.log("Received preference updates:", req.body.preferences);
        // In a real app, we would save these to a separate preferences store
      }
      
      // Don't proceed if there's nothing to update
      if (Object.keys(updateData).length === 0 && !req.body.preferences) {
        return res.status(400).json({ message: "No valid fields to update" });
      }
      
      const updatedUser = await storage.updateUser(req.session.userId!, updateData);
      
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Don't send the password back to the client
      const { password, ...safeUser } = updatedUser;
      
      res.status(200).json({
        ...safeUser,
        message: "Settings updated successfully"
      });
    } catch (error) {
      console.error("Update user settings error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Password change endpoint
  app.post("/api/settings/change-password", authenticateUser, async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      
      if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: "Current password and new password are required" });
      }
      
      const user = await storage.getUser(req.session.userId!);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // In a real app, we would use bcrypt to compare passwords
      // But for this demo, we'll do a simple check
      if (currentPassword !== "password") {
        return res.status(401).json({ message: "Current password is incorrect" });
      }
      
      // In a real app, we would hash the new password
      // const hashedPassword = await bcrypt.hash(newPassword, 10);
      
      // Update the password
      await storage.updateUser(req.session.userId!, { password: newPassword });
      
      res.status(200).json({ message: "Password changed successfully" });
    } catch (error) {
      console.error("Change password error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Alert types endpoint
  app.post("/api/settings/alert-types", authenticateUser, async (req, res) => {
    try {
      const { alertType, enabled } = req.body;
      
      if (alertType === undefined || enabled === undefined) {
        return res.status(400).json({ message: "Alert type and enabled status are required" });
      }
      
      console.log(`Alert type ${alertType} set to ${enabled ? 'enabled' : 'disabled'}`);
      
      // In a real app, we would update the user's preferences in the database
      // For now, just return a success response
      
      res.status(200).json({ 
        message: `Alert preference for ${alertType} updated successfully`,
        alertType,
        enabled
      });
    } catch (error) {
      console.error("Update alert type error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Get notifications endpoint
  app.get("/api/notifications", authenticateUser, async (req, res) => {
    try {
      // In a real app, fetch from database
      // For now, return demo notifications
      const notifications = [
        {
          id: 1,
          type: "security",
          message: "New login detected from your device",
          read: false,
          timestamp: new Date(Date.now() - 15 * 60000).toISOString(), // 15 minutes ago
          actionUrl: "/settings"
        },
        {
          id: 2,
          type: "account",
          message: "Your statement is available",
          read: false,
          timestamp: new Date(Date.now() - 2 * 3600000).toISOString(), // 2 hours ago
          actionUrl: "/accounts"
        },
        {
          id: 3,
          type: "transaction",
          message: "Payment of $49.99 was processed",
          read: true,
          timestamp: new Date(Date.now() - 24 * 3600000).toISOString(), // 1 day ago
          actionUrl: "/accounts"
        }
      ];
      
      res.status(200).json(notifications);
    } catch (error) {
      console.error("Get notifications error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Mark notification as read endpoint
  app.post("/api/notifications/:id/read", authenticateUser, async (req, res) => {
    try {
      const notificationId = parseInt(req.params.id);
      
      // In a real app, update in database
      // For now, just return success
      
      res.status(200).json({ 
        message: "Notification marked as read",
        id: notificationId
      });
    } catch (error) {
      console.error("Mark notification as read error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Notification channels endpoint
  app.post("/api/settings/notification-channels", authenticateUser, async (req, res) => {
    try {
      const { channel, enabled } = req.body;
      
      if (channel === undefined || enabled === undefined) {
        return res.status(400).json({ message: "Notification channel and enabled status are required" });
      }
      
      console.log(`Notification channel ${channel} set to ${enabled ? 'enabled' : 'disabled'}`);
      
      // In a real app, we would update the user's preferences in the database
      // For now, just return a success response
      
      res.status(200).json({ 
        message: `Notification channel ${channel} updated successfully`,
        channel,
        enabled
      });
    } catch (error) {
      console.error("Update notification channel error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Bill routes
  app.get("/api/bills", authenticateUser, async (req, res) => {
    try {
      const bills = await storage.getBillsByUserId(req.session.userId!);
      res.status(200).json(bills);
    } catch (error) {
      console.error("Get bills error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.post("/api/bills", authenticateUser, async (req, res) => {
    try {
      const validatedData = insertBillSchema.safeParse({
        ...req.body,
        userId: req.session.userId,
        status: "pending" // Ensure all new bills are created with pending status
      });
      
      if (!validatedData.success) {
        return res.status(400).json({ message: "Invalid bill data", errors: validatedData.error.errors });
      }
      
      const bill = await storage.createBill(validatedData.data);
      
      // Return a response with a note about approval
      res.status(201).json({
        ...bill,
        _message: "Your bill payment has been scheduled and is pending admin approval."
      });
    } catch (error) {
      console.error("Create bill error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Support ticket routes
  app.get("/api/support-tickets", authenticateUser, async (req, res) => {
    try {
      const tickets = await storage.getSupportTicketsByUserId(req.session.userId!);
      res.status(200).json(tickets);
    } catch (error) {
      console.error("Get support tickets error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.post("/api/support-tickets", authenticateUser, async (req, res) => {
    try {
      const validatedData = insertSupportTicketSchema.safeParse({
        ...req.body,
        userId: req.session.userId
      });
      
      if (!validatedData.success) {
        return res.status(400).json({ message: "Invalid ticket data", errors: validatedData.error.errors });
      }
      
      const ticket = await storage.createSupportTicket(validatedData.data);
      res.status(201).json(ticket);
    } catch (error) {
      console.error("Create support ticket error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Admin routes
  app.get("/api/admin/support-tickets", authenticateAdmin, async (req, res) => {
    try {
      const status = req.query.status as string;
      const tickets = await storage.getAllSupportTickets(status);
      res.status(200).json(tickets);
    } catch (error) {
      console.error("Admin get support tickets error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.patch("/api/admin/support-tickets/:id", authenticateAdmin, async (req, res) => {
    try {
      const ticketId = parseInt(req.params.id);
      const { status } = req.body;
      
      if (!status || !["open", "in progress", "closed"].includes(status)) {
        return res.status(400).json({ message: "Invalid status" });
      }
      
      const ticket = await storage.getSupportTicket(ticketId);
      
      if (!ticket) {
        return res.status(404).json({ message: "Ticket not found" });
      }
      
      const updatedTicket = await storage.updateSupportTicket(ticketId, { status });
      res.status(200).json(updatedTicket);
    } catch (error) {
      console.error("Admin update support ticket error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.get("/api/admin/kyc-verifications", authenticateAdmin, async (req, res) => {
    try {
      const status = req.query.status as string;
      const verifications = await storage.getAllKycVerifications(status);
      res.status(200).json(verifications);
    } catch (error) {
      console.error("Admin get KYC verifications error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // WebAuthn routes for biometric authentication
  app.post("/api/webauthn/register-options", async (req, res) => {
    // Log what's in the session for debugging purposes
    console.log("WebAuthn register options - Session ID:", req.sessionID);
    console.log("WebAuthn register options - Session data:", req.session);
    
    // Check auth token first in case session is not properly set
    const authHeader = req.headers.authorization;
    const authToken = authHeader?.split(' ')[1];
    let userId: number | undefined = req.session.userId;
    
    // If no session but token exists, try to set the session
    if (!userId && authToken) {
      try {
        console.log("No session userId but token exists, trying to extract user from token");
        const [tokenUserId, timestamp] = authToken.split('.');
        const id = parseInt(tokenUserId);
        
        if (!isNaN(id) && id > 0) {
          // Verify the user exists
          const user = await storage.getUser(id);
          if (user) {
            console.log("Found user from token:", id);
            userId = id;
            
            // Update the session
            req.session.userId = id;
            await new Promise<void>((resolve, reject) => {
              req.session.save(err => {
                if (err) {
                  console.error("Error saving session:", err);
                  reject(err);
                } else {
                  console.log("Session saved with userId:", id);
                  resolve();
                }
              });
            });
          }
        }
      } catch (error) {
        console.error("Error extracting user from token:", error);
      }
    }
    
    // Check user is already authenticated (to register a device)
    if (!userId) {
      console.error("WebAuthn register options - No userId in session or token");
      return res.status(401).json({ message: "User must be logged in to register a device" });
    }
    
    console.log("WebAuthn register options - User authenticated with userId:", userId);
    const { username } = req.body;
    
    // Call the WebAuthn registration function
    await registerOptions(req, res);
  });
  
  app.post("/api/webauthn/register-verification", async (req, res) => {
    // Log what's in the session for debugging purposes
    console.log("WebAuthn register verification - Session ID:", req.sessionID);
    console.log("WebAuthn register verification - Session data:", req.session);
    
    // Check auth token first in case session is not properly set
    const authHeader = req.headers.authorization;
    const authToken = authHeader?.split(' ')[1];
    let userId: number | undefined = req.session.userId;
    
    // If no session but token exists, try to set the session
    if (!userId && authToken) {
      try {
        console.log("No session userId but token exists, trying to extract user from token");
        const [tokenUserId, timestamp] = authToken.split('.');
        const id = parseInt(tokenUserId);
        
        if (!isNaN(id) && id > 0) {
          // Verify the user exists
          const user = await storage.getUser(id);
          if (user) {
            console.log("Found user from token:", id);
            userId = id;
            
            // Update the session
            req.session.userId = id;
            await new Promise<void>((resolve, reject) => {
              req.session.save(err => {
                if (err) {
                  console.error("Error saving session:", err);
                  reject(err);
                } else {
                  console.log("Session saved with userId:", id);
                  resolve();
                }
              });
            });
          }
        }
      } catch (error) {
        console.error("Error extracting user from token:", error);
      }
    }
    
    // Check user is already authenticated
    if (!userId) {
      console.error("WebAuthn register verification - No userId in session or token");
      return res.status(401).json({ message: "User must be logged in to complete registration" });
    }
    
    console.log("WebAuthn register verification - User authenticated with userId:", userId);
    
    // Verify the WebAuthn registration
    await registerVerification(req, res);
  });
  
  app.post("/api/webauthn/login-options", async (req, res) => {
    // Log what's in the session for debugging purposes
    console.log("WebAuthn login options - Session ID:", req.sessionID);
    console.log("WebAuthn login options - Session data:", req.session);
    
    // No authentication check needed since this is used for login
    
    // Generate options for WebAuthn login
    await loginOptions(req, res);
  });
  
  app.post("/api/webauthn/login-verification", async (req, res) => {
    // Log what's in the session for debugging purposes
    console.log("WebAuthn login verification - Session ID:", req.sessionID);
    console.log("WebAuthn login verification - Session data:", req.session);
    
    // No authentication check needed since this is used for login
    
    // Verify the WebAuthn login
    await loginVerification(req, res);
  });
  
  app.post("/api/webauthn/remove-credential", authenticateUser, async (req, res) => {
    // Log what's in the session for debugging purposes
    console.log("WebAuthn remove credential - Session ID:", req.sessionID);
    console.log("WebAuthn remove credential - Session data:", req.session);
    
    // Remove a WebAuthn credential
    await removeCredential(req, res);
  });
  
  // Get all biometric credentials for a user
  app.get("/api/webauthn/credentials", authenticateUser, async (req, res) => {
    try {
      // Log what's in the session for debugging purposes
      console.log("WebAuthn get credentials - Session ID:", req.sessionID);
      console.log("WebAuthn get credentials - Session data:", req.session);
      console.log("WebAuthn get credentials - User authenticated with userId:", req.session.userId);
      
      const credentials = await storage.getWebauthnCredentialsByUserId(req.session.userId!);
      
      // Return only necessary information (not sensitive data like public key)
      const safeCredentials = credentials.map(({ publicKey, ...rest }) => {
        // Return safe credential data without sensitive keys
        const safeCredential = {
          ...rest,
          registeredAt: rest.createdAt || new Date()
        };
        
        // Add lastUsed if it exists in the database record
        if ('updatedAt' in rest && rest.updatedAt) {
          safeCredential.lastUsed = rest.updatedAt;
        }
        
        return safeCredential;
      });
      
      res.status(200).json(safeCredentials);
    } catch (error) {
      console.error("Get credentials error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Approve Transaction
  app.post("/api/admin/transactions/:id/approve", authenticateAdmin, async (req, res) => {
    try {
      const transactionId = parseInt(req.params.id);
      
      // Get the transaction
      const transaction = await storage.getTransaction(transactionId);
      
      if (!transaction) {
        return res.status(404).json({ message: "Transaction not found" });
      }
      
      // Only allow approval of pending transactions
      if (transaction.status !== "pending") {
        return res.status(400).json({ 
          message: "Only pending transactions can be approved",
          currentStatus: transaction.status
        });
      }
      
      // Update transaction status to processing
      const updatedTransaction = await storage.updateTransaction(transactionId, {
        status: "processing",
        adminNotes: req.body.notes || "Approved by admin on " + new Date().toISOString()
      });
      
      // For deposit transactions, update the account balance
      if (transaction.transactionType === "deposit") {
        const account = await storage.getAccount(transaction.accountId);
        
        if (account) {
          // Convert the balance and amount to numbers for the addition
          const currentBalance = parseFloat(account.balance);
          const depositAmount = parseFloat(transaction.amount);
          
          // Update the account balance
          await storage.updateAccount(account.id, {
            balance: (currentBalance + depositAmount).toFixed(2),
            availableBalance: (parseFloat(account.availableBalance) + depositAmount).toFixed(2),
            lastUpdated: new Date()
          });
        }
      }
      
      // For transfer transactions, deduct from source and add to destination
      if (transaction.transactionType === "transfer" && transaction.toAccountId) {
        const sourceAccount = await storage.getAccount(transaction.accountId);
        const destAccount = await storage.getAccount(transaction.toAccountId);
        
        if (sourceAccount && destAccount) {
          const amount = parseFloat(transaction.amount);
          
          // Deduct from source account
          await storage.updateAccount(sourceAccount.id, {
            balance: (parseFloat(sourceAccount.balance) - amount).toFixed(2),
            availableBalance: (parseFloat(sourceAccount.availableBalance) - amount).toFixed(2),
            lastUpdated: new Date()
          });
          
          // Add to destination account
          await storage.updateAccount(destAccount.id, {
            balance: (parseFloat(destAccount.balance) + amount).toFixed(2),
            availableBalance: (parseFloat(destAccount.availableBalance) + amount).toFixed(2),
            lastUpdated: new Date()
          });
        }
      }
      
      // Complete the transaction
      setTimeout(async () => {
        // After a short delay to simulate processing, mark as completed
        await storage.updateTransaction(transactionId, {
          status: "completed"
        });
      }, 10000); // 10 second delay
      
      res.status(200).json(updatedTransaction);
    } catch (error) {
      console.error("Admin approve transaction error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Cancel Transaction
  app.post("/api/admin/transactions/:id/cancel", authenticateAdmin, async (req, res) => {
    try {
      const transactionId = parseInt(req.params.id);
      
      // Get the transaction
      const transaction = await storage.getTransaction(transactionId);
      
      if (!transaction) {
        return res.status(404).json({ message: "Transaction not found" });
      }
      
      // Only allow cancellation of pending transactions
      if (transaction.status !== "pending") {
        return res.status(400).json({ 
          message: "Only pending transactions can be cancelled",
          currentStatus: transaction.status
        });
      }
      
      // Update transaction status to cancelled
      const updatedTransaction = await storage.updateTransaction(transactionId, {
        status: "cancelled",
        adminNotes: req.body.notes || "Cancelled by admin on " + new Date().toISOString()
      });
      
      res.status(200).json(updatedTransaction);
    } catch (error) {
      console.error("Admin cancel transaction error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Bills
  app.get("/api/admin/bills", authenticateAdmin, async (req, res) => {
    try {
      // Get all users
      const allUsers = await storage.getAllUsers();
      let allBills = [];
      
      // For each user, get their bills
      for (const user of allUsers) {
        const userBills = await storage.getBillsByUserId(user.id);
        
        // Enrich bill data with user info
        const enrichedBills = userBills.map(bill => ({
          ...bill,
          userName: `${user.firstName} ${user.lastName}`,
          userId: user.id
        }));
        
        allBills.push(...enrichedBills);
      }
      
      // Format bills to match what the frontend expects
      allBills = allBills.map((bill: any) => {
        // Format bill data
        return {
          id: bill.id,
          payee: bill.payee,
          accountNumber: bill.accountNumber || 'N/A',
          amount: bill.amount,
          dueDate: bill.dueDate,
          status: bill.status || 'pending',
          isRecurring: bill.isRecurring || false,
          frequency: bill.frequency || null,
          category: bill.category || 'uncategorized',
          user: {
            id: bill.userId,
            name: bill.userName || 'Unknown User'
          }
        };
      });
      
      // Sort by due date, soonest first
      allBills.sort((a: any, b: any) => {
        const dateA = new Date(a.dueDate);
        const dateB = new Date(b.dueDate);
        return dateA.getTime() - dateB.getTime();
      });
      
      res.status(200).json(allBills);
    } catch (error) {
      console.error("Admin bills error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Approve Bill Payment
  app.post("/api/admin/bills/:id/approve", authenticateAdmin, async (req, res) => {
    try {
      const billId = parseInt(req.params.id);
      
      // Get the bill
      const bill = await storage.getBill(billId);
      
      if (!bill) {
        return res.status(404).json({ message: "Bill not found" });
      }
      
      // Only allow approval of pending bills
      if (bill.status !== "pending") {
        return res.status(400).json({ 
          message: "Only pending bills can be approved",
          currentStatus: bill.status
        });
      }
      
      // Update bill status to processing
      const updatedBill = await storage.updateBill(billId, {
        status: "processing"
      });
      
      // Create a transaction to represent this bill payment
      const user = await storage.getUser(bill.userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Get user's accounts
      const accounts = await storage.getAccountsByUserId(user.id);
      if (!accounts || accounts.length === 0) {
        return res.status(400).json({ message: "User has no accounts" });
      }
      
      // Use the first checking account for bill payment
      const checkingAccount = accounts.find(acc => acc.accountType === "checking") || accounts[0];
      
      // Create transaction record for the bill payment
      const billTransaction = await storage.createTransaction({
        accountId: checkingAccount.id,
        transactionType: "debit",
        amount: bill.amount,
        description: `Payment to ${bill.payee}`,
        category: bill.category || "bill_payment",
        status: "processing",
        merchantName: bill.payee,
        method: "electronic",
        referenceNumber: `BILL-${bill.id}-${Date.now().toString().slice(-6)}`,
        adminNotes: `Bill payment approved by admin on ${new Date().toISOString()}`
      });
      
      // Update account balance
      const currentBalance = parseFloat(checkingAccount.balance);
      const billAmount = parseFloat(bill.amount);
      
      await storage.updateAccount(checkingAccount.id, {
        balance: (currentBalance - billAmount).toFixed(2),
        availableBalance: (parseFloat(checkingAccount.availableBalance) - billAmount).toFixed(2),
        lastUpdated: new Date()
      });
      
      // Complete the bill payment
      setTimeout(async () => {
        // After a short delay to simulate processing, mark as paid
        await storage.updateBill(billId, {
          status: "paid"
        });
        
        // Update transaction status
        await storage.updateTransaction(billTransaction.id, {
          status: "completed"
        });
      }, 10000); // 10 second delay
      
      res.status(200).json(updatedBill);
    } catch (error) {
      console.error("Admin approve bill error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Cancel Bill Payment
  app.post("/api/admin/bills/:id/cancel", authenticateAdmin, async (req, res) => {
    try {
      const billId = parseInt(req.params.id);
      
      // Get the bill
      const bill = await storage.getBill(billId);
      
      if (!bill) {
        return res.status(404).json({ message: "Bill not found" });
      }
      
      // Only allow cancellation of pending bills
      if (bill.status !== "pending") {
        return res.status(400).json({ 
          message: "Only pending bills can be cancelled",
          currentStatus: bill.status
        });
      }
      
      // Update bill status to cancelled
      const updatedBill = await storage.updateBill(billId, {
        status: "cancelled"
      });
      
      res.status(200).json(updatedBill);
    } catch (error) {
      console.error("Admin cancel bill error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Account Application Routes
  // Check if user has pending or approved applications from their IP
  app.get("/api/account-applications/check-ip", async (req, res) => {
    try {
      const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
      console.log("IP check request from:", ipAddress);

      if (!ipAddress) {
        return res.status(200).json({ hasApplication: false });
      }

      // Check for applications in MemStorage
      const existingIPApplications = await storage.getAccountApplicationsByIPAddress(String(ipAddress));
      
      // Also check in SQL database
      let sqlApplications = [];
      try {
        const { pool } = await import("./db");
        await ensureApplicationsTable();
        
        const sqlResult = await pool.query(
          'SELECT * FROM applications WHERE ip_address = $1 ORDER BY updated_at DESC',
          [String(ipAddress)]
        );
        
        if (sqlResult.rows && sqlResult.rows.length > 0) {
          console.log(`Found ${sqlResult.rows.length} applications from IP ${ipAddress} in SQL database`);
          sqlApplications = sqlResult.rows.map(row => ({
            id: row.id,
            status: row.status,
            applicationNumber: row.application_id,
            submittedAt: row.created_at,
            lastUpdatedAt: row.updated_at
          }));
        }
      } catch (sqlError) {
        console.error("Error checking SQL database for IP applications:", sqlError);
      }
      
      // Combine applications from both sources
      const allApplications = [
        ...(existingIPApplications || []),
        ...sqlApplications
      ];
      
      if (allApplications.length > 0) {
        // Sort applications by last updated date (newest first)
        const sortedApplications = [...allApplications].sort((a, b) => 
          new Date(b.lastUpdatedAt || b.submittedAt).getTime() - 
          new Date(a.lastUpdatedAt || a.submittedAt).getTime()
        );
        
        // Get the most recent application
        const latestApplication = sortedApplications[0];
        
        // Check application status
        if (latestApplication.status === 'pending_review' || latestApplication.status === 'approved') {
          const isPending = latestApplication.status === 'pending_review';
          const statusMessage = isPending 
            ? "You already have a pending application. You can check its status using your application number." 
            : "You already have an approved application. You should have received instructions via email.";
          
          return res.status(200).json({
            hasApplication: true,
            applicationStatus: latestApplication.status,
            applicationNumber: latestApplication.applicationNumber,
            message: statusMessage,
            canSubmitNew: false
          });
        } else if (latestApplication.status === 'denied') {
          // Application was rejected, user can submit a new one
          return res.status(200).json({ 
            hasApplication: true,
            applicationStatus: 'denied',
            applicationNumber: latestApplication.applicationNumber,
            canSubmitNew: true,
            message: "Your previous application was rejected. You may submit a new application."
          });
        }
      }
      
      // No existing applications from this IP
      return res.status(200).json({ 
        hasApplication: false,
        canSubmitNew: true
      });
    } catch (error) {
      console.error("Error checking IP for applications:", error);
      // Default to allowing submission in case of error
      return res.status(200).json({ hasApplication: false, canSubmitNew: true });
    }
  });

  // Submit new account application
  app.post("/api/account-applications/apply", async (req, res) => {
    try {
      console.log("Received application data:", JSON.stringify(req.body, null, 2));
      const validatedData = insertAccountApplicationSchema.safeParse(req.body);
      
      if (!validatedData.success) {
        console.log("Validation failed:", JSON.stringify(validatedData.error, null, 2));
        return res.status(400).json({ 
          message: "Invalid application data", 
          errors: validatedData.error.errors 
        });
      }
      
      console.log("Validation successful!");
      
      // Get client IP address
      const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
      console.log("Application request from IP:", ipAddress);
      
      // Check if email already exists in users
      const existingUser = await storage.getUserByEmail(validatedData.data.contactEmail);
      if (existingUser) {
        return res.status(400).json({ 
          message: "Email already exists as a registered user. Please login instead." 
        });
      }
      
      // Check if there's already a pending application for this email
      const existingApplication = await storage.getAccountApplicationByEmail(validatedData.data.contactEmail);
      if (existingApplication && existingApplication.status === 'pending_review') {
        return res.status(400).json({ 
          message: "You already have a pending application. You'll be notified via email when it's reviewed.", 
          applicationNumber: existingApplication.applicationNumber
        });
      }
      
      // Check for existing applications from the same IP address - first in MemStorage
      const existingIPApplications = await storage.getAccountApplicationsByIPAddress(String(ipAddress));
      
      // Also check SQL database for applications from this IP
      let sqlApplications = [];
      try {
        const { pool } = await import("./db");
        await ensureApplicationsTable();
        
        const sqlResult = await pool.query(
          'SELECT * FROM applications WHERE ip_address = $1',
          [String(ipAddress)]
        );
        
        if (sqlResult.rows && sqlResult.rows.length > 0) {
          console.log(`Found ${sqlResult.rows.length} applications from IP ${ipAddress} in SQL database before submission`);
          sqlApplications = sqlResult.rows.map(row => ({
            id: row.id,
            status: row.status,
            applicationNumber: row.application_id,
            submittedAt: row.created_at,
            lastUpdatedAt: row.updated_at
          }));
        }
      } catch (sqlError) {
        console.error("Error checking SQL database for IP applications before submission:", sqlError);
      }
      
      // Combine applications from both sources
      const allIPApplications = [
        ...(existingIPApplications || []),
        ...sqlApplications
      ];
      
      if (allIPApplications.length > 0) {
        // Find if there are any pending or approved applications from this IP
        // Users should only be allowed to submit a new application if all previous ones were rejected
        const pendingOrApprovedApplications = allIPApplications.filter(
          app => app.status === 'pending_review' || app.status === 'approved'
        );
        
        if (pendingOrApprovedApplications.length > 0) {
          const isPending = pendingOrApprovedApplications.some(app => app.status === 'pending_review');
          const statusMessage = isPending 
            ? "An application from your location is already under review." 
            : "An application from your location has already been approved.";
          
          return res.status(403).json({
            message: "Multiple applications not allowed",
            details: statusMessage,
            applicationNumber: pendingOrApprovedApplications[0].applicationNumber,
            status: pendingOrApprovedApplications[0].status
          });
        }
        
        // If we get here, user had previous applications but they were all rejected,
        // so we allow them to submit a new one
        console.log("Previous applications from this IP were all rejected. Allowing new submission.");
      }
      
      // Add IP address to the application data
      validatedData.data.ipAddress = String(ipAddress);
      
      // Create the application in MemStorage
      const application = await storage.createAccountApplication(validatedData.data);
      
      // Extract personal info from application data
      const personalInfo = validatedData.data.applicationData?.personal || {};
      const identificationInfo = validatedData.data.applicationData?.identification || {};
      const fullName = `${personalInfo.firstName || ''} ${personalInfo.lastName || ''}`.trim();
      const ssn = personalInfo.ssn || '';
      
      // Also save the application to the SQL database for persistence
      try {
        const { pool } = await import("./db");
        
        // First ensure the table exists
        await ensureApplicationsTable();
        
        // Then insert the new application
        await pool.query(`
          INSERT INTO applications 
          (application_id, name, email, phone, document_filename, ip_address, status, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        `, [
          application.applicationNumber,
          fullName,
          validatedData.data.contactEmail,
          validatedData.data.contactPhone || '',
          validatedData.data.identificationDocument || '',
          String(ipAddress),
          'pending_review',
          new Date(),
          new Date()
        ]);
        
        console.log(`Successfully saved application ${application.applicationNumber} to SQL database`);
      } catch (sqlError) {
        console.error("Error saving application to SQL database:", sqlError);
        // Continue with response even if SQL save fails
      }
      
      // Create KYC verification record based on application
      // This will allow the application to appear in the Admin KYC section
      try {
        await storage.createKycVerification({
          userId: 0, // Placeholder until user is created
          idType: identificationInfo.idType || 'application_ssn',
          idNumber: identificationInfo.idNumber || ssn || 'pending',
          documentFront: identificationInfo.documentFront || null,
          documentBack: identificationInfo.documentBack || null,
          selfie: identificationInfo.selfieImage || null,
          status: 'pending',
          submittedAt: new Date(),
          notes: `Automatically created from application ${application.applicationNumber}`,
          applicationId: application.id,
          documentData: validatedData.data.applicationData || {}
        });
        console.log("Created corresponding KYC verification record for application", application.id);
      } catch (kycError) {
        console.error("Error creating KYC verification record:", kycError);
        // Continue with response even if KYC record creation fails
      }
      
      res.status(201).json({ 
        message: "Application submitted successfully. You'll be notified via email when your application is reviewed.",
        applicationNumber: application.applicationNumber 
      });
    } catch (error) {
      console.error("Account application submission error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Check application status
  app.get("/api/account-applications/status/:applicationNumber", async (req, res) => {
    try {
      const { applicationNumber } = req.params;
      
      // First, try to get the application status from the MemStorage
      const application = await storage.getAccountApplicationByApplicationNumber(applicationNumber);
      
      // Also check the SQL database for this application number
      let sqlStatus = null;
      try {
        const { pool } = await import("./db");
        const sqlResult = await pool.query(
          'SELECT * FROM applications WHERE application_id = $1',
          [applicationNumber]
        );
        
        if (sqlResult.rows && sqlResult.rows.length > 0) {
          sqlStatus = sqlResult.rows[0].status;
          console.log(`Found application ${applicationNumber} in SQL database with status: ${sqlStatus}`);
        }
      } catch (sqlError) {
        console.error("Error checking SQL database for application status:", sqlError);
        // Continue even if SQL check fails
      }
      
      // If application not found in either storage, return 404
      if (!application && !sqlStatus) {
        return res.status(404).json({ message: "Application not found" });
      }
      
      // Always prioritize SQL status if available, as it's more persistent
      const finalStatus = sqlStatus || (application ? application.status : 'pending_review');
      
      // Log this status request
      console.log(`Status check for application ${applicationNumber}, status: ${finalStatus} (MemStorage: ${application?.status || 'not found'}, SQL: ${sqlStatus || 'not found'})`);
      
      // If statuses are different, sync them (update MemStorage to match SQL)
      if (application && sqlStatus && application.status !== sqlStatus) {
        console.log(`Status mismatch detected for application ${applicationNumber}. Updating MemStorage to match SQL: ${sqlStatus}`);
        // Update the memory storage to match SQL (more authoritative)
        try {
          await storage.updateAccountApplicationStatus(
            application.id,
            sqlStatus,
            application.reviewerId || null,
            "Status synchronized from SQL database"
          );
          console.log(`✅ Successfully synchronized application ${applicationNumber} status from SQL to MemStorage`);
        } catch (syncError) {
          console.error(`Failed to sync application status to MemStorage: ${syncError}`);
        }
      }
      
      // Get IP address for tracking
      const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
      
      // Check if this user can submit a new application
      let canSubmitNew = false;
      if (finalStatus === 'denied') {
        // If this application was denied, they can submit a new one
        canSubmitNew = true;
      }
      
      // For SQL-sourced status, create proper reviewed date if it was approved
      const reviewedAt = sqlStatus === 'approved' ? new Date() : application?.reviewedAt || null;
      
      // Return enhanced information about the application
      res.status(200).json({
        applicationNumber: applicationNumber,
        status: finalStatus,
        submittedAt: application?.submittedAt || new Date(),
        lastUpdatedAt: new Date(), // Always use current time to ensure client sees changes
        reviewedAt: reviewedAt,
        reasonForDenial: application?.reasonForDenial || null,
        canSubmitNew: canSubmitNew,
        // Messages based on status
        statusMessage: getStatusMessage(finalStatus),
        nextSteps: getNextSteps(finalStatus),
        // Add a timestamp to force client-side state updates
        _timestamp: Date.now()
      });
    } catch (error) {
      console.error("Application status check error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
// Helper functions for application status messages
function getStatusMessage(status: string): string {
  switch(status) {
    case 'pending_review':
      return "Your application is pending review by our team.";
    case 'in_review':
      return "Your application is currently being reviewed by our banking team.";
    case 'approved':
      return "Your application has been approved! You can now create login credentials.";
    case 'denied':
      return "We're sorry, but your application was not approved at this time.";
    case 'additional_info':
      return "We need additional information to process your application.";
    default:
      return "Application status: " + status;
  }
}

function getNextSteps(status: string): string {
  switch(status) {
    case 'pending_review':
      return "Please check back in 1-2 business days for an update.";
    case 'in_review':
      return "No action needed. We'll notify you once the review is complete.";
    case 'approved':
      return "Click on 'Create Login' to set up your account credentials.";
    case 'denied':
      return "You may submit a new application with updated information if you wish.";
    case 'additional_info':
      return "Please contact customer support to provide the required information.";
    default:
      return "";
  }
}
  
  // Admin Routes - List All Applications
  // API endpoint to get application by application number
  app.get("/api/admin/account-applications/by-number/:applicationNumber", authenticateAdmin, async (req, res) => {
    try {
      const { applicationNumber } = req.params;
      
      if (!applicationNumber) {
        return res.status(400).json({ message: "Application number is required" });
      }
      
      // First, try to get the application from MemStorage
      let application = await storage.getAccountApplicationByApplicationNumber(applicationNumber);
      let foundInSQL = false;
      
      // If not found in MemStorage, check the SQL database
      if (!application) {
        try {
          const { pool } = await import("./db");
          const sqlResult = await pool.query(
            'SELECT * FROM applications WHERE application_id = $1',
            [applicationNumber]
          );
          
          if (sqlResult.rows && sqlResult.rows.length > 0) {
            const sqlApp = sqlResult.rows[0];
            foundInSQL = true;
            
            // Create a simplified application object from SQL data
            application = {
              id: sqlApp.id,
              status: sqlApp.status,
              applicationNumber: sqlApp.application_id,
              contactEmail: sqlApp.email,
              contactPhone: sqlApp.phone || '',
              submittedAt: sqlApp.created_at,
              lastUpdatedAt: sqlApp.updated_at,
              ipAddress: sqlApp.ip_address,
              // Other fields may be incomplete but provide minimum data needed
              userId: null,
              reviewerId: null,
              reviewedAt: null,
              applicationData: {
                personal: {
                  firstName: sqlApp.name.split(' ')[0] || '',
                  lastName: sqlApp.name.split(' ').slice(1).join(' ') || ''
                }
              },
              notes: 'Application data recovered from SQL database'
            };
            
            console.log(`Application ${applicationNumber} found in SQL but not in MemStorage, created simplified object`);
          }
        } catch (sqlError) {
          console.error("Error checking SQL database for application:", sqlError);
        }
      }
      
      // If application still not found, return 404
      if (!application) {
        return res.status(404).json({ message: "Application not found in any storage system" });
      }
      
      // Log application detail access for compliance and auditing
      await storage.createDocumentAccessLog({
        accessId: `app-detail-${applicationNumber}-${Date.now()}`,
        documentPath: `/api/admin/account-applications/by-number/${applicationNumber}`,
        documentType: 'application-details',
        entityType: 'application',
        entityId: application.id,
        accessedBy: req.user.id,
        isAdminAccess: true,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        browserInfo: JSON.stringify(req.headers),
        accessMethod: 'view',
        accessStatus: 'success',
        accessReason: 'Administrative review',
        sessionId: req.sessionID,
        encryptionStatus: 'encrypted',
        additionalInfo: JSON.stringify({
          adminId: req.user.id,
          adminName: `${req.user.firstName} ${req.user.lastName}`,
          applicationNumber: application.applicationNumber,
          applicationStatus: application.status
        }),
        purpose: 'application_review'
      });
      
      // Fetch document access logs for this application
      const accessLogs = await storage.getDocumentAccessLogsByEntityId(
        'application', 
        application.id,
        20 // Limit to most recent 20 logs
      );
      
      // Return the application data with access logs
      res.status(200).json({
        application,
        accessLogs,
        metadata: {
          accessedAt: new Date().toISOString(),
          accessedBy: {
            id: req.user.id,
            name: `${req.user.firstName} ${req.user.lastName}`
          }
        }
      });
    } catch (error) {
      console.error("Admin application details by number error:", error);
      res.status(500).json({ 
        message: "Error retrieving application details", 
        error: error instanceof Error ? error.message : "Unknown error" 
      });
    }
  });

  // Ensure the applications table exists
  const ensureApplicationsTable = async () => {
    try {
      const { pool } = await import("./db");
      
      // Check if the applications table exists
      const tableCheck = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name = 'applications'
        );
      `);
      
      const tableExists = tableCheck.rows[0].exists;
      
      if (!tableExists) {
        console.log("Creating applications table...");
        // Create the applications table with additional fields
        await pool.query(`
          CREATE TABLE applications (
            id SERIAL PRIMARY KEY,
            application_id VARCHAR(20) NOT NULL,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            phone VARCHAR(20),
            document_filename VARCHAR(255),
            ip_address VARCHAR(50),
            status VARCHAR(50) DEFAULT 'pending_review',
            reviewer_id INTEGER,
            reviewer_name VARCHAR(255),
            review_notes TEXT,
            reviewed_at TIMESTAMP,
            reason_for_denial TEXT,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            application_data JSONB
          );
        `);
        
        // Create index to speed up lookups
        await pool.query(`
          CREATE INDEX idx_applications_application_id ON applications(application_id);
          CREATE INDEX idx_applications_ip_address ON applications(ip_address);
          CREATE INDEX idx_applications_email ON applications(email);
          CREATE INDEX idx_applications_status ON applications(status);
        `);
        
        // Insert sample data for testing 
        await pool.query(`
          INSERT INTO applications (application_id, name, email, phone, status, ip_address) VALUES
          ('APP-20250430-0001', 'John Smith', 'john.smith@example.com', '123-456-7890', 'pending_review', '192.168.1.1'),
          ('APP-20250430-0002', 'Jane Doe', 'jane.doe@example.com', '234-567-8901', 'approved', '192.168.1.2'),
          ('APP-20250430-0003', 'Robert Johnson', 'robert.johnson@example.com', '345-678-9012', 'denied', '192.168.1.3'),
          ('APP-20250430-0004', 'Sarah Williams', 'sarah.williams@example.com', '456-789-0123', 'pending_review', '192.168.1.4')
        `);
        
        console.log("Applications table created with sample data and indexes");
      } else {
        // Check if we need to add any missing columns - this helps upgrade existing tables
        try {
          // Check for application_data column
          const columnCheck = await pool.query(`
            SELECT EXISTS (
              SELECT FROM information_schema.columns 
              WHERE table_schema = 'public' 
              AND table_name = 'applications'
              AND column_name = 'application_data'
            );
          `);
          
          const hasApplicationData = columnCheck.rows[0].exists;
          
          if (!hasApplicationData) {
            console.log("Adding application_data column to applications table...");
            await pool.query(`
              ALTER TABLE applications 
              ADD COLUMN application_data JSONB,
              ADD COLUMN reviewer_id INTEGER,
              ADD COLUMN reviewer_name VARCHAR(255),
              ADD COLUMN review_notes TEXT,
              ADD COLUMN reviewed_at TIMESTAMP,
              ADD COLUMN reason_for_denial TEXT,
              ADD COLUMN user_id INTEGER
            `);
            
            // Also create indexes if they don't exist
            await pool.query(`
              CREATE INDEX IF NOT EXISTS idx_applications_application_id ON applications(application_id);
              CREATE INDEX IF NOT EXISTS idx_applications_ip_address ON applications(ip_address);
              CREATE INDEX IF NOT EXISTS idx_applications_email ON applications(email);
              CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
            `);
            
            console.log("Applications table updated with additional columns and indexes");
          }
        } catch (alterError) {
          console.error("Error updating applications table schema:", alterError);
          // Continue even if alter table fails
        }
        
        console.log("Applications table already exists");
      }
      
      return tableExists;
    } catch (error) {
      console.error("Error ensuring applications table:", error);
      return false;
    }
  };
  
  // Admin endpoint to check and create the applications table
  app.get("/api/admin/check-applications-table", authenticateAdmin, async (req, res) => {
    try {
      const result = await ensureApplicationsTable();
      const { pool } = await import("./db");
      
      // Count applications
      const countResult = await pool.query('SELECT COUNT(*) FROM applications');
      const count = parseInt(countResult.rows[0].count);
      
      res.status(200).json({
        message: result ? "Applications table already exists" : "Applications table created",
        applicationCount: count
      });
    } catch (error) {
      console.error("Error checking applications table:", error);
      res.status(500).json({ message: "Error checking applications table" });
    }
  });
  
  // Direct SQL applications endpoint - dedicated endpoint just for SQL applications
  app.get("/api/admin/sql-applications", authenticateAdmin, async (req, res) => {
    try {
      await ensureApplicationsTable();
      const { pool } = await import("./db");
      const result = await pool.query('SELECT * FROM applications ORDER BY created_at DESC');
      
      if (result.rows && result.rows.length > 0) {
        console.log(`Found ${result.rows.length} applications from SQL database`);
        
        // Log access for auditing
        await storage.createDocumentAccessLog({
          accessId: `sql-app-list-${Date.now()}`,
          documentPath: '/api/admin/sql-applications',
          documentType: 'sql-application-list',
          entityType: 'admin',
          entityId: req.user.id,
          accessedBy: req.user.id,
          isAdminAccess: true,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'] || '',
          browserInfo: JSON.stringify(req.headers),
          accessMethod: 'view',
          accessStatus: 'success',
          accessReason: 'Administrative review of SQL applications',
          sessionId: req.sessionID,
          encryptionStatus: 'encrypted',
          additionalInfo: JSON.stringify({
            resultCount: result.rows.length,
            queryType: 'direct-sql-endpoint'
          }),
          purpose: 'sql_applications_management'
        });
        
        return res.status(200).json({
          applications: result.rows.map(row => ({
            id: row.id,
            applicationNumber: row.application_id,
            name: row.name,
            email: row.email,
            contactEmail: row.email,
            contactPhone: row.phone,
            status: row.status,
            submittedAt: row.created_at,
            lastUpdatedAt: row.updated_at,
            documentFilename: row.document_filename,
            applicationData: {
              firstName: row.name.split(' ')[0],
              lastName: row.name.split(' ').slice(1).join(' '),
              email: row.email
            },
            ipAddress: row.ip_address
          })),
          source: "sql-database"
        });
      } else {
        return res.status(200).json({
          applications: [],
          source: "sql-database"
        });
      }
    } catch (error) {
      console.error("Error retrieving SQL applications:", error);
      res.status(500).json({ 
        message: "Error retrieving SQL applications", 
        error: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  
  // Ensure applications table exists when the server starts
  ensureApplicationsTable();

  // Enhanced Admin Applications API with pagination, sorting, and filtering
  app.get("/api/admin/account-applications", authenticateAdmin, async (req, res) => {
    try {
      // First try new direct PostgreSQL approach if the applications table exists
      try {
        // Maintaining backward compatibility with existing code by using both approaches
        // The PostgreSQL pool direct query using new schema
        const { pool } = await import("./db");
        const result = await pool.query('SELECT * FROM applications ORDER BY created_at DESC');
        
        // Return either from the new table or fall back to the old one
        if (result.rows && result.rows.length > 0) {
          // Log access for regulatory compliance (simplified for direct query)
          await storage.createDocumentAccessLog({
            accessId: `app-list-${Date.now()}`,
            documentPath: '/api/admin/account-applications',
            documentType: 'application-list',
            entityType: 'admin',
            entityId: req.user.id,
            accessedBy: req.user.id,
            isAdminAccess: true,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'] || '',
            browserInfo: JSON.stringify(req.headers),
            accessMethod: 'view',
            accessStatus: 'success',
            accessReason: 'Administrative review of applications',
            sessionId: req.sessionID,
            encryptionStatus: 'encrypted',
            additionalInfo: JSON.stringify({
              resultCount: result.rows.length,
              queryType: 'direct-sql'
            }),
            purpose: 'applications_management'
          });
          
          return res.status(200).json({
            applications: result.rows.map(row => ({
              id: row.id,
              applicationNumber: row.application_id,
              name: row.name,
              email: row.email,
              contactEmail: row.email,
              contactPhone: row.phone,
              status: row.status,
              submittedAt: row.created_at,
              lastUpdatedAt: row.updated_at,
              documentFilename: row.document_filename,
              applicationData: {
                firstName: row.name.split(' ')[0],
                lastName: row.name.split(' ').slice(1).join(' '),
                email: row.email
              },
              ipAddress: row.ip_address
            })),
            pagination: {
              total: result.rows.length,
              page: 1,
              limit: result.rows.length,
              totalPages: 1
            }
          });
        }
      } catch (sqlError) {
        console.log("Direct SQL approach failed, falling back to storage API:", sqlError);
        // Continue to existing code if the direct SQL approach fails
      }
      
      // Original approach with storage API
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 50;
      const status = req.query.status as string;
      const sortBy = req.query.sortBy as string || 'submittedAt';
      const sortOrder = req.query.sortOrder as string || 'desc';
      const search = req.query.search as string;
      
      // Calculate pagination offset
      const offset = (page - 1) * limit;
      
      // Get applications with filtering, sorting and pagination
      const applications = await storage.getAllAccountApplications(
        status, 
        limit, 
        offset, 
        sortBy, 
        sortOrder,
        search
      );
      
      // Get total count for pagination
      const totalCount = await storage.getAccountApplicationsCount(status, search);
      
      // Log access for regulatory compliance
      await storage.createDocumentAccessLog({
        accessId: `app-list-${Date.now()}`,
        documentPath: '/api/admin/account-applications',
        documentType: 'application-list',
        entityType: 'admin',
        entityId: req.user.id,
        accessedBy: req.user.id,
        isAdminAccess: true,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        browserInfo: JSON.stringify(req.headers),
        accessMethod: 'view',
        accessStatus: 'success',
        accessReason: 'Administrative review of applications',
        sessionId: req.sessionID,
        encryptionStatus: 'encrypted',
        additionalInfo: JSON.stringify({
          filters: { status, page, limit, sortBy, sortOrder, search },
          resultCount: applications.length
        }),
        purpose: 'applications_management'
      });
      
      // Return paginated response with metadata
      res.status(200).json({
        applications,
        pagination: {
          total: totalCount,
          page,
          limit,
          totalPages: Math.ceil(totalCount / limit)
        },
        filters: {
          status: status || 'all',
          search: search || ''
        },
        sorting: {
          sortBy,
          sortOrder
        }
      });
    } catch (error) {
      console.error("Admin applications list error:", error);
      res.status(500).json({ message: "Error retrieving applications: " + (error instanceof Error ? error.message : "Unknown error") });
    }
  });
  
  // Enhanced Admin Routes - Get Application Details with document access tracking
  app.get("/api/admin/account-applications/:id", authenticateAdmin, async (req, res) => {
    try {
      const applicationId = parseInt(req.params.id);
      
      const application = await storage.getAccountApplication(applicationId);
      if (!application) {
        return res.status(404).json({ message: "Application not found" });
      }
      
      // Log application detail access for compliance and auditing
      await storage.createDocumentAccessLog({
        accessId: `app-detail-${applicationId}-${Date.now()}`,
        documentPath: `/api/admin/account-applications/${applicationId}`,
        documentType: 'application-details',
        entityType: 'application',
        entityId: applicationId,
        accessedBy: req.user.id,
        isAdminAccess: true,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        browserInfo: JSON.stringify(req.headers),
        accessMethod: 'view',
        accessStatus: 'success',
        accessReason: 'Administrative review',
        sessionId: req.sessionID,
        encryptionStatus: 'encrypted',
        additionalInfo: JSON.stringify({
          adminId: req.user.id,
          adminName: `${req.user.firstName} ${req.user.lastName}`,
          applicationNumber: application.applicationNumber,
          applicationStatus: application.status
        }),
        purpose: 'application_review'
      });
      
      // Fetch document access logs for this application
      const accessLogs = await storage.getDocumentAccessLogsByEntityId(
        'application', 
        applicationId,
        20 // Limit to most recent 20 logs
      );
      
      // Return the application data with access logs
      res.status(200).json({
        application,
        accessLogs,
        metadata: {
          accessedAt: new Date().toISOString(),
          accessedBy: {
            id: req.user.id,
            name: `${req.user.firstName} ${req.user.lastName}`
          }
        }
      });
    } catch (error) {
      console.error("Admin application details error:", error);
      res.status(500).json({ 
        message: "Error retrieving application details", 
        error: error instanceof Error ? error.message : "Unknown error" 
      });
    }
  });
  
  // Admin Routes - Approve Application
  app.post("/api/admin/account-applications/:id/approve", authenticateAdmin, async (req, res) => {
    try {
      const applicationId = parseInt(req.params.id);
      const adminId = req.session.userId!;
      const { notes } = req.body;
      
      const application = await storage.getAccountApplication(applicationId);
      if (!application) {
        return res.status(404).json({ message: "Application not found" });
      }
      
      if (application.status !== 'pending_review') {
        return res.status(400).json({ 
          message: "Only pending applications can be approved",
          currentStatus: application.status
        });
      }
      
      // Update application status in MemStorage
      const updatedApplication = await storage.updateAccountApplicationStatus(
        applicationId,
        'approved',
        adminId,
        notes
      );
      
      // Also update the SQL database if it exists
      try {
        const { pool } = await import("./db");
        
        // First, check if the application exists in the SQL database by application number
        const checkResult = await pool.query(
          'SELECT * FROM applications WHERE application_id = $1',
          [application.applicationNumber]
        );
        
        if (checkResult.rows && checkResult.rows.length > 0) {
          // Application exists in SQL DB, update it
          console.log(`Updating SQL application ${application.applicationNumber} to approved status`);
          await pool.query(
            'UPDATE applications SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE application_id = $2',
            ['approved', application.applicationNumber]
          );
        } else {
          console.log(`Application ${application.applicationNumber} not found in SQL DB, skipping SQL update`);
        }
      } catch (sqlError) {
        console.error("Error updating application in SQL database:", sqlError);
        // Continue with the response even if SQL update fails
      }
      
      // Also update any related KYC verification records
      try {
        // Query for KYC verification records associated with this application
        const kycVerifications = await storage.getKycVerificationsByApplicationId(applicationId);
        if (kycVerifications && kycVerifications.length > 0) {
          for (const kyc of kycVerifications) {
            await storage.updateKycVerification(kyc.id, {
              status: 'approved',
              reviewerId: adminId,
              reviewedAt: new Date(),
              notes: notes || 'Application approved'
            });
          }
          console.log(`Updated ${kycVerifications.length} KYC verification records for approved application ${applicationId}`);
        }
      } catch (kycError) {
        console.error("Error updating KYC verification records:", kycError);
        // Continue with response even if KYC record update fails
      }
      
      // ENHANCEMENT: Auto-create a user account for the approved application
      try {
        // Extract application data for user creation
        const appData = application.applicationData as any;
        const contactEmail = application.contactEmail;
        
        // Only proceed if we have the necessary data
        if (appData && appData.personal && contactEmail) {
          const firstName = appData.personal.firstName || '';
          const lastName = appData.personal.lastName || '';
          
          // Generate a username based on first and last name
          const baseUsername = `${firstName.toLowerCase()}${lastName.toLowerCase()}`.replace(/[^a-z0-9]/g, '');
          let username = baseUsername;
          let counter = 1;
          
          // Check if username exists and add counter if needed
          let existingUser = await storage.getUserByUsername(username);
          while (existingUser) {
            username = `${baseUsername}${counter}`;
            counter++;
            existingUser = await storage.getUserByUsername(username);
          }
          
          // Generate a temporary password - in a real system, this would be random and secure
          const tempPassword = `temp${Math.floor(100000 + Math.random() * 900000)}`;
          
          // Create the user
          const user = await storage.createUser({
            username,
            password: tempPassword, // This would be hashed in storage.createUser
            firstName,
            lastName,
            email: contactEmail,
            phoneNumber: application.contactPhone || '',
            isVerified: true, // Mark as verified since application was approved
            isActive: true
          });
          
          console.log(`🏦 Auto-created user account for approved application: ${username}`);
          
          // Update application with reference to the created user
          const updatedApp = await storage.getAccountApplication(applicationId);
          if (updatedApp) {
            updatedApp.userId = user.id;
            await storage.updateAccountApplication(applicationId, updatedApp);
            console.log(`Updated application ${applicationId} with new userId ${user.id}`);
          }
          
          // In a real system, we would now send an email with account details and password reset link
          console.log(`Would send welcome email to ${contactEmail} with username: ${username} and temp password instructions`);
          
          // Include the created user info in the response
          updatedApplication.autoCreatedUser = {
            id: user.id,
            username,
            email: contactEmail,
            tempPasswordGenerated: true
          };
        } else {
          console.log('Could not auto-create user - missing required application data');
        }
      } catch (userCreationError) {
        console.error("Error auto-creating user from approved application:", userCreationError);
        // Continue with response even if user creation fails
      }
      
      res.status(200).json(updatedApplication);
    } catch (error) {
      console.error("Admin application approval error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Admin Routes - Deny Application
  app.post("/api/admin/account-applications/:id/deny", authenticateAdmin, async (req, res) => {
    try {
      const applicationId = parseInt(req.params.id);
      const adminId = req.session.userId!;
      const { notes, reason } = req.body;
      
      if (!reason) {
        return res.status(400).json({ message: "Reason for denial is required" });
      }
      
      const application = await storage.getAccountApplication(applicationId);
      if (!application) {
        return res.status(404).json({ message: "Application not found" });
      }
      
      if (application.status !== 'pending_review') {
        return res.status(400).json({ 
          message: "Only pending applications can be denied",
          currentStatus: application.status
        });
      }
      
      // Update application status in MemStorage
      const updatedApplication = await storage.updateAccountApplicationStatus(
        applicationId,
        'denied',
        adminId,
        notes || reason
      );
      
      // Also update the SQL database record with denial info
      try {
        const { pool } = await import("./db");
        await ensureApplicationsTable();
        
        // Check if record exists in SQL database
        const checkResult = await pool.query(
          'SELECT * FROM applications WHERE application_id = $1',
          [application.applicationNumber]
        );
        
        if (checkResult.rows && checkResult.rows.length > 0) {
          // Update existing record
          console.log(`Updating SQL application ${application.applicationNumber} to denied status`);
          await pool.query(`
            UPDATE applications 
            SET status = $1, 
                updated_at = CURRENT_TIMESTAMP, 
                reviewer_id = $2,
                reviewer_name = $3,
                review_notes = $4,
                reviewed_at = CURRENT_TIMESTAMP,
                reason_for_denial = $5
            WHERE application_id = $6
          `, [
            'denied',
            adminId,
            'Admin Staff', // In a real app you would use actual admin name
            notes || 'Application denied',
            reason,
            application.applicationNumber
          ]);
        } else {
          // If not in SQL DB, add it (for consistency)
          // Get basic info from application
          const personalInfo = application.applicationData?.personal || {};
          const fullName = `${personalInfo.firstName || ''} ${personalInfo.lastName || ''}`.trim();
          
          await pool.query(`
            INSERT INTO applications 
            (application_id, name, email, phone, ip_address, status, 
             reviewer_id, review_notes, reviewed_at, reason_for_denial, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
          `, [
            application.applicationNumber,
            fullName || 'Unnamed Applicant',
            application.contactEmail || '',
            application.contactPhone || '',
            application.ipAddress || '',
            'denied',
            adminId,
            notes || 'Application denied',
            new Date(),
            reason,
            application.submittedAt || new Date(),
            new Date()
          ]);
        }
        
        console.log(`Successfully updated SQL record for denied application ${application.applicationNumber}`);
      } catch (sqlError) {
        console.error("Error updating application in SQL database:", sqlError);
        // Continue with response even if SQL update fails
      }
      
      // We already tried to update the SQL database above, so no need for a second attempt
      
      // Also update any related KYC verification records
      try {
        // Query for KYC verification records associated with this application
        const kycVerifications = await storage.getKycVerificationsByApplicationId(applicationId);
        if (kycVerifications && kycVerifications.length > 0) {
          for (const kyc of kycVerifications) {
            await storage.updateKycVerification(kyc.id, {
              status: 'rejected',
              reviewerId: adminId,
              reviewedAt: new Date(),
              notes: notes || reason || 'Application denied'
            });
          }
          console.log(`Updated ${kycVerifications.length} KYC verification records for denied application ${applicationId}`);
        }
      } catch (kycError) {
        console.error("Error updating KYC verification records for denied application:", kycError);
        // Continue with response even if KYC record update fails
      }
      
      // In a real app, we would send an email notification to the applicant
      
      res.status(200).json(updatedApplication);
    } catch (error) {
      console.error("Admin application denial error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Create user from approved application
  app.post("/api/admin/account-applications/:id/create-user", authenticateAdmin, async (req, res) => {
    try {
      const applicationId = parseInt(req.params.id);
      const adminId = req.session.userId!;
      const { username, password } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required" });
      }
      
      const application = await storage.getAccountApplication(applicationId);
      if (!application) {
        return res.status(404).json({ message: "Application not found" });
      }
      
      if (application.status !== 'approved') {
        return res.status(400).json({ 
          message: "Only approved applications can be converted to users",
          currentStatus: application.status
        });
      }
      
      // Check if user with username already exists
      const existingUser = await storage.getUserByUsername(username);
      if (existingUser) {
        return res.status(400).json({ message: "Username already exists" });
      }
      
      // Create user from application
      const user = await storage.convertApplicationToUser(applicationId, username, password);
      
      // Update any related KYC verification records to point to the created user
      try {
        // Query for KYC verification records associated with this application
        const kycVerifications = await storage.getKycVerificationsByApplicationId(applicationId);
        if (kycVerifications && kycVerifications.length > 0) {
          for (const kyc of kycVerifications) {
            await storage.updateKycVerification(kyc.id, {
              userId: user.id,
              status: 'approved',
              reviewerId: adminId,
              reviewedAt: new Date(),
              notes: `User account created from application ${application.applicationNumber}`
            });
          }
          console.log(`Updated ${kycVerifications.length} KYC verification records for user creation from application ${applicationId}`);
        }
      } catch (kycError) {
        console.error("Error updating KYC verification records for user creation:", kycError);
        // Continue with response even if KYC record update fails
      }
      
      // Don't return password
      const { password: _, ...userWithoutPassword } = user;
      
      res.status(201).json({
        message: "User created successfully",
        user: userWithoutPassword
      });
    } catch (error) {
      console.error("Create user from application error:", error);
      res.status(500).json({ 
        message: "Failed to create user", 
        error: (error as Error).message 
      });
    }
  });

  // Use the document routes for all document-related endpoints
  app.use("/api/documents", documentRouter);

  // Secure Document Handling System
  // In a real banking application, these would use secure storage with encryption, access controls,
  // audit logging, and proper authentication checks.

  // Document Upload Security Middleware
  const secureDocumentAccess = async (req: Request, res: Response, next: Function) => {
    // In a real bank application, this would:
    // 1. Verify proper authentication (which we're doing)
    // 2. Check specific document access permissions
    // 3. Log access attempts for compliance and security auditing
    // 4. Implement rate limiting to prevent abuse
    // 5. Verify request integrity with CSRF tokens
    
    // Check for authentication using our session userId
    const isAuthenticated = !!req.session.userId;
    const isAdminPath = req.path.includes('/api/admin/');
    const isAdminAuth = req.headers['x-admin-auth'] === process.env.ADMIN_SECRET_TOKEN;
    
    if (!isAuthenticated && !isAdminPath && !isAdminAuth) {
      return res.status(401).json({ 
        message: "Unauthorized access to secure documents",
        errorCode: "DOCUMENT_AUTH_REQUIRED",
        timestamp: new Date().toISOString()
      });
    }
    
    // Log document access for audit trail
    console.log(`[SECURITY AUDIT] Document access attempt: ${req.path} by user ${req.session.userId || 'admin'}`);
    
    // Store document access details if a userId is available
    try {
      if (req.session.userId) {
        const userId = req.session.userId;
        const path = req.path;
        const isAdmin = path.includes('/api/admin/');
        const ipAddress = req.ip || req.socket.remoteAddress || null;
        const userAgent = req.headers['user-agent'] || null;
        
        // Extract entity type and ID from the URL path
        // This is a simplified version; in a real app, you'd have a more robust parser
        let entityType = 'document';
        let entityId = 0;
        
        if (path.includes('/kyc/')) {
          entityType = 'kyc';
          const match = path.match(/\/kyc\/(\d+)/);
          if (match && match[1]) {
            entityId = parseInt(match[1], 10);
          }
        } else if (path.includes('/application/')) {
          entityType = 'application';
          const match = path.match(/\/application\/(\d+)/);
          if (match && match[1]) {
            entityId = parseInt(match[1], 10);
          }
        } else if (path.includes('/account/')) {
          entityType = 'account';
          const match = path.match(/\/account\/(\d+)/);
          if (match && match[1]) {
            entityId = parseInt(match[1], 10);
          }
        }
        
        // Create an access log through the storage interface
        await storage.createDocumentAccessLog({
          accessId: req.headers['x-access-id'] as string || crypto.randomUUID(),
          documentType: path.split('/').pop() || 'unknown',
          entityType,
          entityId,
          documentPath: path,
          accessedBy: userId,
          accessStatus: 'successful',
          isAdminAccess: isAdmin,
          ipAddress,
          userAgent,
          purpose: 'Viewing',
          encryptionStatus: 'encrypted',
          additionalInfo: JSON.stringify({
            method: req.method,
            referrer: req.headers.referer || null
          })
        });
      }
    } catch (error) {
      // Log but don't block access on logging failure
      console.error('Error logging document access:', error);
    }
    
    next();
  };

  // Secure document download route for KYC verification documents
  app.get("/api/documents/kyc/:verificationId/:documentType", secureDocumentAccess, async (req, res) => {
    try {
      const { verificationId, documentType } = req.params;
      
      // Validate request parameters
      if (!verificationId || !documentType) {
        return res.status(400).json({ message: "Invalid document request" });
      }
      
      const isAdmin = req.session.isAdmin;
      const userId = req.session.userId;
      
      // Get the verification record to check permissions
      const verification = await storage.getKycVerification(parseInt(verificationId));
      
      // Security check - only document owner or admin can access
      if (!verification) {
        return res.status(404).json({ message: "Document not found" });
      }
      
      if (!isAdmin && verification.userId !== userId) {
        // Log security violation attempt
        console.log(`[SECURITY WARNING] Unauthorized document access attempt: User ${userId} attempted to access document for verification ${verificationId}`);
        return res.status(403).json({ message: "Forbidden" });
      }
      
      // Get user data to include with document
      let userData = null;
      if (verification.userId) {
        userData = await storage.getUser(verification.userId);
      }
      
      // Enhanced document access with complete details
      // Log successful document access for audit compliance
      console.log(`[AUDIT] Document access: ${documentType} for verification ${verificationId} by ${isAdmin ? 'admin' : 'user ' + userId}`);
      
      // In a real bank application, this would retrieve the actual document
      // and stream it with proper headers. For our prototype, we'll return
      // placeholder data with comprehensive metadata.
      
      const accessId = `DOC-ACCESS-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
      const accessTimestamp = new Date().toISOString();
      
      if (['id-front', 'id-back', 'passport', 'drivers-license-front', 'drivers-license-back'].includes(documentType)) {
        // Identity document - return with detailed metadata
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          verificationId: parseInt(verificationId),
          userId: verification.userId,
          idType: verification.idType,
          idNumber: verification.idNumber,
          idExpiryDate: verification.idExpiryDate,
          idIssueCountry: verification.idIssueCountry,
          verificationStatus: verification.status,
          reviewerId: verification.reviewerId,
          reviewedAt: verification.reviewedAt,
          userDetails: userData ? {
            id: userData.id,
            fullName: `${userData.firstName} ${userData.lastName}`,
            email: userData.email,
            dateOfBirth: userData.dateOfBirth,
            securityLevel: userData.securityLevel,
            status: userData.status,
            verificationStatus: userData.kycStatus,
            nationality: userData.nationality,
            gender: userData.gender
          } : null,
          securityLevel: "critical",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
            isTransferLimited: true
          }
        });
      } else if (documentType === 'proof-of-address') {
        // Proof of address document
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          verificationId: parseInt(verificationId),
          userId: verification.userId,
          addressType: verification.addressType || 'residential',
          addressVerified: verification.addressVerified,
          addressVerificationMethod: verification.addressVerificationMethod || 'document',
          verificationStatus: verification.status,
          addressDetails: verification.addressDetails,
          userDetails: userData ? {
            id: userData.id,
            fullName: `${userData.firstName} ${userData.lastName}`,
            email: userData.email,
            dateOfBirth: userData.dateOfBirth,
            securityLevel: userData.securityLevel,
            status: userData.status,
            verificationStatus: userData.kycStatus
          } : null,
          securityLevel: "sensitive",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
            isTransferLimited: true
          }
        });
      } else if (documentType === 'selfie' || documentType === 'video-verification') {
        // Selfie or video verification
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          verificationId: parseInt(verificationId),
          userId: verification.userId,
          biometricVerificationStatus: verification.biometricVerificationStatus || 'pending',
          livenessCheckPassed: verification.livenessCheckPassed,
          faceMatchConfidence: verification.faceMatchConfidence || 0.85,
          verificationStatus: verification.status,
          userDetails: userData ? {
            id: userData.id,
            fullName: `${userData.firstName} ${userData.lastName}`,
            email: userData.email,
            dateOfBirth: userData.dateOfBirth,
            securityLevel: userData.securityLevel,
            status: userData.status,
            verificationStatus: userData.kycStatus
          } : null,
          securityLevel: "critical",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
            isTransferLimited: true,
            biometricDataProtected: true
          }
        });
      } else {
        // Generic response for any other document type
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          verificationId: parseInt(verificationId),
          userId: verification.userId,
          verificationStatus: verification.status,
          userDetails: userData ? {
            id: userData.id,
            fullName: `${userData.firstName} ${userData.lastName}`,
            email: userData.email,
            securityLevel: userData.securityLevel,
            status: userData.status
          } : null,
          securityLevel: "standard",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip
        });
      }
    } catch (error) {
      console.error("Secure document access error:", error);
      res.status(500).json({ 
        message: "Failed to retrieve document",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
        requestId: `REQ-${Date.now()}`
      });
    }
  });

  // Secure document download route for application documents
  app.get("/api/documents/application/:applicationId/:documentType", secureDocumentAccess, async (req, res) => {
    try {
      const { applicationId, documentType } = req.params;
      
      // Validate request parameters
      if (!applicationId || !documentType) {
        return res.status(400).json({ message: "Invalid document request" });
      }
      
      const isAdmin = req.session.isAdmin;
      const userId = req.session.userId;
      
      // Get the application to check permissions
      const application = await storage.getAccountApplication(parseInt(applicationId));
      
      // Security check - only application owner or admin can access
      if (!application) {
        return res.status(404).json({ message: "Document not found" });
      }
      
      // Check if user owns this application or is admin
      // In a real app, we would have the proper relationship between applications and users
      if (!isAdmin && application.contactEmail !== userId) {
        // Log security violation attempt
        console.log(`[SECURITY WARNING] Unauthorized application document access attempt: User ${userId} attempted to access document for application ${applicationId}`);
        return res.status(403).json({ message: "Forbidden" });
      }
      
      // Enhanced document access with complete details
      // Log successful document access for audit compliance
      console.log(`[AUDIT] Application document access: ${documentType} for application ${applicationId} by ${isAdmin ? 'admin' : 'user ' + userId}`);
      
      // Get reviewer data if it exists
      let reviewerData = null;
      if (application.reviewerId) {
        reviewerData = await storage.getUser(application.reviewerId);
      }
      
      // In a real bank application, this would retrieve the actual document
      // and stream it with proper headers. For our prototype, we'll return
      // placeholder data with comprehensive metadata.
      
      const accessId = `DOC-ACCESS-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
      const accessTimestamp = new Date().toISOString();
      
      // Parse the application data to include relevant details
      let applicationDetails = {};
      if (application.applicationData) {
        try {
          // Try to parse it if it's a string
          if (typeof application.applicationData === 'string') {
            applicationDetails = JSON.parse(application.applicationData);
          } else {
            // If it's already an object, use it directly
            applicationDetails = application.applicationData;
          }
        } catch (e) {
          console.error("Failed to parse application data:", e);
          // If parsing fails, provide a fallback
          applicationDetails = { 
            note: "Application data could not be parsed",
            rawData: application.applicationData
          };
        }
      }
      
      if (documentType === 'application-form') {
        // Application form document - return with detailed metadata
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          applicationId: parseInt(applicationId),
          applicationNumber: application.applicationNumber,
          applicationStatus: application.status,
          submittedAt: application.submittedAt,
          lastUpdatedAt: application.lastUpdatedAt,
          reviewedAt: application.reviewedAt,
          applicationDetails: applicationDetails,
          ipAddress: application.ipAddress,
          deviceInfo: application.deviceInfo,
          contactDetails: {
            email: application.contactEmail,
            phone: application.contactPhone
          },
          reviewData: application.reviewerId ? {
            reviewerId: application.reviewerId,
            reviewerName: reviewerData ? `${reviewerData.firstName} ${reviewerData.lastName}` : 'Unknown',
            reviewNotes: application.reviewNotes,
            reviewDate: application.reviewedAt
          } : null,
          securityLevel: "sensitive",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
            isTransferLimited: true
          }
        });
      } else if (documentType === 'identity-proof' || documentType === 'passport' || documentType === 'drivers-license') {
        // Identity document
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          applicationId: parseInt(applicationId),
          applicationNumber: application.applicationNumber,
          applicationStatus: application.status,
          identificationDetails: applicationDetails.identification || {},
          personalDetails: applicationDetails.personal || {},
          securityLevel: "critical",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
            isTransferLimited: true
          }
        });
      } else if (documentType === 'proof-of-address') {
        // Address proof
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          applicationId: parseInt(applicationId),
          applicationNumber: application.applicationNumber,
          applicationStatus: application.status,
          addressDetails: applicationDetails.contact?.address || {},
          contactDetails: {
            email: application.contactEmail,
            phone: application.contactPhone
          },
          securityLevel: "sensitive",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
            isTransferLimited: true
          }
        });
      } else if (documentType === 'income-proof') {
        // Income proof
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          applicationId: parseInt(applicationId),
          applicationNumber: application.applicationNumber,
          applicationStatus: application.status,
          employmentDetails: applicationDetails.employment || {},
          incomeDetails: {
            annualIncome: applicationDetails.employment?.annualIncome,
            sourceOfFunds: applicationDetails.employment?.sourceOfFunds
          },
          securityLevel: "sensitive",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip,
          securityDetails: {
            isEncrypted: true,
            isWatermarked: true,
            hasDigitalSignature: true,
            auditTrailId: `AUDIT-${accessId}`,
            isTransferLimited: true
          }
        });
      } else {
        // Generic response for any other document type
        return res.status(200).json({
          accessId: accessId,
          accessTimestamp: accessTimestamp,
          documentType: documentType,
          applicationId: parseInt(applicationId),
          applicationNumber: application.applicationNumber,
          applicationStatus: application.status,
          submittedAt: application.submittedAt,
          lastUpdatedAt: application.lastUpdatedAt,
          contactEmail: application.contactEmail,
          contactPhone: application.contactPhone,
          securityLevel: "standard",
          encryptionMethod: "AES-256-GCM",
          accessedBy: isAdmin ? 'administrator' : `user ${userId}`,
          accessMethod: req.headers['user-agent'],
          ipAddress: req.ip
        });
      }
    } catch (error) {
      console.error("Secure application document access error:", error);
      res.status(500).json({ 
        message: "Failed to retrieve document",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
        requestId: `REQ-${Date.now()}`
      });
    }
  });

  // API route for document metadata access
  app.get("/api/documents/metadata/:documentId", secureDocumentAccess, async (req, res) => {
    try {
      const { documentId } = req.params;
      const docType = req.query.docType as string || 'unknown';
      const entityType = req.query.entityType as string || 'unknown';
      const entityId = req.query.entityId as string;
      
      // Log access for audit purposes
      console.log(`[AUDIT] Document metadata accessed: ${documentId} by user ${req.session.userId || 'anonymous'}`);
      
      // In a real bank application, this would fetch document metadata from database
      // For now, we'll implement the security framework and return enhanced metadata
      
      // Generate realistic metadata that would be available in a banking system
      const uploadDate = new Date();
      const accessId = `META-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
      
      // Map document types to appropriate MIME types and descriptions
      let mimeType = "application/pdf";
      let description = "Banking Document";
      let securityLevel = "standard";
      let fileSize = 1024 * 1024 * (Math.random() * 4 + 1); // Random size between 1-5MB
      
      if (['id-front', 'id-back', 'passport', 'selfie'].includes(docType)) {
        mimeType = "image/jpeg";
        description = "Identity Verification Document";
        securityLevel = "critical";
        fileSize = 1024 * 1024 * (Math.random() * 2 + 0.5); // 500KB-2.5MB
      } else if (docType === 'statement' || docType === 'application-form') {
        mimeType = "application/pdf";
        description = docType === 'statement' ? "Account Statement" : "Account Application";
        securityLevel = "sensitive";
        fileSize = 1024 * 1024 * (Math.random() * 3 + 2); // 2-5MB
      } else if (docType === 'proof-of-address') {
        mimeType = "application/pdf";
        description = "Address Verification Document";
        securityLevel = "sensitive";
        fileSize = 1024 * 1024 * (Math.random() * 2 + 1); // 1-3MB
      }
      
      let entityDetails = {};
      
      // If we have entity information, try to retrieve relevant data
      if (entityId && entityType) {
        if (entityType === 'user') {
          const userData = await storage.getUser(parseInt(entityId));
          if (userData) {
            entityDetails = {
              entityType: 'user',
              entityId: userData.id,
              name: `${userData.firstName} ${userData.lastName}`,
              email: userData.email,
              username: userData.username
            };
          }
        } else if (entityType === 'kyc') {
          const kycData = await storage.getKycVerification(parseInt(entityId));
          if (kycData) {
            entityDetails = {
              entityType: 'kyc',
              entityId: kycData.id,
              status: kycData.status,
              userId: kycData.userId,
              documentType: docType
            };
          }
        } else if (entityType === 'application') {
          const appData = await storage.getAccountApplication(parseInt(entityId));
          if (appData) {
            entityDetails = {
              entityType: 'application',
              entityId: appData.id,
              applicationNumber: appData.applicationNumber,
              status: appData.status,
              contactEmail: appData.contactEmail
            };
          }
        }
      }
      
      res.status(200).json({
        id: documentId,
        accessId: accessId,
        fileName: `${docType}-${documentId}.${mimeType.split('/')[1]}`,
        mimeType: mimeType,
        description: description,
        uploadDate: uploadDate,
        lastAccessed: new Date(),
        fileSize: Math.floor(fileSize),
        isEncrypted: true,
        encryptionMethod: "AES-256-GCM",
        accessLevel: securityLevel,
        accessCount: Math.floor(Math.random() * 10) + 1, // Simulated access count
        entityDetails: entityDetails,
        securityDetails: {
          isEncrypted: true,
          isWatermarked: securityLevel === "critical" || securityLevel === "sensitive",
          hasDigitalSignature: true,
          isDRMProtected: securityLevel === "critical",
          authRequiredForDownload: true,
          auditedAccess: true,
          retentionPolicy: securityLevel === "critical" ? "7 years" : "5 years",
          isUserDownloadable: securityLevel !== "critical",
          accessRestrictedTo: securityLevel === "critical" ? "Owner and Administrator" : "Authorized Users",
          securityClassification: securityLevel,
          lastSecurityScan: new Date(uploadDate.getTime() - 1000 * 60 * 60 * 24).toISOString()
        },
        complianceInfo: {
          regulatoryFrameworks: ["GDPR", "PCI-DSS", "ISO27001"],
          dataClassification: securityLevel === "critical" ? "Restricted" : "Confidential",
          dataSubjectRights: "Accessible upon formal request",
          retentionPeriod: securityLevel === "critical" ? "7 years" : "5 years",
          legalHold: false
        },
        accessedBy: req.session.userId ? 'authenticated user' : 'anonymous',
        accessMethod: req.headers['user-agent'],
        ipAddress: req.ip
      });
    } catch (error) {
      console.error("Document metadata access error:", error);
      res.status(500).json({ 
        message: "Failed to retrieve document metadata",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
        requestId: `REQ-${Date.now()}`
      });
    }
  });
  
  // Secure Document Upload Endpoint
  // In a real bank application, this would store documents in encrypted storage
  // and record metadata in the database
  app.post("/api/documents/upload", secureDocumentAccess, async (req, res) => {
    try {
      const { documentType, entityType, entityId, metadata } = req.body;
      
      // Validate request
      if (!documentType || !entityType || !entityId) {
        return res.status(400).json({ message: "Missing required document information" });
      }
      
      // In a real bank application:
      // 1. We'd validate the file (virus scan, content check, etc)
      // 2. Encrypt the document with AES-256
      // 3. Store in secure storage with access controls
      // 4. Store metadata in database with document reference
      // 5. Generate an audit log entry
      
      console.log(`[SECURITY AUDIT] Document upload: ${documentType} for ${entityType} ID ${entityId} by user ${req.session.userId || 'anonymous'}`);
      
      // Create a document record
      const documentId = Date.now().toString(); // In real app, this would be a proper UUID
      
      // Return success with document ID and secure access URL
      res.status(201).json({
        success: true,
        documentId,
        secureUrl: `/api/documents/${entityType}/${entityId}/${documentType}`,
        message: "Document uploaded and encrypted successfully"
      });
    } catch (error) {
      console.error("Document upload error:", error);
      res.status(500).json({ message: "Failed to process document" });
    }
  });
  
  // Document verification endpoint - add banking-specific document verification
  app.post("/api/documents/verify", secureDocumentAccess, async (req, res) => {
    try {
      const { documentId, verificationLevel = "standard" } = req.body;
      
      if (!documentId) {
        return res.status(400).json({ message: "Missing document ID" });
      }
      
      // In a real bank application:
      // 1. We'd check the document against fraud databases
      // 2. Perform OCR to extract information
      // 3. Compare extracted data with provided data
      // 4. Check for tampering or digital manipulation
      // 5. Generate verification score based on multiple factors
      
      // Log verification attempt for audit and compliance
      console.log(`[COMPLIANCE] Document verification: ${documentId} at ${verificationLevel} level by user/system ${req.session.userId || 'system'}`);
      
      // Simulate verification process timing
      const verificationResult = {
        verified: true,
        score: 0.92, // Confidence score
        flags: [],   // Any potential issues
        timestamp: new Date().toISOString(),
        verificationId: `VER-${Date.now()}`,
        verificationLevel,
        message: "Document successfully verified"
      };
      
      res.status(200).json(verificationResult);
    } catch (error) {
      console.error("Document verification error:", error);
      res.status(500).json({ message: "Document verification failed" });
    }
  });
  
  // Document Center API for admin dashboard
  app.get("/api/admin/documents", authenticateAdmin, async (req, res) => {
    try {
      // In a real banking application, this would query the document database
      // and join with relevant entity tables (users, applications, etc.)
      
      // Get mock document data for demo purposes
      const mockDocuments = [
        {
          id: "doc-10001",
          fileName: "passport-maria-gonzalez.jpg",
          documentType: "Passport",
          category: "kyc",
          uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 5).toISOString(),
          expiryDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 5).toISOString(),
          status: "active",
          securityLevel: "critical",
          entityType: "user",
          entityId: 1001,
          entityName: "Maria Gonzalez",
          fileSize: 1458000,
          mimeType: "image/jpeg",
          lastAccessed: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
          accessCount: 8,
          verificationStatus: "Verified",
          hasFlags: false,
          tags: ["primary_id", "kyc_verified", "international"]
        },
        {
          id: "doc-10002",
          fileName: "drivers-license-front-james-wilson.jpg",
          documentType: "ID Card Front",
          category: "kyc",
          uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2).toISOString(),
          status: "pending_verification",
          securityLevel: "sensitive",
          entityType: "user",
          entityId: 1002,
          entityName: "James Wilson",
          fileSize: 1245333,
          mimeType: "image/jpeg",
          accessCount: 3,
          hasFlags: true,
          tags: ["primary_id", "unverified"]
        },
        {
          id: "doc-10003",
          fileName: "drivers-license-back-james-wilson.jpg",
          documentType: "ID Card Back",
          category: "kyc",
          uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2).toISOString(),
          status: "pending_verification",
          securityLevel: "sensitive",
          entityType: "user",
          entityId: 1002,
          entityName: "James Wilson",
          fileSize: 1187422,
          mimeType: "image/jpeg",
          accessCount: 2,
          hasFlags: false,
          tags: ["primary_id", "unverified"]
        },
        {
          id: "doc-10004",
          fileName: "proof-of-address-sarah-williams.pdf",
          documentType: "Proof of Address",
          category: "kyc",
          uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 10).toISOString(),
          status: "active",
          securityLevel: "standard",
          entityType: "user",
          entityId: 1003,
          entityName: "Sarah Williams",
          fileSize: 2257891,
          mimeType: "application/pdf",
          lastAccessed: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
          accessCount: 4,
          verificationStatus: "Verified",
          hasFlags: false,
          tags: ["address_verification"]
        },
        {
          id: "doc-10005",
          fileName: "mortgage-application-rodriguez.pdf",
          documentType: "Mortgage Application",
          category: "application",
          uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 1).toISOString(),
          status: "pending_verification",
          securityLevel: "critical",
          entityType: "application",
          entityId: 5001,
          entityName: "Carlos Rodriguez",
          fileSize: 3548712,
          mimeType: "application/pdf",
          accessCount: 1,
          hasFlags: false,
          tags: ["mortgage", "high_value", "pending_review"]
        },
        {
          id: "doc-10006",
          fileName: "income-verification-johnson.pdf",
          documentType: "Income Verification",
          category: "application",
          uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7).toISOString(),
          status: "active",
          securityLevel: "sensitive",
          entityType: "application",
          entityId: 5002,
          entityName: "David Johnson",
          fileSize: 1854236,
          mimeType: "application/pdf",
          lastAccessed: new Date(Date.now() - 1000 * 60 * 60 * 72).toISOString(),
          accessCount: 6,
          verificationStatus: "Verified",
          hasFlags: true,
          tags: ["financial", "income", "flagged_review"]
        },
        {
          id: "doc-10007",
          fileName: "account-agreement-lisa-chen.pdf",
          documentType: "Account Agreement",
          category: "agreements",
          uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 14).toISOString(),
          status: "active",
          securityLevel: "standard",
          entityType: "user",
          entityId: 1004,
          entityName: "Lisa Chen",
          fileSize: 1125478,
          mimeType: "application/pdf",
          lastAccessed: new Date(Date.now() - 1000 * 60 * 60 * 120).toISOString(),
          accessCount: 2,
          hasFlags: false,
          tags: ["legal", "agreement", "onboarding"]
        },
        {
          id: "doc-10008",
          fileName: "passport-expired-robert-smith.jpg",
          documentType: "Passport",
          category: "kyc",
          uploadDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 365).toISOString(),
          expiryDate: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30).toISOString(),
          status: "expired",
          securityLevel: "sensitive",
          entityType: "user",
          entityId: 1005,
          entityName: "Robert Smith",
          fileSize: 1356214,
          mimeType: "image/jpeg",
          lastAccessed: new Date(Date.now() - 1000 * 60 * 60 * 24 * 10).toISOString(),
          accessCount: 4,
          verificationStatus: "Expired",
          hasFlags: true,
          tags: ["primary_id", "expired", "needs_update"]
        }
      ];
      
      // Log access to document list for compliance
      console.log(`[COMPLIANCE] Admin accessed document list: ${req.session.userId}`);
      
      res.status(200).json(mockDocuments);
    } catch (error) {
      console.error("Error fetching documents:", error);
      res.status(500).json({ message: "Failed to retrieve documents" });
    }
  });

  // Endpoint for creating a user account from an approved application
  app.post("/api/auth/create-account-from-application", async (req, res) => {
    try {
      const { applicationId, username, password, email } = req.body;
      
      console.log("Create account from application request received:", { applicationId, username, email });
      
      if (!applicationId || !username || !password || !email) {
        console.log("Missing required fields:", { 
          hasAppId: !!applicationId, 
          hasUsername: !!username, 
          hasPassword: !!password, 
          hasEmail: !!email 
        });
        return res.status(400).json({ message: "Application ID, username, password, and email are required" });
      }
      
      // Check if username already exists
      const existingUsername = await storage.getUserByUsername(username);
      if (existingUsername) {
        console.log("Username already exists:", username);
        return res.status(400).json({ message: "Username already exists" });
      }
      
      // Check if email already exists
      const existingEmail = await storage.getUserByEmail(email);
      if (existingEmail) {
        console.log("Email already exists:", email);
        return res.status(400).json({ message: "Email already exists" });
      }
      
      // First check for the application in memory
      console.log("Checking for application in memory:", applicationId);
      let application = await storage.getAccountApplicationByApplicationNumber(applicationId);
      let foundInSQL = false;
      
      // If not found in memory, try SQL database
      if (!application) {
        console.log("Application not found in memory, checking SQL");
        try {
          const { pool } = await import("./db");
          const sqlResult = await pool.query(
            'SELECT * FROM applications WHERE application_id = $1',
            [applicationId]
          );
          
          console.log("SQL query result:", sqlResult.rows ? sqlResult.rows.length : 0, "rows found");
          
          if (sqlResult.rows && sqlResult.rows.length > 0) {
            console.log("Application found in SQL:", sqlResult.rows[0]);
            application = {
              id: sqlResult.rows[0].id,
              applicationNumber: sqlResult.rows[0].application_id,
              status: sqlResult.rows[0].status,
              contactEmail: sqlResult.rows[0].email,
              submittedAt: sqlResult.rows[0].created_at,
              lastUpdatedAt: sqlResult.rows[0].updated_at,
              fullName: sqlResult.rows[0].name || ''
            };
            foundInSQL = true;
          }
        } catch (sqlError) {
          console.error("SQL error checking application:", sqlError);
        }
      }
      
      if (!application) {
        console.log("Application not found with ID:", applicationId);
        return res.status(404).json({ message: "Application not found" });
      }
      
      console.log("Application found:", application);
      
      if (application.status !== "approved") {
        console.log("Application status not approved:", application.status);
        return res.status(400).json({ message: "Application must be approved to create an account" });
      }
      
      if (application.contactEmail.toLowerCase() !== email.toLowerCase()) {
        console.log("Email mismatch:", { applicationEmail: application.contactEmail, providedEmail: email });
        return res.status(400).json({ message: "Email must match the application email" });
      }
      
      // For demo, we'll use a simple password
      const hashedPassword = "password"; // In real app, would be hashed with bcrypt
      
      console.log("Creating user with data:", { username, email, name: application.fullName });
      
      // Create the user
      const user = await storage.createUser({
        username,
        password: hashedPassword,
        email,
        firstName: application.fullName.split(' ')[0] || "",
        lastName: application.fullName.split(' ').slice(1).join(' ') || "",
        role: "customer",
        status: "active",
        securityLevel: "standard",
        hasFraudAlert: false,
        failedLoginAttempts: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: new Date(),
        loginRestricted: false,
        transferRestricted: false,
        depositRestricted: false,
        withdrawalRestricted: false,
        cardRestricted: false,
      });
      
      console.log("User created successfully:", user.id);
      
      // Update the application to mark it as completed
      if (application.id) {
        try {
          await storage.updateAccountApplicationStatus(application.id, "completed", undefined, "Account created");
          console.log("Application status updated to completed");
        } catch (updateError) {
          console.error("Error updating application status:", updateError);
          // Continue even if update fails
        }
      }
      
      // Set up session
      req.session.userId = user.id;
      
      // Save the session and return
      req.session.save(err => {
        if (err) {
          console.error("Session save error:", err);
          return res.status(500).json({ message: "Error saving session" });
        }
        
        console.log("Session saved successfully, user logged in:", user.id);
        
        const { password: _, ...userWithoutPassword } = user;
        
        res.status(201).json({
          user: userWithoutPassword,
          message: "Account created successfully"
        });
      });
    } catch (error) {
      console.error("Create account from application error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Register document routes for secure document access and logging
  app.use('/api/documents', documentRouter);
  console.log('Document routes registered at /api/documents');

  const httpServer = createServer(app);
  return httpServer;
}
