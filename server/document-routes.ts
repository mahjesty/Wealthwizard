import { Router, Response } from "express";
import type { Request as ExpressRequest } from "express";

// Extend the Request type to include authentication and session properties
interface Request extends ExpressRequest {
  user?: any;
  isAuthenticated?: () => boolean;
  sessionID?: string;
  session: any;
  logId?: number;
}
import { v4 as uuidv4 } from "uuid";
import { storage } from "./storage";
import { insertDocumentAccessLogSchema } from "@shared/schema";
import { z } from "zod";
import crypto from "crypto";
import path from "path";
import fs from "fs";

const router = Router();

// Middleware to secure document access with proper authentication and logging
const secureDocumentAccess = async (req: Request, res: Response, next: Function) => {
  try {
    // Extract tracking and access information
    const { accessId = uuidv4() } = req.query;
    const documentPath = req.path;
    const documentType = req.query.docType?.toString() || path.basename(documentPath).split('.')[0];
    const entityType = req.query.entityType?.toString() || "document";
    const entityId = parseInt(req.query.entityId?.toString() || "0", 10);
    const isAdmin = req.query.admin === "true" || (req.user?.role === "admin");
    const purpose = req.query.purpose?.toString() || null;
    
    // Extract browser and request information for audit logging
    const ipAddress = req.ip || req.socket.remoteAddress || null;
    const userAgent = req.get("User-Agent") || null;
    
    // Reject access if not authenticated
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      return res.status(401).json({
        error: "UNAUTHORIZED",
        message: "Authentication required to access documents"
      });
    }
    
    // Additional security check based on entityType and access permissions
    let hasAccess = false;
    
    // Set access permissions based on document and user relationship
    switch (entityType) {
      case "user":
        // User can access their own documents, admins can access any user document
        hasAccess = (req.user.id === entityId) || (req.user.role === "admin");
        break;
      
      case "account":
        // Check if the account belongs to the user or if admin
        const account = await storage.getAccount(entityId);
        hasAccess = account ? (account.userId === req.user.id) || (req.user.role === "admin") : false;
        break;
      
      case "application":
        // Check if the application belongs to the user, is related to them, or if admin
        const application = await storage.getAccountApplication(entityId);
        hasAccess = application ? 
          (application.userId === req.user.id) || 
          (application.email === req.user.email) || 
          (req.user.role === "admin") : false;
        break;
      
      case "kyc":
        // Check if the KYC belongs to the user or if admin
        const kycVerification = await storage.getKycVerification(entityId);
        hasAccess = kycVerification ? 
          (kycVerification.userId === req.user.id) || 
          (req.user.role === "admin") : false;
        break;
      
      case "document":
        // Generic documents are accessible based on user role
        hasAccess = isAdmin || (req.user.role === "admin");
        break;
        
      default:
        // Default to admin-only for unknown entity types
        hasAccess = (req.user.role === "admin");
    }
    
    // If no access, reject with 403
    if (!hasAccess) {
      // Log the access attempt for security auditing (even failed attempts)
      await storage.createDocumentAccessLog({
        accessId: accessId.toString(),
        documentPath,
        documentType,
        entityType,
        entityId,
        accessedBy: req.user.id,
        isAdminAccess: isAdmin,
        accessStatus: "DENIED",
        ipAddress,
        userAgent,
        browserInfo: userAgent, // Duplicate for better search
        accessMethod: req.method,
        sessionId: req.sessionID,
        encryptionStatus: "N/A",
        additionalInfo: JSON.stringify({
          reason: "PERMISSION_DENIED",
          timestamp: new Date().toISOString(),
          requestPath: req.path,
          queryParams: req.query
        })
      });
      
      return res.status(403).json({
        error: "FORBIDDEN",
        message: "You do not have permission to access this document"
      });
    }
    
    // Log successful document access
    const logEntry = await storage.createDocumentAccessLog({
      accessId: accessId.toString(),
      documentPath,
      documentType,
      entityType,
      entityId,
      accessedBy: req.user.id,
      isAdminAccess: isAdmin,
      accessStatus: "GRANTED",
      ipAddress,
      userAgent,
      browserInfo: userAgent,
      accessMethod: req.method,
      sessionId: req.sessionID,
      purpose,
      encryptionStatus: "encrypted",
      additionalInfo: JSON.stringify({
        reason: "AUTHENTICATED_ACCESS",
        timestamp: new Date().toISOString(),
        deviceInfo: req.headers["sec-ch-ua"] || null
      })
    });
    
    // Add the log ID to the request for further processing
    req.logId = logEntry.id;
    
    // Access granted, continue to the document handler
    next();
  } catch (error) {
    console.error("Error in document access middleware:", error);
    res.status(500).json({
      error: "SERVER_ERROR",
      message: "Error processing document access request"
    });
  }
};

// Register routes
router.use(secureDocumentAccess);

// Log document access (from client-side)
router.post("/access-log", async (req: Request, res: Response) => {
  try {
    // Validate the log data using the schema
    const validationResult = insertDocumentAccessLogSchema.safeParse(req.body);
    
    if (!validationResult.success) {
      return res.status(400).json({
        error: "VALIDATION_ERROR",
        message: "Invalid document access log data",
        details: validationResult.error.errors
      });
    }
    
    // Create default values for missing fields
    const logData = {
      ...validationResult.data,
      accessId: req.body.accessId || uuidv4(),
      accessedBy: req.body.accessedBy || (req.user?.id || 0),
      isAdminAccess: req.body.isAdminAccess || (req.user?.role === "admin"),
      ipAddress: req.ip || req.socket.remoteAddress || null,
      userAgent: req.get("User-Agent") || null,
      accessStatus: "LOGGED_FROM_CLIENT",
      sessionId: req.sessionID,
    };
    
    // Create the log entry
    const logEntry = await storage.createDocumentAccessLog(logData);
    
    res.status(201).json({
      success: true,
      logId: logEntry.id,
      accessId: logEntry.accessId,
      message: "Document access log created successfully"
    });
  } catch (error) {
    console.error("Error logging document access:", error);
    res.status(500).json({
      error: "SERVER_ERROR",
      message: "Failed to log document access"
    });
  }
});

// Get document access logs for a specific entity
router.get("/logs/:entityType/:entityId", async (req: Request, res: Response) => {
  try {
    const { entityType, entityId } = req.params;
    
    // Only admins can access logs
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        error: "FORBIDDEN",
        message: "Only administrators can access document logs"
      });
    }
    
    // Get the logs from storage
    const logs = await storage.getDocumentAccessLogsByEntityId(
      entityType,
      parseInt(entityId, 10)
    );
    
    res.json({
      success: true,
      count: logs.length,
      logs
    });
  } catch (error) {
    console.error("Error retrieving document access logs:", error);
    res.status(500).json({
      error: "SERVER_ERROR",
      message: "Failed to retrieve document access logs"
    });
  }
});

// Get document metadata
router.get("/metadata/:documentId", async (req: Request, res: Response) => {
  try {
    const { documentId } = req.params;
    const entityType = req.query.entityType?.toString() || "document";
    const entityId = parseInt(req.query.entityId?.toString() || "0", 10);
    
    // Here you would typically query a document metadata store
    // For now we'll return simulated metadata
    
    // Generate a realistic upload date (within the last 90 days)
    const randomDaysAgo = Math.floor(Math.random() * 90);
    const uploadDate = new Date();
    uploadDate.setDate(uploadDate.getDate() - randomDaysAgo);
    
    // Generate a realistic file size (between 100KB and 10MB)
    const fileSize = Math.floor(Math.random() * 10000000) + 100000;
    
    // Return document metadata
    res.json({
      documentId,
      documentType: req.query.docType?.toString() || documentId,
      fileName: `${documentId.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`,
      fileSize,
      uploadDate,
      mimeType: "application/pdf",
      securityLevel: "confidential",
      securityDetails: {
        isEncrypted: true,
        encryptionMethod: "AES-256-GCM",
        accessControl: "role-based"
      },
      lastViewed: new Date(),
      viewCount: Math.floor(Math.random() * 20), // Simulated view count
      metadata: {
        entityType,
        entityId,
        isArchived: false,
        retentionPeriod: "7-years",
        classifications: ["financial", "personal", "identification"]
      }
    });
  } catch (error) {
    console.error("Error retrieving document metadata:", error);
    res.status(500).json({
      error: "SERVER_ERROR",
      message: "Failed to retrieve document metadata"
    });
  }
});

// Get KYC verification document
router.get("/kyc/:verificationId/:documentType", async (req: Request, res: Response) => {
  try {
    const { verificationId, documentType } = req.params;
    const idNum = parseInt(verificationId, 10);
    
    // Get the verification record
    const verification = await storage.getKycVerification(idNum);
    
    if (!verification) {
      return res.status(404).json({
        error: "NOT_FOUND",
        message: "KYC verification not found"
      });
    }
    
    // Check permissions (owner or admin)
    if (verification.userId !== req.user?.id && req.user?.role !== "admin") {
      return res.status(403).json({
        error: "FORBIDDEN",
        message: "You do not have permission to access this document"
      });
    }
    
    // Map document type to document field
    let documentUrl: string | null = null;
    
    switch (documentType) {
      case "id-front":
        documentUrl = verification.documentFront;
        break;
      case "id-back":
        documentUrl = verification.documentBack;
        break;
      case "selfie":
        documentUrl = verification.selfie;
        break;
      default:
        return res.status(404).json({
          error: "NOT_FOUND",
          message: "Document type not found"
        });
    }
    
    if (!documentUrl) {
      return res.status(404).json({
        error: "NOT_FOUND",
        message: "Document not found"
      });
    }
    
    // In a real application, here you would:
    // 1. Retrieve the encrypted document from storage
    // 2. Decrypt it using the appropriate key
    // 3. Return the document with appropriate headers
    
    // For this example, we'll just return a JSON response
    res.json({
      success: true,
      message: "Document access placeholder. In production, the actual document would be returned.",
      documentType,
      verificationId,
      // In a real app, you would stream the actual document
      documentPlaceholder: "This is a placeholder for the actual document content"
    });
  } catch (error) {
    console.error("Error retrieving KYC document:", error);
    res.status(500).json({
      error: "SERVER_ERROR",
      message: "Failed to retrieve KYC document"
    });
  }
});

export default router;