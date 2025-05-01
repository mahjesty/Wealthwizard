import { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { storage } from './storage';
import crypto from 'crypto';
import { Request, Response } from 'express';

// The name of your application, displayed during the biometric prompt
const RP_NAME = 'Fortis Capital';

// The ID for your application (must be a valid domain string)
const RP_ID = process.env.NODE_ENV === 'production' 
  ? process.env.APP_DOMAIN || 'fortiscapital.com'
  : 'localhost';

// The origin for your application (protocol + domain, must start with https:// in production)
const ORIGIN = process.env.NODE_ENV === 'production'
  ? `https://${process.env.APP_DOMAIN || 'fortiscapital.com'}`
  : 'http://localhost:5000';

// Store challenges temporarily for verification (in a real app, use a database)
const challengeStorage = new Map<string, string>();

/**
 * Generate and store a new authentication challenge
 */
function generateChallenge(userId: string): string {
  const challenge = crypto.randomBytes(32).toString('base64url');
  challengeStorage.set(userId, challenge);
  return challenge;
}

/**
 * Verify a stored challenge for a user
 */
function verifyChallenge(userId: string, challenge: string): boolean {
  const storedChallenge = challengeStorage.get(userId);
  if (!storedChallenge || storedChallenge !== challenge) {
    return false;
  }
  challengeStorage.delete(userId);
  return true;
}

/**
 * Generate registration options for a user
 */
export async function registerOptions(req: Request, res: Response) {
  try {
    const { username, userId } = req.body;
    
    if (!username || !userId) {
      return res.status(400).send('Username and userId are required');
    }
    
    // Check if user exists
    const user = await storage.getUser(Number(userId));
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    // Generate a new challenge for this registration
    const challenge = generateChallenge(userId);
    
    // Check if there are any existing credentials for this user
    const existingCredentials = await storage.getWebauthnCredentialsByUserId(Number(userId))
    
    // Generate registration options
    const options = generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: Buffer.from(userId.toString(), 'utf-8'),
      userName: username,
      userDisplayName: `${user.firstName} ${user.lastName}`,
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        requireResidentKey: false,
      },
      challenge,
      excludeCredentials: existingCredentials.map(credential => ({
        id: credential.credentialId,
        type: 'public-key',
        transports: credential.transports ? credential.transports.split(',') : ['internal'],
      })),
    });
    
    // Store these options temporarily to verify them later
    // In a real app, save to session or database
    const optionsResult = await options;
    req.session.currentChallenge = optionsResult.challenge;
    
    res.json(optionsResult);
  } catch (error) {
    console.error('Error in registerOptions:', error);
    res.status(500).send('Server error during registration setup');
  }
}

/**
 * Verify a registration response
 */
export async function registerVerification(req: Request, res: Response) {
  try {
    const { id, rawId, response, type } = req.body;
    
    if (!id || !rawId || !response || !type) {
      return res.status(400).send('Missing required fields');
    }
    
    // Get the expected challenge from session
    const expectedChallenge = req.session.currentChallenge;
    if (!expectedChallenge) {
      return res.status(400).send('No challenge found in session');
    }
    
    // Verify the registration response
    const verification = await verifyRegistrationResponse({
      credential: {
        id,
        rawId,
        response,
        type,
      },
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
    
    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).send('Registration verification failed');
    }
    
    // Get verified registration info
    const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;
    
    // Store credential information in database for the user
    const credentialData = {
      userId: Number(req.session.userId),
      credentialId: Buffer.from(credentialID).toString('base64url'),
      publicKey: Buffer.from(credentialPublicKey).toString('base64'),
      counter,
      transports: response.transports ? response.transports.join(',') : null,
      attestationFormat: verification.registrationInfo.fmt,
    };
    
    console.log(`Registering credential for user ${req.session.userId} with ID: ${credentialData.credentialId}`);
    
    await storage.createWebauthnCredential(credentialData);
    
    // Clear the challenge from session
    delete req.session.currentChallenge;
    
    res.json({
      verified: true,
      credentialId: Buffer.from(credentialID).toString('base64url'),
    });
  } catch (error) {
    console.error('Error in registerVerification:', error);
    res.status(500).send('Server error during registration verification');
  }
}

/**
 * Generate authentication options
 */
export async function loginOptions(req: Request, res: Response) {
  try {
    // Optional: If username is provided, only allow credentials for that user
    const { username } = req.body;
    let allowCredentials = [];
    
    if (username) {
      const user = await storage.getUserByUsername(username);
      if (user) {
        const userCredentials = await storage.getWebauthnCredentialsByUserId(user.id);
        allowCredentials = userCredentials.map(credential => ({
          id: credential.credentialId,
          type: 'public-key' as const,
          transports: credential.transports ? credential.transports.split(',') : ['internal'],
        }));
      }
    }
    
    // Generate a challenge for this authentication
    const challenge = crypto.randomBytes(32).toString('base64url');
    
    // Store the challenge in session
    req.session.currentChallenge = challenge;
    
    // Generate authentication options
    const options = generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'required',
      challenge,
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
    });
    
    res.json(options);
  } catch (error) {
    console.error('Error in loginOptions:', error);
    res.status(500).send('Server error during authentication setup');
  }
}

/**
 * Verify an authentication response
 */
export async function loginVerification(req: Request, res: Response) {
  try {
    const { id, rawId, response, type } = req.body;
    
    if (!id || !rawId || !response || !type) {
      return res.status(400).send('Missing required fields');
    }
    
    // Get the expected challenge from session
    const expectedChallenge = req.session.currentChallenge;
    if (!expectedChallenge) {
      return res.status(400).send('No challenge found in session');
    }
    
    // Lookup the credential in database
    const credential = await storage.getWebauthnCredentialByCredentialId(id);
    if (!credential) {
      console.error(`Credential with ID ${id} not found in database`);
      return res.status(400).send('Unknown credential');
    }
    
    console.log(`Found credential ${id} for user ${credential.userId}`);
    // Store user ID in session for later use in biometric authentication
    if (!req.session.userId) {
      req.session.userId = credential.userId;
    }
    
    // Verify the authentication response
    const verification = await verifyAuthenticationResponse({
      credential: {
        id,
        rawId,
        response,
        type,
      },
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialPublicKey: Buffer.from(credential.publicKey, 'base64'),
        credentialID: Buffer.from(credential.credentialId, 'base64url'),
        counter: credential.counter || 0,
      },
    });
    
    if (!verification.verified) {
      return res.status(400).send('Authentication verification failed');
    }
    
    // Update the credential counter in the database
    if (verification.authenticationInfo) {
      await storage.updateWebauthnCredential(
        credential.id, 
        { counter: verification.authenticationInfo.newCounter }
      );
    }
    
    // Get the user from database
    const user = await storage.getUser(credential.userId);
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    // Login the user
    req.session.userId = user.id;
    
    // Clear the challenge
    delete req.session.currentChallenge;
    
    res.json({
      verified: true,
      username: user.username,
    });
  } catch (error) {
    console.error('Error in loginVerification:', error);
    res.status(500).send('Server error during authentication verification');
  }
}

/**
 * Remove a credential
 */
export async function removeCredential(req: Request, res: Response) {
  try {
    const { credentialId } = req.body;
    
    if (!credentialId) {
      return res.status(400).send('Missing credentialId');
    }
    
    // Only allow authenticated users to remove credentials
    if (!req.session.userId) {
      return res.status(401).send('Unauthorized');
    }
    
    // Find the credential
    const credential = await storage.getWebauthnCredentialByCredentialId(credentialId);
    if (!credential) {
      return res.status(404).send('Credential not found');
    }
    
    // Verify this credential belongs to the authenticated user
    if (credential.userId !== req.session.userId) {
      return res.status(403).send('Unauthorized: This credential does not belong to you');
    }
    
    // Remove the credential
    const success = await storage.deleteWebauthnCredential(credential.id);
    
    res.json({ success });
  } catch (error) {
    console.error('Error in removeCredential:', error);
    res.status(500).send('Server error during credential removal');
  }
}