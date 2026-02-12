/**
 * Email Verification Utilities
 * Handles email verification token generation and validation
 */

const crypto = require('crypto');

/**
 * Generate a random verification token
 * @returns {string} - Verification token
 */
function generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate verification URL
 * @param {string} baseUrl - Base URL of the application
 * @param {string} token - Verification token
 * @returns {string} - Complete verification URL
 */
function generateVerificationUrl(baseUrl, token) {
    return `${baseUrl}/verify-email?token=${token}`;
}

/**
 * Check if verification token is expired
 * @param {Date} createdAt - Token creation timestamp
 * @param {number} expiryHours - Expiry duration in hours (default 24)
 * @returns {boolean}
 */
function isTokenExpired(createdAt, expiryHours = 24) {
    const now = new Date();
    const tokenAge = (now - new Date(createdAt)) / (1000 * 60 * 60); // in hours
    return tokenAge > expiryHours;
}

/**
 * Simulate sending verification email
 * In production, this would integrate with an email service (SendGrid, AWS SES, etc.)
 * @param {string} email - User email
 * @param {string} verificationUrl - Verification URL
 * @returns {boolean} - Success status
 */
function sendVerificationEmail(email, verificationUrl) {
    // Simulate email sending
    console.log('\n=================================');
    console.log('📧 EMAIL VERIFICATION');
    console.log('=================================');
    console.log(`To: ${email}`);
    console.log(`Subject: Verify Your Email Address`);
    console.log('\nHi there,\n');
    console.log('Thank you for registering! Please verify your email address by clicking the link below:\n');
    console.log(`${verificationUrl}\n`);
    console.log('This link will expire in 24 hours.');
    console.log('\nIf you did not create this account, please ignore this email.\n');
    console.log('=================================\n');
    
    return true; // In production, return actual send status
}

/**
 * Simulate sending welcome email after verification
 * @param {string} email - User email
 * @param {string} username - Username
 * @returns {boolean}
 */
function sendWelcomeEmail(email, username) {
    console.log('\n=================================');
    console.log('📧 WELCOME EMAIL');
    console.log('=================================');
    console.log(`To: ${email}`);
    console.log(`Subject: Welcome to Secure Voting App!`);
    console.log(`\nHi ${username},\n`);
    console.log('Your email has been verified successfully!');
    console.log('You now have full access to all features.\n');
    console.log('=================================\n');
    
    return true;
}

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean}
 */
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

module.exports = {
    generateVerificationToken,
    generateVerificationUrl,
    isTokenExpired,
    sendVerificationEmail,
    sendWelcomeEmail,
    isValidEmail
};
