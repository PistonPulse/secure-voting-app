const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');

// Import RBAC and Security modules
const { ROLES, PERMISSIONS, getDefaultRole } = require('./rbac-config');
const { AuditLogger, AUDIT_EVENTS } = require('./audit-logger');
const {
    requirePermission,
    requireRole,
    requireEmailVerification,
    attachUserRole,
    secureRoute
} = require('./security-middleware');
const {
    generateVerificationToken,
    generateVerificationUrl,
    isTokenExpired,
    sendVerificationEmail,
    sendWelcomeEmail,
    isValidEmail
} = require('./email-verification');

const app = express();
const PORT = process.env.PORT || 3000;

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
}

// Initialize audit logger
const auditLogger = new AuditLogger(logsDir);

// Access logging
const accessLogStream = fs.createWriteStream(path.join(logsDir, 'access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: accessLogStream }));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:", "https://images.unsplash.com"],
            upgradeInsecureRequests: [],  // Upgrades HTTP to HTTPS (Mixed Content Protection)
            blockAllMixedContent: []      // Blocks all mixed content
        }
    },
    // Additional security headers for mixed content protection
    hsts: {
        maxAge: 31536000,           // 1 year
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET || 'voting-app-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 3600000 // 1 hour
    }
}));

// Attach audit logger to all requests
app.use((req, res, next) => {
    req.auditLogger = auditLogger;
    next();
});

// Attach user role to session
app.use(attachUserRole(readJSON, USERS_FILE));

// General rate limiter for all routes (excluding static files)
const generalLimiter = rateLimit({
    windowMs: 15 * 1000, // 15 seconds
    max: 30, // 30 requests per 15 seconds (increased to account for multiple asset requests per page)
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for static files and assets
        return req.path.startsWith('/css') || 
               req.path.startsWith('/js') || 
               req.path.startsWith('/images') ||
               req.path.startsWith('/fonts') ||
               req.path.includes('favicon') ||
               req.path.includes('.well-known') ||
               req.path.endsWith('.css') ||
               req.path.endsWith('.js') ||
               req.path.endsWith('.png') ||
               req.path.endsWith('.jpg') ||
               req.path.endsWith('.jpeg') ||
               req.path.endsWith('.gif') ||
               req.path.endsWith('.svg') ||
               req.path.endsWith('.woff') ||
               req.path.endsWith('.woff2') ||
               req.path.endsWith('.ttf') ||
               req.path.endsWith('.ico');
    },
    handler: (req, res) => {
        console.log('⚠️ RATE LIMIT EXCEEDED for IP:', req.ip, 'Path:', req.path);
        res.status(429).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Rate Limit Exceeded</title>
                <style>
                    body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
                    .error-container { background: white; padding: 3rem; border-radius: 1rem; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 500px; text-align: center; }
                    .error-badge { background: #ef4444; color: white; padding: 0.5rem 1rem; border-radius: 0.5rem; display: inline-block; font-weight: bold; margin-bottom: 1rem; }
                    h1 { color: #1f2937; margin: 1rem 0; }
                    p { color: #6b7280; line-height: 1.6; margin: 1rem 0; }
                    .back-link { display: inline-block; margin-top: 1.5rem; padding: 0.75rem 1.5rem; background: linear-gradient(135deg, #667eea, #764ba2); color: white; text-decoration: none; border-radius: 0.5rem; font-weight: 500; }
                    .back-link:hover { opacity: 0.9; }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <div class="error-badge">ERROR 429</div>
                    <h1>Rate Limit Exceeded</h1>
                    <p>Too many requests from your IP address. Please wait 15 seconds before trying again.</p>
                    <p style="font-size: 0.9rem; color: #9ca3af;">This security feature protects against automated attacks and ensures fair access for all users.</p>
                    <a href="/" class="back-link">← Back to Home</a>
                </div>
            </body>
            </html>
        `);
    }
});

app.use(generalLimiter);

// Stricter rate limiter for authentication routes
const authLimiter = rateLimit({
    windowMs: 15 * 1000, // 15 seconds
    max: 10, // 10 attempts per 15 seconds
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // Don't count successful logins
    handler: (req, res) => {
        console.log('⚠️ AUTH RATE LIMIT EXCEEDED for IP:', req.ip, 'Path:', req.path);
        res.status(429).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Too Many Login Attempts</title>
                <style>
                    body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
                    .error-container { background: white; padding: 3rem; border-radius: 1rem; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 500px; text-align: center; }
                    .error-badge { background: #f59e0b; color: white; padding: 0.5rem 1rem; border-radius: 0.5rem; display: inline-block; font-weight: bold; margin-bottom: 1rem; }
                    h1 { color: #1f2937; margin: 1rem 0; }
                    p { color: #6b7280; line-height: 1.6; margin: 1rem 0; }
                    .back-link { display: inline-block; margin-top: 1.5rem; padding: 0.75rem 1.5rem; background: linear-gradient(135deg, #667eea, #764ba2); color: white; text-decoration: none; border-radius: 0.5rem; font-weight: 500; }
                    .back-link:hover { opacity: 0.9; }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <div class="error-badge">TOO MANY ATTEMPTS</div>
                    <h1>Login Rate Limit Exceeded</h1>
                    <p>Too many login attempts. Please wait 15 seconds before trying again.</p>
                    <p style="font-size: 0.9rem; color: #9ca3af;">This prevents brute force attacks and protects your account.</p>
                    <a href="/login" class="back-link">← Back to Login</a>
                </div>
            </body>
            </html>
        `);
    }
});

const csrfProtection = csrf({ cookie: true });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const POLLS_FILE = path.join(DATA_DIR, 'polls.json');
const VOTES_FILE = path.join(DATA_DIR, 'votes.json');
const CREDENTIALS_FILE = path.join(DATA_DIR, 'credentials.json');

function readJSON(filepath) {
    try {
        if (!fs.existsSync(filepath)) {
            return filepath === POLLS_FILE ? [] : 
                   filepath === VOTES_FILE ? [] : 
                   filepath === CREDENTIALS_FILE ? {} : [];
        }
        const data = fs.readFileSync(filepath, 'utf8');
        return data ? JSON.parse(data) : [];
    } catch (error) {
        console.error(`Error reading ${filepath}:`, error);
        return [];
    }
}

function writeJSON(filepath, data) {
    try {
        fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error(`Error writing ${filepath}:`, error);
    }
}

// SQL Injection Detection Patterns
const SQL_INJECTION_PATTERNS = [
    /('|")\s*(OR|AND)\s*('|")?[\d\w]*('|")?\s*=\s*('|")?[\d\w]*('|")?/i,  // ' OR '1'='1, " AND "1"="1
    /('|")\s*(OR|AND)\s+\d+\s*=\s*\d+/i,                                    // ' OR 1=1
    /('|")\s*;\s*(DROP|DELETE|UPDATE|INSERT|SELECT|UNION)/i,               // '; DROP TABLE
    /UNION\s+(ALL\s+)?SELECT/i,                                             // UNION SELECT
    /SELECT\s+.*\s+FROM/i,                                                  // SELECT * FROM
    /INSERT\s+INTO/i,                                                       // INSERT INTO
    /DELETE\s+FROM/i,                                                       // DELETE FROM
    /UPDATE\s+.*\s+SET/i,                                                   // UPDATE table SET
    /DROP\s+(TABLE|DATABASE)/i,                                             // DROP TABLE/DATABASE
    /--\s*$/,                                                               // SQL comment at end
    /\/\*.*\*\//,                                                           // SQL block comment
    /EXEC(\s+|\()/i,                                                        // EXEC command
    /xp_/i,                                                                 // SQL Server extended procedures
    /0x[0-9a-fA-F]+/,                                                       // Hex encoded values
    /CHAR\s*\(/i,                                                           // CHAR() function
    /CONCAT\s*\(/i,                                                         // CONCAT() function
    /HAVING\s+/i,                                                           // HAVING clause injection
    /GROUP\s+BY/i,                                                          // GROUP BY injection
    /ORDER\s+BY\s+\d+/i,                                                    // ORDER BY number (column enumeration)
    /WAITFOR\s+DELAY/i,                                                     // Time-based injection
    /BENCHMARK\s*\(/i,                                                      // MySQL time-based injection
    /SLEEP\s*\(/i,                                                          // MySQL SLEEP injection
];

function detectSQLInjection(input) {
    if (typeof input !== 'string') return false;
    
    for (const pattern of SQL_INJECTION_PATTERNS) {
        if (pattern.test(input)) {
            return true;
        }
    }
    return false;
}

function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    
    // Check for SQL injection attempts
    if (detectSQLInjection(input)) {
        logSecurityEvent(`SQL Injection attempt detected: "${input}"`);
        return ''; // Return empty string for malicious input
    }
    
    // Remove dangerous characters
    return input
        .trim()
        .replace(/[<>]/g, '')           // XSS prevention
        .replace(/['";\\]/g, '');       // SQL special characters
}

// Legacy security logging function (now uses auditLogger)
function logSecurityEvent(message) {
    auditLogger.logSecurityThreat(AUDIT_EVENTS.SQL_INJECTION_BLOCKED, {
        message,
        ip: 'system',
        userAgent: 'system'
    });
}

// Legacy middleware for backward compatibility
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        auditLogger.logEvent(AUDIT_EVENTS.ACCESS_DENIED, {
            ip: req.ip,
            userAgent: req.get('user-agent'),
            resource: req.path,
            message: 'Unauthenticated user attempted to access protected resource'
        });
        res.redirect('/login');
    }
}

function isAdmin(req, res, next) {
    const userRole = req.session?.role || ROLES.GUEST;
    if (req.session && (req.session.isAdmin || userRole === ROLES.ADMINISTRATOR)) {
        next();
    } else {
        auditLogger.logEvent(AUDIT_EVENTS.ACCESS_DENIED, {
            userId: req.session?.userId,
            username: req.session?.username,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            resource: req.path,
            message: 'Non-admin user attempted to access admin resource'
        });
        res.redirect('/admin-login');
    }
}

// SQL Injection Protection Middleware
function sqlInjectionProtection(req, res, next) {
    const fieldsToCheck = { ...req.body, ...req.query, ...req.params };
    
    for (const [key, value] of Object.entries(fieldsToCheck)) {
        if (typeof value === 'string' && detectSQLInjection(value)) {
            logSecurityEvent(`SQL Injection blocked - Field: "${key}", Value: "${value}", IP: ${req.ip}`);
            return res.status(400).render('error', {
                errorTitle: 'Security Alert',
                errorMessage: 'Potentially malicious input detected. Your request has been blocked and logged.'
            });
        }
    }
    next();
}

// Apply SQL injection protection to all POST requests
app.use(sqlInjectionProtection);

// Routes

// Root route - redirect based on auth status
app.get('/', (req, res) => {
    if (req.session && req.session.userId) {
        // User is logged in, show voting page
        return res.redirect('/vote');
    } else {
        // Not logged in, show login page
        return res.redirect('/login');
    }
});

// Email Verification Route
app.get('/verify-email', async (req, res) => {
    try {
        const token = req.query.token;
        
        if (!token) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: '',
                errorTitle: 'Invalid Verification Link',
                errorMessage: 'The verification link is invalid or missing.'
            });
        }
        
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.verificationToken === token);
        
        if (!user) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: '',
                errorTitle: 'Invalid Verification Token',
                errorMessage: 'The verification token is invalid or has already been used.'
            });
        }
        
        if (user.emailVerified) {
            return res.render('error', {
                session: req.session,
                csrfToken: '',
                errorTitle: 'Already Verified',
                errorMessage: 'Your email has already been verified. You can log in now.'
            });
        }
        
        // Check if token is expired
        if (isTokenExpired(user.verificationTokenCreatedAt)) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: '',
                errorTitle: 'Token Expired',
                errorMessage: 'The verification link has expired. Please request a new verification email.'
            });
        }
        
        // Verify the email
        user.emailVerified = true;
        user.verificationToken = null;
        writeJSON(USERS_FILE, users);
        
        // Update session if this is the current user
        if (req.session && req.session.userId === user.id) {
            req.session.emailVerified = true;
        }
        
        // Log the verification
        auditLogger.logEvent(AUDIT_EVENTS.EMAIL_VERIFIED, {
            userId: user.id,
            username: user.username,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            message: `Email verified for user: ${user.username}`
        });
        
        // Send welcome email
        sendWelcomeEmail(user.email, user.username);
        
        // Render success page
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Email Verified</title>
                <style>
                    body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
                    .container { background: white; padding: 3rem; border-radius: 1rem; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 500px; text-align: center; }
                    .success-badge { background: #10b981; color: white; padding: 0.5rem 1rem; border-radius: 0.5rem; display: inline-block; font-weight: bold; margin-bottom: 1rem; }
                    h1 { color: #1f2937; margin: 1rem 0; }
                    p { color: #6b7280; line-height: 1.6; margin: 1rem 0; }
                    .login-link { display: inline-block; margin-top: 1.5rem; padding: 0.75rem 1.5rem; background: linear-gradient(135deg, #667eea, #764ba2); color: white; text-decoration: none; border-radius: 0.5rem; font-weight: 500; }
                    .login-link:hover { opacity: 0.9; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success-badge">✓ VERIFIED</div>
                    <h1>Email Verified Successfully!</h1>
                    <p>Your email has been verified. You now have full access to all features of the voting app.</p>
                    <a href="/login" class="login-link">Go to Login</a>
                </div>
            </body>
            </html>
        `);
        
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).render('error', {
            session: req.session,
            csrfToken: '',
            errorTitle: 'Verification Error',
            errorMessage: 'An error occurred during email verification.'
        });
    }
});

// Resend Verification Email Route
app.post('/resend-verification', csrfProtection, async (req, res) => {
    try {
        if (!req.session || !req.session.userId) {
            return res.redirect('/login');
        }
        
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === req.session.userId);
        
        if (!user) {
            return res.redirect('/login');
        }
        
        if (user.emailVerified) {
            return res.redirect('/vote');
        }
        
        // Generate new token
        const newToken = generateVerificationToken();
        user.verificationToken = newToken;
        user.verificationTokenCreatedAt = new Date().toISOString();
        writeJSON(USERS_FILE, users);
        
        // Send verification email
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        const verificationUrl = generateVerificationUrl(baseUrl, newToken);
        sendVerificationEmail(user.email, verificationUrl);
        
        auditLogger.logEvent(AUDIT_EVENTS.EMAIL_VERIFICATION_SENT, {
            userId: user.id,
            username: user.username,
            ip: req.ip,
            message: `Verification email resent to ${user.email}`
        });
        
        res.send('Verification email sent! Please check your inbox.');
    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).send('Error sending verification email');
    }
});

app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { 
        errorMessage: null,
        successMessage: null,
        csrfToken: req.csrfToken()
    });
});

app.post('/register', 
    authLimiter,
    csrfProtection,
    [
        // --- Username Rules: alphanumeric only, 5-15 characters ---
        body('username')
            .trim()
            .isLength({ min: 5, max: 15 }).withMessage('Username must be between 5 and 15 characters')
            .isAlphanumeric().withMessage('Username must only contain letters and numbers (no spaces or special characters)')
            .custom(value => {
                if (value.toLowerCase() === 'admin') {
                    throw new Error('The username "admin" is not allowed');
                }
                return true;
            }),
        
        // --- Email Rule ---
        body('email')
            .trim()
            .isEmail().withMessage('Please enter a valid email address')
            .normalizeEmail(),
        
        // --- Password Rules: 8-12 chars, uppercase, lowercase, number, special char ---
        body('password')
            .isLength({ min: 8, max: 12 }).withMessage('Password must be between 8 and 12 characters')
            .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
            .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
            .matches(/[0-9]/).withMessage('Password must contain at least one number')
            .matches(/[@$!%*?&#^()_+=\[\]{};':"\\|,.<>\/~`-]/).withMessage('Password must contain at least one special character')
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const errorMessages = errors.array().map(e => e.msg).join(', ');
            return res.render('register', { 
                errorMessage: errorMessages,
                csrfToken: req.csrfToken()
            });
        }

        const username = sanitizeInput(req.body.username);
        const email = req.body.email.trim().toLowerCase();
        const password = req.body.password;

        const users = readJSON(USERS_FILE);

        if (users.find(u => u.username === username)) {
            return res.render('register', { 
                errorMessage: 'Username already exists.',
                csrfToken: req.csrfToken()
            });
        }

        if (users.find(u => u.email === email)) {
            return res.render('register', { 
                errorMessage: 'Email already registered.',
                csrfToken: req.csrfToken()
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = generateVerificationToken();
        
        const newUser = {
            id: Date.now().toString(),
            username,
            email,
            passwordHash: hashedPassword,
            role: getDefaultRole(), // Default role: customer
            emailVerified: false,
            verificationToken,
            verificationTokenCreatedAt: new Date().toISOString(),
            createdAt: new Date().toISOString(),
            lastVote: null
        };

        users.push(newUser);
        writeJSON(USERS_FILE, users);

        // Log successful registration
        auditLogger.logEvent(AUDIT_EVENTS.REGISTRATION, {
            userId: newUser.id,
            username,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            message: `New user registered: ${username}`,
            metadata: { email, role: newUser.role }
        });

        // Send verification email
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        const verificationUrl = generateVerificationUrl(baseUrl, verificationToken);
        sendVerificationEmail(email, verificationUrl);
        
        auditLogger.logEvent(AUDIT_EVENTS.EMAIL_VERIFICATION_SENT, {
            userId: newUser.id,
            username,
            ip: req.ip,
            message: `Verification email sent to ${email}`
        });

        // Auto-login after registration (but with limited access until verified)
        req.session.userId = newUser.id;
        req.session.username = newUser.username;
        req.session.role = newUser.role;
        req.session.emailVerified = false;
        
        res.render('register', {
            errorMessage: null,
            successMessage: 'Registration successful! Please check your email to verify your account.',
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', { 
            errorMessage: 'An error occurred during registration.',
            csrfToken: req.csrfToken()
        });
    }
});

app.get('/login', csrfProtection, (req, res) => {
    res.render('login', { 
        errorMessage: null,
        csrfToken: req.csrfToken()
    });
});

app.post('/login', 
    authLimiter,
    csrfProtection,
    [
        body('username')
            .trim()
            .notEmpty()
            .withMessage('Username is required')
            .isLength({ min: 3 })
            .withMessage('Username must be at least 3 characters'),
        body('password')
            .notEmpty()
            .withMessage('Password is required')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters')
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const errorMessages = errors.array().map(e => e.msg).join(', ');
            return res.render('login', { 
                errorMessage: errorMessages,
                csrfToken: req.csrfToken()
            });
        }

        const username = sanitizeInput(req.body.username);
        const password = req.body.password;

        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.username === username);

        if (!user) {
            auditLogger.logAuthentication(false, username, req.ip, req.get('user-agent'), {
                reason: 'user not found'
            });
            return res.render('login', { 
                errorMessage: 'Invalid username or password.',
                csrfToken: req.csrfToken()
            });
        }

        const validPassword = await bcrypt.compare(password, user.passwordHash || user.password);

        if (!validPassword) {
            auditLogger.logAuthentication(false, username, req.ip, req.get('user-agent'), {
                reason: 'wrong password'
            });
            return res.render('login', { 
                errorMessage: 'Invalid username or password.',
                csrfToken: req.csrfToken()
            });
        }

        // Set session data
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role || getDefaultRole();
        req.session.emailVerified = user.emailVerified || false;
        req.session.isAdmin = user.role === ROLES.ADMINISTRATOR;

        auditLogger.logAuthentication(true, username, req.ip, req.get('user-agent'), {
            userId: user.id,
            role: user.role
        });
        
        res.redirect('/');
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { 
            errorMessage: 'An error occurred during login.',
            csrfToken: req.csrfToken()
        });
    }
});

app.get('/voting', isAuthenticated, csrfProtection, (req, res) => {
    res.redirect('/vote');
});

app.get('/vote', isAuthenticated, requirePermission(PERMISSIONS.VIEW_POLLS), csrfProtection, (req, res) => {
    const polls = readJSON(POLLS_FILE);
    const votes = readJSON(VOTES_FILE);
    const users = readJSON(USERS_FILE);
    const currentUser = users.find(u => u.id === req.session.userId);

    if (polls.length === 0) {
        return res.render('index', {
            session: req.session,
            csrfToken: req.csrfToken(),
            poll: null,
            hasVoted: false,
            userVote: null,
            isAdmin: false
        });
    }

    const poll = polls[0]; // Single standard poll
    const pollVotes = votes[poll.id.toString()] || [];
    const userVoteRecord = pollVotes.find(v => v.userId === req.session.userId);
    const hasVoted = !!userVoteRecord || (currentUser && currentUser.lastVote === poll.id);
    const userVote = userVoteRecord ? poll.options[userVoteRecord.option] : 
                     (currentUser && currentUser.lastVoteOption !== undefined) ? poll.options[currentUser.lastVoteOption] : null;

    res.render('index', { 
        session: req.session,
        csrfToken: req.csrfToken(),
        poll: poll,
        hasVoted: hasVoted,
        userVote: userVote,
        isAdmin: false
    });
});

app.post('/vote', isAuthenticated, requirePermission(PERMISSIONS.CAST_VOTE), requireEmailVerification, csrfProtection, (req, res) => {
    try {
        const pollId = parseInt(req.body.pollId);
        const optionValue = req.body.option;
        
        console.log('Vote data received:', { pollId, optionValue, body: req.body });

        const users = readJSON(USERS_FILE);
        const votes = readJSON(VOTES_FILE);
        const polls = readJSON(POLLS_FILE);
        const poll = polls.find(p => p.id === pollId);

        if (!poll) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Invalid Poll',
                errorMessage: 'The poll you are trying to vote on does not exist.'
            });
        }

        // Find option index - handle both number index and option name
        let optionIndex;
        if (!isNaN(parseInt(optionValue))) {
            optionIndex = parseInt(optionValue);
        } else {
            optionIndex = poll.options.indexOf(optionValue);
        }

        if (optionIndex < 0 || optionIndex >= poll.options.length) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Invalid Option',
                errorMessage: 'The option you selected is not valid.'
            });
        }

        const currentUser = users.find(u => u.id === req.session.userId);
        if (currentUser && currentUser.lastVote === pollId) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Already Voted',
                errorMessage: 'You have already voted in this poll. Vote duplication is not allowed.'
            });
        }

        // Initialize poll votes array if it doesn't exist
        if (!votes[pollId.toString()]) {
            votes[pollId.toString()] = [];
        }

        // Check for duplicate
        const alreadyVoted = votes[pollId.toString()].find(v => v.userId === req.session.userId);
        if (alreadyVoted) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Already Voted',
                errorMessage: 'You have already voted in this poll. Vote duplication is not allowed.'
            });
        }

        // Record vote with userId and option
        votes[pollId.toString()].push({
            userId: req.session.userId,
            option: optionIndex,
            timestamp: new Date().toISOString()
        });
        writeJSON(VOTES_FILE, votes);
        
        console.log('Vote recorded:', votes[pollId.toString()]);

        // Update user's lastVote with pollId
        if (currentUser) {
            currentUser.lastVote = pollId;
            currentUser.lastVoteOption = optionIndex;
            writeJSON(USERS_FILE, users);
        }

        // Log vote
        auditLogger.logVote(
            req.session.userId,
            req.session.username,
            pollId,
            poll.options[optionIndex],
            req.ip,
            { userAgent: req.get('user-agent') }
        );

        res.redirect('/vote');
    } catch (error) {
        console.error('Voting error:', error);
        res.status(500).render('error', {
            session: req.session,
            csrfToken: req.csrfToken(),
            errorTitle: 'Voting Error',
            errorMessage: 'An error occurred while processing your vote.'
        });
    }
});

app.get('/results', isAuthenticated, requirePermission(PERMISSIONS.VIEW_RESULTS), csrfProtection, (req, res) => {
    const polls = readJSON(POLLS_FILE);
    const votes = readJSON(VOTES_FILE);

    if (polls.length === 0) {
        return res.render('results', {
            session: req.session,
            csrfToken: req.csrfToken(),
            poll: null,
            results: {}
        });
    }

    const poll = polls[0]; // Single standard poll
    const pollVotes = votes[poll.id.toString()] || [];
    
    // Count votes per option from the votes array
    const results = {};
    poll.options.forEach((_, index) => {
        results[index] = 0;
    });
    
    pollVotes.forEach(vote => {
        if (vote.option !== undefined && vote.option !== null) {
            results[vote.option] = (results[vote.option] || 0) + 1;
        }
    });

    res.render('results', { 
        session: req.session,
        csrfToken: req.csrfToken(),
        poll: poll,
        results: results
    });
});

// User Account/Profile Page
app.get('/account', isAuthenticated, csrfProtection, (req, res) => {
    try {
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === req.session.userId);
        
        res.render('account', {
            session: req.session,
            csrfToken: req.csrfToken(),
            userEmail: user ? user.email : null,
            successMessage: null
        });
    } catch (error) {
        console.error('Account page error:', error);
        res.redirect('/vote');
    }
});

app.get('/admin-login', csrfProtection, (req, res) => {
    res.render('admin-login', { 
        errorMessage: null,
        csrfToken: req.csrfToken()
    });
});

app.post('/admin-login', authLimiter, csrfProtection, [
    body('username').trim().escape(),
    body('password').trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        const username = req.body.username;  // Already escaped by validator
        const password = req.body.password;

        const credentials = readJSON(CREDENTIALS_FILE);

        if (username !== credentials.username) {
            return res.render('admin-login', { 
                errorMessage: 'Invalid admin credentials.',
                csrfToken: req.csrfToken()
            });
        }

        const validPassword = await bcrypt.compare(password, credentials.password);

        if (!validPassword) {
            return res.render('admin-login', { 
                errorMessage: 'Invalid admin credentials.',
                csrfToken: req.csrfToken()
            });
        }

        req.session.isAdmin = true;
        req.session.adminUsername = username;
        req.session.username = username;
        req.session.role = ROLES.ADMINISTRATOR;
        req.session.emailVerified = true;

        auditLogger.logEvent(AUDIT_EVENTS.ADMIN_LOGIN, {
            username,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            message: `Admin logged in: ${username}`
        });

        res.redirect('/admin');
    } catch (error) {
        console.error('Admin login error:', error);
        res.render('admin-login', { 
            errorMessage: 'An error occurred during login.',
            csrfToken: req.csrfToken()
        });
    }
});

app.get('/admin/dashboard', isAdmin, csrfProtection, (req, res) => {
    res.redirect('/admin');
});

app.get('/admin', isAdmin, csrfProtection, (req, res) => {
    const users = readJSON(USERS_FILE);
    const polls = readJSON(POLLS_FILE);
    const votes = readJSON(VOTES_FILE);
    const credentials = readJSON(CREDENTIALS_FILE);

    const userCount = users.length;
    const adminUsername = credentials.username || 'admin';

    res.render('dashboard', {
        session: req.session,
        csrfToken: req.csrfToken(),
        userCount: userCount,
        adminUsername: adminUsername,
        errorMessage: null,
        successMessage: null
    });
});

// New Route: Change Admin Username (XSS Demo)
app.post('/admin/change-username', isAdmin, csrfProtection, [
    body('newUsername')
        .trim()
        .isLength({ min: 3 }).withMessage('Username must be at least 3 characters')
        .escape()  // Sanitize dangerous characters instead of blocking them
], (req, res) => {
    try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const errorMessages = errors.array().map(e => e.msg).join(', ');
            
            const users = readJSON(USERS_FILE);
            const credentials = readJSON(CREDENTIALS_FILE);
            const userCount = users.length;
            
            return res.render('dashboard', {
                session: req.session,
                csrfToken: req.csrfToken(),
                userCount: userCount,
                adminUsername: credentials.username,
                errorMessage: errorMessages,
                successMessage: null
            });
        }

        const newUsername = req.body.newUsername;

        // Read credentials file
        const credentials = readJSON(CREDENTIALS_FILE);
        
        // Update the admin username
        credentials.username = newUsername;
        
        // Save back to file
        writeJSON(CREDENTIALS_FILE, credentials);
        
        // Update session
        req.session.adminUsername = newUsername;
        req.session.username = newUsername;
        
        // Redirect back to dashboard with success message
        const users = readJSON(USERS_FILE);
        const userCount = users.length;
        
        res.render('dashboard', {
            session: req.session,
            csrfToken: req.csrfToken(),
            userCount: userCount,
            adminUsername: newUsername,
            errorMessage: null,
            successMessage: `Username successfully changed to "${newUsername}"!`
        });
        
    } catch (error) {
        console.error('Change username error:', error);
        const users = readJSON(USERS_FILE);
        const credentials = readJSON(CREDENTIALS_FILE);
        const userCount = users.length;
        
        res.render('dashboard', {
            session: req.session,
            csrfToken: req.csrfToken(),
            userCount: userCount,
            adminUsername: credentials.username,
            errorMessage: 'An error occurred while changing the username.',
            successMessage: null
        });
    }
});

// Admin Logout Route
app.get('/admin/logout', (req, res) => {
    auditLogger.logEvent(AUDIT_EVENTS.LOGOUT, {
        userId: req.session?.userId,
        username: req.session?.username || req.session?.adminUsername,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        message: `Admin logged out: ${req.session?.adminUsername || 'unknown'}`
    });
    req.session.destroy();
    res.redirect('/admin-login');
});

app.post('/admin/logout', csrfProtection, (req, res) => {
    auditLogger.logEvent(AUDIT_EVENTS.LOGOUT, {
        userId: req.session?.userId,
        username: req.session?.username || req.session?.adminUsername,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        message: `Admin logged out: ${req.session?.adminUsername || 'unknown'}`
    });
    req.session.destroy();
    res.redirect('/admin-login');
});

// Admin route to view audit logs
app.get('/admin/audit-logs', isAdmin, requirePermission(PERMISSIONS.VIEW_AUDIT_LOGS), csrfProtection, (req, res) => {
    try {
        const logs = auditLogger.getRecentLogs(100);
        
        auditLogger.logEvent(AUDIT_EVENTS.AUDIT_LOG_VIEWED, {
            userId: req.session?.userId,
            username: req.session?.username || req.session?.adminUsername,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            message: 'Admin viewed audit logs'
        });
        
        res.render('audit-logs', {
            session: req.session,
            csrfToken: req.csrfToken(),
            logs: logs.reverse() // Most recent first
        });
    } catch (error) {
        console.error('Error loading audit logs:', error);
        res.status(500).render('error', {
            session: req.session,
            csrfToken: req.csrfToken(),
            errorTitle: 'Error Loading Logs',
            errorMessage: 'An error occurred while loading audit logs.'
        });
    }
});

// Admin route to manage user roles
app.get('/admin/manage-roles', isAdmin, requirePermission(PERMISSIONS.CHANGE_USER_ROLES), csrfProtection, (req, res) => {
    try {
        const users = readJSON(USERS_FILE);
        
        res.render('manage-roles', {
            session: req.session,
            csrfToken: req.csrfToken(),
            users: users,
            roles: ROLES,
            errorMessage: null,
            successMessage: null
        });
    } catch (error) {
        console.error('Error loading user roles:', error);
        res.status(500).render('error', {
            session: req.session,
            csrfToken: req.csrfToken(),
            errorTitle: 'Error',
            errorMessage: 'An error occurred while loading user roles.'
        });
    }
});

// Admin route to update user role
app.post('/admin/update-role', isAdmin, requirePermission(PERMISSIONS.CHANGE_USER_ROLES), csrfProtection, [
    body('userId').trim().notEmpty(),
    body('newRole').trim().isIn(Object.values(ROLES))
], (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const users = readJSON(USERS_FILE);
            return res.render('manage-roles', {
                session: req.session,
                csrfToken: req.csrfToken(),
                users: users,
                roles: ROLES,
                errorMessage: 'Invalid input data',
                successMessage: null
            });
        }
        
        const { userId, newRole } = req.body;
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === userId);
        
        if (!user) {
            return res.render('manage-roles', {
                session: req.session,
                csrfToken: req.csrfToken(),
                users: users,
                roles: ROLES,
                errorMessage: 'User not found',
                successMessage: null
            });
        }
        
        const oldRole = user.role;
        user.role = newRole;
        writeJSON(USERS_FILE, users);
        
        auditLogger.logEvent(AUDIT_EVENTS.ROLE_CHANGE, {
            userId: req.session?.userId,
            username: req.session?.username || req.session?.adminUsername,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            message: `Role changed for user ${user.username}: ${oldRole} -> ${newRole}`,
            metadata: { targetUserId: userId, targetUsername: user.username, oldRole, newRole }
        });
        
        const updatedUsers = readJSON(USERS_FILE);
        res.render('manage-roles', {
            session: req.session,
            csrfToken: req.csrfToken(),
            users: updatedUsers,
            roles: ROLES,
            errorMessage: null,
            successMessage: `Role updated successfully for ${user.username}`
        });
    } catch (error) {
        console.error('Error updating role:', error);
        const users = readJSON(USERS_FILE);
        res.render('manage-roles', {
            session: req.session,
            csrfToken: req.csrfToken(),
            users: users,
            roles: ROLES,
            errorMessage: 'An error occurred while updating the role',
            successMessage: null
        });
    }
});

// User Logout Routes
app.get('/logout', (req, res) => {
    auditLogger.logEvent(AUDIT_EVENTS.LOGOUT, {
        userId: req.session?.userId,
        username: req.session?.username,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        message: `User logged out: ${req.session?.username || 'unknown'}`
    });
    req.session.destroy();
    res.redirect('/login');
});

app.post('/logout', csrfProtection, (req, res) => {
    auditLogger.logEvent(AUDIT_EVENTS.LOGOUT, {
        userId: req.session?.userId,
        username: req.session?.username,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        message: `User logged out: ${req.session?.username || 'unknown'}`
    });
    req.session.destroy();
    res.redirect('/login');
});

// CSRF Error Handler
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).render('error', {
            session: req.session,
            csrfToken: '',
            errorTitle: 'Security Error',
            errorMessage: 'Invalid security token. Please refresh the page and try again.'
        });
    }
    next(err);
});

// General Error Handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).render('error', {
        session: req.session,
        csrfToken: req.csrfToken ? req.csrfToken() : '',
        errorTitle: 'Server Error',
        errorMessage: 'An unexpected error occurred. Please try again later.'
    });
});

// 404 Not Found Handler
app.use((req, res) => {
    res.status(404).render('error', {
        session: req.session,
        csrfToken: req.csrfToken ? req.csrfToken() : '',
        errorTitle: 'Page Not Found',
        errorMessage: 'The page you are looking for does not exist.'
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Security features enabled:');
    console.log('✓ Helmet security headers (CSP, HSTS)');
    console.log('✓ Session management with HttpOnly cookies');
    console.log('✓ Rate limiting on all routes');
    console.log('✓ CSRF protection');
    console.log('✓ Input validation and sanitization');
    console.log('✓ Enhanced password validation');
    console.log('✓ Password hashing with bcrypt');
    console.log('✓ Vote duplication prevention');
    console.log('✓ XSS prevention');
    console.log('✓ Role-Based Access Control (RBAC)');
    console.log('✓ Email verification system');
    console.log('✓ Audit logging for security events');
    console.log('✓ Granular permission system');
    console.log('✓ Defense-in-depth security layers');
    console.log('');
    console.log('🔐 Advanced Security Features:');
    console.log('  • 4 user roles: Guest, Customer, Editor, Administrator');
    console.log('  • Permission matrix with 15+ granular permissions');
    console.log('  • Comprehensive audit logging');
    console.log('  • Email verification requirement');
    console.log('  • Fail-safe defaults (deny by default)');
});
