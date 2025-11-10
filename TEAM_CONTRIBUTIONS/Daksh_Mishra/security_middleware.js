// Daksh Mishra - Security Middleware Implementation
// Part 1: Helmet Security Headers, Rate Limiting, Session Management, CSRF Protection

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

// Helmet Security Headers Configuration
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:", "https://images.unsplash.com"]
        }
    }
}));

// Session Configuration with HttpOnly Cookies
app.use(session({
    secret: 'voting-app-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,         // Prevents JavaScript access to cookies
        secure: false,          // Set to true in production with HTTPS
        maxAge: 24 * 60 * 60 * 1000  // 24 hours
    }
}));

// General Rate Limiter - 30 requests per 15 seconds
const generalLimiter = rateLimit({
    windowMs: 15 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for static files
        return req.path.startsWith('/css') || 
               req.path.startsWith('/js') || 
               req.path.startsWith('/images') ||
               req.path.startsWith('/fonts') ||
               req.path.includes('favicon') ||
               req.path.endsWith('.css') ||
               req.path.endsWith('.js') ||
               req.path.endsWith('.png') ||
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
                    body { 
                        font-family: Arial, sans-serif; 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        min-height: 100vh; 
                        display: flex; 
                        align-items: center; 
                        justify-content: center; 
                        margin: 0; 
                    }
                    .error-container { 
                        background: white; 
                        padding: 3rem; 
                        border-radius: 1rem; 
                        box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
                        max-width: 500px; 
                        text-align: center; 
                    }
                    .error-badge { 
                        background: #ef4444; 
                        color: white; 
                        padding: 0.5rem 1rem; 
                        border-radius: 0.5rem; 
                        display: inline-block; 
                        font-weight: bold; 
                        margin-bottom: 1rem; 
                    }
                    h1 { color: #1f2937; margin: 1rem 0; }
                    p { color: #6b7280; line-height: 1.6; margin: 1rem 0; }
                    .back-link { 
                        display: inline-block; 
                        margin-top: 1.5rem; 
                        padding: 0.75rem 1.5rem; 
                        background: linear-gradient(135deg, #667eea, #764ba2); 
                        color: white; 
                        text-decoration: none; 
                        border-radius: 0.5rem; 
                        font-weight: 500; 
                    }
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

// Authentication Rate Limiter - Stricter for login attempts
const authLimiter = rateLimit({
    windowMs: 15 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        console.log('⚠️ AUTH RATE LIMIT EXCEEDED for IP:', req.ip, 'Path:', req.path);
        res.status(429).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Too Many Login Attempts</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        min-height: 100vh; 
                        display: flex; 
                        align-items: center; 
                        justify-content: center; 
                        margin: 0; 
                    }
                    .error-container { 
                        background: white; 
                        padding: 3rem; 
                        border-radius: 1rem; 
                        box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
                        max-width: 500px; 
                        text-align: center; 
                    }
                    .error-badge { 
                        background: #f59e0b; 
                        color: white; 
                        padding: 0.5rem 1rem; 
                        border-radius: 0.5rem; 
                        display: inline-block; 
                        font-weight: bold; 
                        margin-bottom: 1rem; 
                    }
                    h1 { color: #1f2937; margin: 1rem 0; }
                    p { color: #6b7280; line-height: 1.6; margin: 1rem 0; }
                    .back-link { 
                        display: inline-block; 
                        margin-top: 1.5rem; 
                        padding: 0.75rem 1.5rem; 
                        background: linear-gradient(135deg, #667eea, #764ba2); 
                        color: white; 
                        text-decoration: none; 
                        border-radius: 0.5rem; 
                        font-weight: 500; 
                    }
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

// CSRF Protection
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

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

// Security Logging Function
function logSecurityEvent(message) {
    const logStream = fs.createWriteStream(path.join(logsDir, 'security.log'), { flags: 'a' });
    logStream.write(`[${new Date().toISOString()}] ${message}\n`);
    logStream.end();
}

// Export for use in other modules
module.exports = {
    generalLimiter,
    authLimiter,
    csrfProtection,
    logSecurityEvent
};
