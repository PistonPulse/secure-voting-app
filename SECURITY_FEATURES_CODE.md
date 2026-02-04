# Security Features - Code Snippets

This document contains all the security features implemented in the Secure Voting App.

---

## 1. SQL Injection Prevention

```javascript
const SQL_INJECTION_PATTERNS = [
    /('|")\s*(OR|AND)\s*('|")?[\d\w]*('|")?\s*=\s*('|")?[\d\w]*('|")?/i,
    /('|")\s*(OR|AND)\s+\d+\s*=\s*\d+/i,
    /('|")\s*;\s*(DROP|DELETE|UPDATE|INSERT|SELECT|UNION)/i,
    /UNION\s+(ALL\s+)?SELECT/i,
    /SELECT\s+.*\s+FROM/i,
    /INSERT\s+INTO/i,
    /DELETE\s+FROM/i,
    /UPDATE\s+.*\s+SET/i,
    /DROP\s+(TABLE|DATABASE)/i,
    /--\s*$/,
    /\/\*.*\*\//,
    /EXEC(\s+|\()/i,
    /xp_/i,
    /0x[0-9a-fA-F]+/,
    /CHAR\s*\(/i,
    /CONCAT\s*\(/i,
    /HAVING\s+/i,
    /GROUP\s+BY/i,
    /ORDER\s+BY\s+\d+/i,
    /WAITFOR\s+DELAY/i,
    /BENCHMARK\s*\(/i,
    /SLEEP\s*\(/i,
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

app.use(sqlInjectionProtection);
```

---

## 2. XSS Prevention & Mixed Content Protection

```javascript
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:", "https://images.unsplash.com"],
            upgradeInsecureRequests: [],
            blockAllMixedContent: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
```

---

## 3. Input Sanitization

```javascript
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    if (detectSQLInjection(input)) {
        logSecurityEvent(`SQL Injection attempt detected: "${input}"`);
        return '';
    }
    return input
        .trim()
        .replace(/[<>]/g, '')
        .replace(/['";\\]/g, '');
}
```

---

## 4. Session Management (1 Hour Limit)

```javascript
app.use(session({
    secret: 'voting-app-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 3600000
    }
}));
```

---

## 5. Rate Limiting

```javascript
const generalLimiter = rateLimit({
    windowMs: 15 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        return req.path.startsWith('/css') || 
               req.path.startsWith('/js') || 
               req.path.startsWith('/images') ||
               req.path.startsWith('/fonts') ||
               req.path.endsWith('.css') ||
               req.path.endsWith('.js') ||
               req.path.endsWith('.png') ||
               req.path.endsWith('.ico');
    },
    handler: (req, res) => {
        console.log('⚠️ RATE LIMIT EXCEEDED for IP:', req.ip, 'Path:', req.path);
        res.status(429).send('Rate Limit Exceeded');
    }
});

app.use(generalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        console.log('⚠️ AUTH RATE LIMIT EXCEEDED for IP:', req.ip, 'Path:', req.path);
        res.status(429).send('Too many login attempts.');
    }
});
```

---

## 6. Password Hashing

```javascript
const hashedPassword = await bcrypt.hash(password, 10);

const newUser = {
    id: Date.now().toString(),
    username,
    email,
    passwordHash: hashedPassword,
    lastVote: null
};
```

---

## 7. Username Validation

```javascript
body('username')
    .trim()
    .isLength({ min: 5, max: 15 }).withMessage('Username must be between 5 and 15 characters')
    .isAlphanumeric().withMessage('Username must only contain letters and numbers (no spaces or special characters)')
    .custom(value => {
        if (value.toLowerCase() === 'admin') {
            throw new Error('The username "admin" is not allowed');
        }
        return true;
    })
```

---

## 8. Email Validation

```javascript
body('email')
    .trim()
    .isEmail().withMessage('Please enter a valid email address')
    .normalizeEmail()
```

---

## 9. Password Validation

```javascript
body('password')
    .isLength({ min: 8, max: 12 }).withMessage('Password must be between 8 and 12 characters')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[@$!%*?&#^()_+=\[\]{};':"\\|,.<>\/~`-]/).withMessage('Password must contain at least one special character')
```

---

## 10. CSRF Protection

```javascript
const csrfProtection = csrf({ cookie: true });

app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { 
        errorMessage: null,
        csrfToken: req.csrfToken()
    });
});
```

---

## 11. Access Control

```javascript
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

function isAdmin(req, res, next) {
    if (req.session && req.session.isAdmin) {
        next();
    } else {
        res.redirect('/admin-login');
    }
}
```

---

## 12. Security Logging

```javascript
function logSecurityEvent(message) {
    const logStream = fs.createWriteStream(path.join(logsDir, 'security.log'), { flags: 'a' });
    logStream.write(`[${new Date().toISOString()}] ${message}\n`);
    logStream.end();
}
```

---

*Last Updated: February 4, 2026*
