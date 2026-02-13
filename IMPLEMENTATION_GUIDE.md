# Security Implementation Guide

This document provides key code snippets demonstrating the security features implemented in the Secure Voting Application.

---

## 1. Least Privilege

### 1.1 Admin Access

**Implementation:** RBAC with 4 roles and 15+ permissions

```javascript
// rbac-config.js
const ROLES = { GUEST: 'guest', CUSTOMER: 'customer', EDITOR: 'editor', ADMINISTRATOR: 'admin' };

const PERMISSION_MATRIX = {
    [ROLES.CUSTOMER]: ['view_polls', 'cast_vote', 'view_results'],
    [ROLES.ADMINISTRATOR]: [...Object.values(PERMISSIONS)]
};

function hasPermission(role, permission) {
    return (PERMISSION_MATRIX[role] || []).includes(permission);
}
```

**Admin Routes:**
```javascript
// index.js
app.get('/admin/audit-logs', 
    isAdmin, 
    requirePermission(PERMISSIONS.VIEW_AUDIT_LOGS), 
    (req, res) => { /* ... */ });
```

**Result:** Only administrators with specific permissions can access admin features

---

### 1.2 User Data Access

**Implementation:** Permission-based middleware for all routes

```javascript
// security-middleware.js
function requirePermission(permission) {
    return (req, res, next) => {
        const userRole = req.session?.role || ROLES.GUEST;
        if (hasPermission(userRole, permission)) {
            next();
        } else {
            req.auditLogger.logEvent(AUDIT_EVENTS.PERMISSION_DENIED, {/*...*/});
            res.status(403).render('error', { errorMessage: 'Access Denied' });
        }
    };
}
```

**Usage:**
```javascript
// index.js
app.get('/vote', isAuthenticated, requirePermission(PERMISSIONS.VIEW_POLLS), (req, res) => {/*...*/});
app.post('/vote', isAuthenticated, requirePermission(PERMISSIONS.CAST_VOTE), (req, res) => {/*...*/});
```

**Result:** Users can only access resources their role permits

---

### 1.3 Privilege Escalation Prevention

**Implementation:** Default lowest privilege, controlled role changes

```javascript
// rbac-config.js
function getDefaultRole() {
    return ROLES.CUSTOMER; // Lowest privilege
}

// index.js - Registration
const newUser = {
    role: getDefaultRole(), // Always 'customer', never 'admin'
    emailVerified: false,
    // ...
};
```

**Role Change Control:**
```javascript
// index.js - Only admins can change roles
app.post('/admin/update-role', 
    isAdmin, 
    requirePermission(PERMISSIONS.CHANGE_USER_ROLES),
    (req, res) => {
        const { userId, newRole } = req.body;
        user.role = newRole;
        auditLogger.logEvent(AUDIT_EVENTS.ROLE_CHANGE, {/*...*/});
    });
```

**Result:** New users get customer role; only admins can change roles (logged)

---

## 2. Fail-Safe Defaults

### 2.1 New User Defaults

**Implementation:** Secure defaults for all new accounts

```javascript
// index.js - Registration
const newUser = {
    role: getDefaultRole(),        // 'customer' - not 'admin'
    emailVerified: false,          // Email unverified by default
    verificationToken: generateVerificationToken(),
    createdAt: new Date().toISOString()
};
```

**Email Verification:**
```javascript
// email-verification.js
function generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex'); // 256-bit secure token
}

// security-middleware.js
function requireEmailVerification(req, res, next) {
    if (req.session?.emailVerified) {
        next();
    } else {
        res.status(403).render('error', { errorMessage: 'Email verification required' });
    }
}
```

**Result:** Users start with minimal privileges and must verify email

---

### 2.2 Input Validation

**Implementation:** Multi-layer validation (express-validator, SQL injection detection, sanitization)

```javascript
// index.js - Layer 1: express-validator
app.post('/register', [
    body('username').trim().isLength({min: 5, max: 15}).isAlphanumeric(),
    body('email').trim().isEmail().normalizeEmail(),
    body('password').isLength({min: 8}).matches(/[a-z]/).matches(/[A-Z]/).matches(/[0-9]/)
], async (req, res) => {/*...*/});

// Layer 2: SQL Injection Detection
const SQL_INJECTION_PATTERNS = [
    /('|")\s*(OR|AND)\s*('|")?[\d\w]*('|")?\s*=\s*('|")?[\d\w]*('|")?/i,
    /UNION\s+(ALL\s+)?SELECT/i,
    /DROP\s+(TABLE|DATABASE)/i
];

function detectSQLInjection(input) {
    return SQL_INJECTION_PATTERNS.some(pattern => pattern.test(input));
}

// Layer 3: Sanitization
function sanitizeInput(input) {
    if (detectSQLInjection(input)) return '';
    return input.trim().replace(/[<>]/g, '').replace(/['";\\]/g, '');
}
```

**Result:** Malicious inputs blocked at multiple layers

---

### 2.3 Error Messages

**Implementation:** Generic error messages that don't leak information

```javascript
// index.js - Login
const user = users.find(u => u.username === username);

if (!user) {
    auditLogger.logAuthentication(false, username, req.ip, {reason: 'user not found'});
    return res.render('login', { errorMessage: 'Invalid username or password.' });
}

if (!await bcrypt.compare(password, user.passwordHash)) {
    auditLogger.logAuthentication(false, username, req.ip, {reason: 'invalid password'});
    return res.render('login', { errorMessage: 'Invalid username or password.' }); // Same message
}

// Global error handler
app.use((err, req, res, next) => {
    console.error('Error:', err); // Log detailed error server-side
    res.status(500).render('error', {
        errorMessage: 'An unexpected error occurred.' // Generic message
    });
});
```

**Result:** Attackers cannot determine if username exists or password is wrong

---

## 3. Defense-in-Depth

### 3.1 Authentication Layers

**Implementation:** 4-layer authentication (Password → Session → Email → Permission)

```javascript
// Layer 1: Password Authentication
const validPassword = await bcrypt.compare(password, user.passwordHash);

// Layer 2: Session Management
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: { httpOnly: true, maxAge: 3600000 } // 1 hour
}));

// Layer 3: Email Verification
function requireEmailVerification(req, res, next) {
    if (req.session?.emailVerified) next();
    else res.status(403).render('error', {/*...*/});
}

// Layer 4: Permission Check
function requirePermission(permission) {
    return (req, res, next) => {
        if (hasPermission(req.session?.role, permission)) next();
        else res.status(403).render('error', {/*...*/});
    };
}

// Combined usage
app.post('/vote', 
    isAuthenticated, 
    requireEmailVerification, 
    requirePermission(PERMISSIONS.CAST_VOTE), 
    (req, res) => {/*...*/});
```

**Result:** Multiple security layers must pass before sensitive actions

---

### 3.2 Data Validation Layers

**Implementation:** 5-layer validation system

```javascript
// Layer 1: Client-side HTML5
<input type="text" minlength="5" maxlength="15" pattern="[A-Za-z0-9]+" required>

// Layer 2: express-validator
body('username').trim().isLength({min: 5, max: 15}).isAlphanumeric().escape()

// Layer 3: SQL Injection Detection
function sqlInjectionProtection(req, res, next) {
    for (const [key, value] of Object.entries({...req.body, ...req.query})) {
        if (detectSQLInjection(value)) {
            return res.status(400).render('error', {errorMessage: 'Malicious input detected'});
        }
    }
    next();
}

// Layer 4: Sanitization
const sanitized = sanitizeInput(req.body.username);

// Layer 5: EJS Auto-escaping
// <%= username %> - automatically escapes HTML
```

**Result:** Input validated at multiple points, XSS and SQL injection prevented

---

### 3.3 Session Security

**Implementation:** Secure sessions with timeout and rate limiting

```javascript
// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,    // Prevents JavaScript access
        secure: false,     // Set true with HTTPS
        maxAge: 3600000,  // 1 hour timeout
        sameSite: 'strict'
    }
}));

// Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 1000,  // 15 seconds
    max: 10,              // 10 attempts
    skipSuccessfulRequests: true
});

app.post('/login', authLimiter, (req, res) => {/*...*/});

// Security Headers
app.use(helmet({
    contentSecurityPolicy: {/*...*/},
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));
```

**Result:** Sessions auto-expire, brute force attacks blocked, security headers protect against common attacks

---

## 4. Cross-cutting Tests

### 4.1 SQL Injection Protection

**Attack:** `username: admin' OR '1'='1`

**Protection:**
```javascript
const SQL_INJECTION_PATTERNS = [
    /('|")\s*(OR|AND)\s*('|")?[\d\w]*('|")?\s*=\s*('|")?[\d\w]*('|")?/i,
    /UNION\s+(ALL\s+)?SELECT/i,
    /DROP\s+(TABLE|DATABASE)/i
];

function sqlInjectionProtection(req, res, next) {
    for (const [key, value] of Object.entries({...req.body})) {
        if (detectSQLInjection(value)) {
            auditLogger.logSecurityThreat(AUDIT_EVENTS.SQL_INJECTION_BLOCKED, {/*...*/});
            return res.status(400).render('error', {errorMessage: 'Malicious input detected'});
        }
    }
    next();
}
```

**Result:** ✅ SQL injection blocked, logged, generic error shown

---

### 4.2 XSS Protection

**Attack:** `username: <script>alert('XSS')</script>`

**Protection:**
```javascript
// Input validation blocks special characters
body('username').isAlphanumeric().escape()

// EJS auto-escaping
<%= username %> // Renders as: &lt;script&gt;alert('XSS')&lt;/script&gt;

// CSP headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"]
        }
    }
}));
```

**Result:** ✅ XSS payload escaped, displayed as text, not executed

---

### 4.3 IDOR Vulnerability Prevention

**Attack:** User A tries to access User B's data via `/account?userId=2`

**Protection:**
```javascript
// Use session userId ONLY, ignore query parameters
app.get('/account', isAuthenticated, (req, res) => {
    const userId = req.session.userId; // From session, NOT req.query.userId
    const user = users.find(u => u.id === userId);
    res.render('account', { user });
});

// Voting with session-based user ID
app.post('/vote', isAuthenticated, (req, res) => {
    const userId = req.session.userId; // From authenticated session only
    const vote = { userId, pollId, option };
    votes.push(vote);
});
```

**Result:** ✅ Users can only access their own data, session-based authorization

---

### 4.4 Information Leakage Prevention

**Implementation:** Generic errors, hidden stack traces, secure tokens

```javascript
// Generic login errors
if (!user || !validPassword) {
    return res.render('login', { errorMessage: 'Invalid username or password.' });
}

// Hide stack traces
app.use((err, req, res, next) => {
    console.error('Error:', err.stack); // Log server-side only
    res.status(500).render('error', {
        errorMessage: 'An unexpected error occurred.' // Generic only
    });
});

// Cryptographically secure tokens
function generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex'); // 256-bit entropy
}

// Generic token errors
if (!user || user.emailVerified) {
    return res.status(400).render('error', {
        errorMessage: 'The verification token is invalid or has already been used.'
    });
}
```

**Result:** ✅ No information leakage, attackers can't enumerate users or guess tokens

---

## Summary

### Implementation Status

| Category | Implementation | Status |
|----------|---------------|--------|
| **Least Privilege** | 4 roles, 15+ permissions, RBAC | ✅ Complete |
| **Admin Access** | Permission-based admin routes | ✅ Complete |
| **Privilege Escalation** | Default customer role, controlled changes | ✅ Complete |
| **Fail-Safe Defaults** | Lowest privilege, email verification | ✅ Complete |
| **Input Validation** | Multi-layer validation (5 layers) | ✅ Complete |
| **Error Messages** | Generic messages, no info leakage | ✅ Complete |
| **Defense-in-Depth** | 4 auth layers, rate limiting, HSTS | ✅ Complete |
| **SQL Injection** | 22 patterns, detection + blocking | ✅ Complete |
| **XSS Protection** | Input validation, CSP, auto-escaping | ✅ Complete |
| **IDOR Prevention** | Session-based IDs only | ✅ Complete |
| **Information Leakage** | Generic errors, secure tokens | ✅ Complete |

### Testing Checklist

- [x] Customer cannot access admin routes → 403 Forbidden
- [x] Unverified email cannot vote → Email verification required
- [x] SQL injection blocked: `' OR '1'='1` → Malicious input detected
- [x] XSS escaped: `<script>` → Displayed as text
- [x] Login errors don't reveal user existence → Same generic message
- [x] Rate limiting blocks brute force → 429 after 10 attempts
- [x] Sessions timeout after 1 hour → Auto logout
- [x] IDOR prevented → Session-based user ID only
- [x] Stack traces hidden → Generic error messages
- [x] Default role is customer → Privilege escalation prevented

### File Structure

```
secure-voting-app/
├── index.js                      # Main app with security integrations
├── rbac-config.js               # RBAC system (roles, permissions)
├── audit-logger.js              # Audit logging (35+ events)
├── security-middleware.js       # Security middleware functions
├── email-verification.js        # Email verification utilities
└── views/
    ├── audit-logs.ejs          # Admin audit viewer
    ├── manage-roles.ejs        # Admin role management
    └── account.ejs             # User account page
```

**Security Level: Enterprise-Grade 🔒**
