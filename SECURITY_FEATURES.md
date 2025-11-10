# Security Features Implementation Guide

This document provides a detailed explanation of each security mechanism implemented in the Secure Voting Application, including the technologies used and implementation approach.

---

## 1. Vote Duplication Prevention

### **Purpose**
Ensures each user can vote only once per poll, maintaining election integrity.

### **Technology Used**
- **JSON File Storage** (`votes.json`)
- **Session Management** (express-session)
- **Server-side Validation** (Node.js/Express)

### **Implementation**
- Each vote is stored with the user's unique identifier and poll ID
- Before accepting a new vote, the system checks `votes.json` to see if a record exists with the same `username` and `pollId`
- Validation occurs on the server side to prevent client-side manipulation
- Users attempting to vote twice receive an error message and are redirected

```javascript
// Check if user has already voted
const existingVote = votes.find(v => v.username === username && v.pollId === pollId);
if (existingVote) {
    return res.render('error', { errorMessage: 'You have already voted in this poll.' });
}
```

---

## 2. Password Hashing with bcrypt

### **Purpose**
Protects user passwords by storing them as irreversible cryptographic hashes instead of plain text.

### **Technology Used**
- **bcrypt.js v5.1.1** - Industry-standard password hashing library
- **Salt Rounds**: 10 (2^10 iterations)

### **Implementation**
- During registration, plain text passwords are hashed using bcrypt with 10 salt rounds
- The hash is stored in `users.json` and `credentials.json` instead of the actual password
- During login, the entered password is compared with the stored hash using `bcrypt.compare()`
- Even if the database is compromised, passwords remain protected

```javascript
// Registration - Hash password
const hashedPassword = await bcrypt.hash(password, 10);

// Login - Compare password
const validPassword = await bcrypt.compare(password, user.password);
```

---

## 3. Rate Limiting

### **Purpose**
Prevents brute-force attacks, DDoS attacks, and credential stuffing by limiting request frequency.

### **Technology Used**
- **express-rate-limit v7.1.5** - Middleware for Express.js
- **In-memory Storage** - Tracks requests per IP address

### **Implementation**
- **General Rate Limiter**: 30 requests per 15 seconds per IP
- **Authentication Rate Limiter**: 10 login attempts per 15 seconds per IP
- Excludes static assets (CSS, JS, images, fonts) from counting
- Blocked users receive an HTML error page with countdown timer
- Automatically resets after the time window expires

```javascript
// Authentication-specific rate limiter
const authLimiter = rateLimit({
    windowMs: 15 * 1000,  // 15 seconds
    max: 10,               // 10 requests per window
    message: 'Too many authentication attempts...'
});
```

---

## 4. Input Validation & Sanitization

### **Purpose**
Ensures all user inputs are properly validated and sanitized to prevent injection attacks and data corruption.

### **Technology Used**
- **express-validator v7.0.1** - Validation and sanitization middleware
- **Built-in Methods**: `trim()`, `escape()`, `isLength()`, `isStrongPassword()`

### **Implementation**
- All form inputs are validated using middleware chains
- **Sanitization**: Removes whitespace (`trim()`), escapes HTML entities (`escape()`)
- **Validation Rules**:
  - Usernames: 3-20 characters, alphanumeric
  - Passwords: Minimum 8 characters, requires uppercase, lowercase, number, symbol
  - Email: Valid email format
- Invalid inputs are rejected before database operations

```javascript
[
    body('username')
        .trim()
        .isLength({ min: 3, max: 20 })
        .escape(),
    body('password')
        .isStrongPassword({
            minLength: 8,
            minUppercase: 1,
            minLowercase: 1,
            minNumbers: 1,
            minSymbols: 1
        })
]
```

---

## 5. XSS (Cross-Site Scripting) Prevention

### **Purpose**
Prevents malicious scripts from being injected and executed in users' browsers.

### **Technology Used**
- **EJS Template Engine v3.1.9** - Auto-escaping by default
- **express-validator** - Input sanitization
- **Content Security Policy** (via Helmet)

### **Implementation**
- **Automatic Escaping**: EJS templates use `<%= %>` syntax which automatically escapes HTML
- **Manual Sanitization**: `escape()` method converts `<`, `>`, `&`, `'`, `"` to HTML entities
- **CSP Headers**: Restrict script sources to same-origin only
- Example: `<script>alert('XSS')</script>` becomes `&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;`

```javascript
// EJS auto-escaping
<p>Welcome, <%= username %></p>  // Automatically escapes HTML

// Manual sanitization
body('username').trim().escape()
```

---

## 6. CSRF (Cross-Site Request Forgery) Protection

### **Purpose**
Prevents unauthorized commands from being transmitted from a user that the web application trusts.

### **Technology Used**
- **csurf v1.11.0** - CSRF middleware for Express
- **Double Submit Cookie Pattern**
- **Synchronizer Token Pattern**

### **Implementation**
- A unique CSRF token is generated for each session
- Token is embedded in all forms as a hidden field
- Server validates the token on POST/PUT/DELETE requests
- Requests without valid tokens are rejected with 403 error
- Tokens expire with the session (24 hours)

```javascript
// Generate token in route
app.get('/vote', csrfProtection, (req, res) => {
    res.render('vote', { csrfToken: req.csrfToken() });
});

// Validate token in form
<input type="hidden" name="_csrf" value="<%= csrfToken %>">
```

---

## 7. Security Headers (Helmet)

### **Purpose**
Sets various HTTP headers to protect against common web vulnerabilities.

### **Technology Used**
- **Helmet v7.1.0** - Security header middleware collection

### **Implementation**
Helmet configures 11 security headers automatically:

1. **Content-Security-Policy**: Prevents XSS by controlling resource loading
2. **X-DNS-Prefetch-Control**: Controls browser DNS prefetching
3. **X-Frame-Options**: Prevents clickjacking (DENY)
4. **X-Powered-By**: Removed to hide Express.js
5. **Strict-Transport-Security**: Enforces HTTPS (HSTS)
6. **X-Download-Options**: Prevents IE from executing downloads
7. **X-Content-Type-Options**: Prevents MIME-sniffing
8. **X-Permitted-Cross-Domain-Policies**: Controls Adobe Flash/PDF policies
9. **Referrer-Policy**: Controls referrer information leakage
10. **Cross-Origin-Embedder-Policy**: Isolates resources
11. **Cross-Origin-Opener-Policy**: Isolates browsing contexts

```javascript
app.use(helmet());  // Applies all 11 security headers
```

---

## 8. HttpOnly Cookies

### **Purpose**
Prevents client-side JavaScript from accessing session cookies, protecting against XSS attacks.

### **Technology Used**
- **express-session v1.17.3** - Session management middleware
- **Cookie Flags**: httpOnly, sameSite, secure

### **Implementation**
- Session cookies are marked with `httpOnly: true` flag
- JavaScript code cannot access cookies via `document.cookie`
- **Additional Protections**:
  - `sameSite: 'strict'` - Prevents CSRF attacks
  - `secure: true` - HTTPS-only transmission (production)
  - `maxAge: 24 hours` - Automatic expiration

```javascript
cookie: {
    httpOnly: true,        // No JavaScript access
    secure: false,         // Set true in production with HTTPS
    sameSite: 'strict',    // CSRF protection
    maxAge: 24 * 60 * 60 * 1000  // 24 hours
}
```

---

## 9. Session Security

### **Purpose**
Securely manages user authentication state and prevents session hijacking.

### **Technology Used**
- **express-session v1.17.3** - Server-side session storage
- **Secret Key** - Session encryption
- **Session Flags** - Security configurations

### **Implementation**
- **Server-side Storage**: Session data stored on server, not client
- **Secret Key**: Sessions encrypted with secret key (`voting-app-secret-key-2024`)
- **Session Configurations**:
  - `resave: false` - Don't save unchanged sessions
  - `saveUninitialized: false` - Don't create sessions for unauthenticated users
  - `rolling: true` - Refresh expiration on activity
- **Session Destruction**: Proper logout destroys session completely

```javascript
req.session.destroy(err => {
    if (err) {
        console.error('Session destruction error:', err);
    }
    res.redirect('/login');
});
```

---

## Security Logging

### **Additional Feature**
All security-relevant events are logged with timestamps for audit trails.

### **Events Logged**
- User registration and login attempts
- Failed authentication attempts
- Admin login/logout
- Vote submissions
- CSRF token errors
- Rate limiting triggers
- Username changes

### **Implementation**
```javascript
function logSecurityEvent(message) {
    const timestamp = new Date().toISOString();
    console.log(`[SECURITY] ${timestamp} - ${message}`);
}
```

---

## Technology Stack Summary

| Feature | Primary Technology | Version |
|---------|-------------------|---------|
| Backend Framework | Express.js | 4.18.2 |
| Password Hashing | bcrypt | 5.1.1 |
| Rate Limiting | express-rate-limit | 7.1.5 |
| Input Validation | express-validator | 7.0.1 |
| CSRF Protection | csurf | 1.11.0 |
| Security Headers | helmet | 7.1.0 |
| Session Management | express-session | 1.17.3 |
| Template Engine | EJS | 3.1.9 |
| Data Storage | JSON Files | Native |

---

## Security Best Practices Followed

1. ✅ **Defense in Depth**: Multiple layers of security
2. ✅ **Principle of Least Privilege**: Users get minimal necessary permissions
3. ✅ **Secure by Default**: Security features enabled by default
4. ✅ **Input Validation**: All inputs validated and sanitized
5. ✅ **Output Encoding**: All outputs properly escaped
6. ✅ **Secure Session Management**: HttpOnly, SameSite cookies
7. ✅ **Password Security**: Strong hashing with bcrypt
8. ✅ **Rate Limiting**: Protection against brute-force attacks
9. ✅ **Security Logging**: Audit trail for security events
10. ✅ **Error Handling**: User-friendly errors without sensitive information

---

## Testing the Security Features

### 1. Vote Duplication Prevention
- Register and login as a user
- Vote in a poll
- Try voting again → Should be blocked

### 2. Password Hashing
- Check `users.json` → Passwords are hashed, not plain text

### 3. Rate Limiting
- Spam the login page → Should be blocked after 10 attempts in 15 seconds

### 4. Input Validation
- Try registering with weak password → Should be rejected
- Try username with special characters → Should be sanitized

### 5. XSS Prevention
- Try changing admin username to `<script>alert('XSS')</script>`
- Check rendered page → Script should be escaped as text

### 6. CSRF Protection
- Try submitting a form without CSRF token → Should get 403 error

### 7. Security Headers
- Open DevTools → Network tab → Check response headers
- Should see X-Frame-Options, CSP, etc.

### 8. HttpOnly Cookies
- Open DevTools → Application → Cookies
- Session cookie should have HttpOnly flag

### 9. Session Security
- Login → Close browser → Session should expire after 24 hours

---

## Future Enhancements

1. **HTTPS/TLS**: Implement SSL certificates for encrypted communication
2. **Database Migration**: Move from JSON to PostgreSQL/MongoDB
3. **2FA**: Add two-factor authentication
4. **OAuth**: Integrate Google/GitHub login
5. **Audit Logs**: Store security logs in database
6. **Anomaly Detection**: AI-based suspicious activity detection
7. **Password Policies**: Enforce password expiration
8. **Account Lockout**: Lock accounts after multiple failed attempts

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/)
- [bcrypt npm documentation](https://www.npmjs.com/package/bcrypt)
- [Helmet.js documentation](https://helmetjs.github.io/)

---

**Last Updated**: November 10, 2025  
**Developed by**: Daksh Mishra, Swarni Chouhan, Tanish Gupta, Tanish Shah
