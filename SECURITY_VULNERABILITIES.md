# Security Vulnerabilities Overview

This document summarizes key security vulnerabilities relevant to web applications, especially in the context of voting systems. Each vulnerability is briefly described for awareness and mitigation planning.

---

## 1. SQL Injection
SQL Injection occurs when user input is improperly sanitized and directly included in SQL queries. Attackers can manipulate queries to access, modify, or delete database data.

**Example:**
- Unsanitized input in login forms or search fields.

**Mitigation:**
- Use parameterized queries or ORM frameworks.
- Validate and sanitize all user inputs.

**Code Snippet (Input Validation Preventing SQL Injection):**
```javascript
// Registration route with express-validator
app.post('/register',
	[
		body('username')
			.trim()
			.isLength({ min: 3 }).withMessage('Username must be at least 3 characters')
			.isAlphanumeric().withMessage('Username must only contain letters and numbers'),
		body('password')
			.isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.render('register', { errorMessage: errors.array().map(e => e.msg).join(', ') });
		}
		// ...
	}
);
```
*This validation blocks SQL injection attempts by rejecting malicious input before it reaches the data layer.*

---

## 2. Cross-Site Scripting (XSS)
XSS allows attackers to inject malicious scripts into web pages viewed by other users. This can lead to session hijacking, defacement, or redirection to malicious sites.

**Example:**
- Displaying user-generated content without proper escaping.

**Mitigation:**
- Escape output in HTML, JavaScript, and CSS contexts.
- Use Content Security Policy (CSP).

**Code Snippet (XSS Protection):**
```javascript
// Input sanitization with express-validator
body('newUsername')
	.trim()
	.isLength({ min: 3 })
	.escape(); // Converts < to &lt;, > to &gt;, etc.

// EJS template auto-escaping
<h2>Hello, <%= adminUsername %> 👋</h2>
// If adminUsername = "<script>alert('XSS')</script>", it is rendered as text, not executed.

// Content Security Policy with Helmet
app.use(helmet({
	contentSecurityPolicy: {
		directives: {
			defaultSrc: ["'self'"],
			scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
			styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
		}
	}
}));
```
*This multi-layered approach ensures scripts are never executed, even if injected.*

---

## 3. Weak Authentication
Weak authentication mechanisms make it easier for attackers to gain unauthorized access.

**Example:**
- Simple or predictable passwords.
- Lack of account lockout after repeated failed attempts.

**Mitigation:**
- Enforce strong password policies.
- Implement multi-factor authentication (MFA).
- Use account lockout and monitoring.

**Code Snippet (Strong Authentication):**
```javascript
// Password validation
body('password')
	.isLength({ min: 8 })
	.withMessage('Password must be at least 8 characters')
	.matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])/)
	.withMessage('Password must include uppercase, lowercase, number, and special character');

// Password hashing with bcrypt
const hashedPassword = await bcrypt.hash(password, 10);

// Rate limiting login attempts
const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 5, // Limit each IP to 5 requests per windowMs
	message: 'Too many login attempts, please try again later.'
});
```
*This ensures passwords are strong, hashed, and brute-force attacks are mitigated.*

---

## 4. Improper Error Handling
Improper error handling can leak sensitive information about the application’s internals, aiding attackers.

**Example:**
- Displaying stack traces or database errors to users.

**Mitigation:**
- Show generic error messages to users.
- Log detailed errors securely on the server side only.

**Code Snippet (Error Handling):**
```javascript
// Validation error handling
const errors = validationResult(req);
if (!errors.isEmpty()) {
	return res.render('register', { errorMessage: errors.array().map(e => e.msg).join(', ') });
}

// General error handler
app.use((err, req, res, next) => {
	console.error('Error:', err);
	res.status(500).render('error', {
		errorTitle: 'Server Error',
		errorMessage: 'An unexpected error occurred. Please try again later.'
	});
});
```
*Users see only safe, generic messages; details are logged for developers.*

---

## 5. Improper Data Storage

Storing sensitive data insecurely can lead to data breaches.

**Examples:**
- Storing passwords in plaintext.
- Unencrypted sensitive files or database fields.
- Placing sensitive files (e.g., credentials.json, users.json) in world-readable locations or in the public/ directory, making them accessible to anyone via the web or file system.

**Mitigation:**
- Hash and salt passwords using strong algorithms (e.g., bcrypt).
- Encrypt sensitive data at rest and in transit.
- Store sensitive files outside of publicly accessible directories and restrict file permissions.

**Code Snippet (Password Hashing & Data Storage):**
```javascript
// Hash password before storing
const hashedPassword = await bcrypt.hash(password, 10);
const newUser = {
	id: Date.now().toString(),
	username,
	passwordHash: hashedPassword,
	createdAt: new Date().toISOString()
};
users.push(newUser);
writeJSON(USERS_FILE, users);

// Example users.json entry
{
	"id": "1234567890",
	"username": "testuser",
	"passwordHash": "$2b$10$YW0vpW8y5vipaKDeAVL15Og9jtaGJfP55l4NeAnOEEuRGte2HFA8W"
}
// Example of insecure storage (DO NOT DO THIS):
// Placing sensitive files in the public directory
// public/credentials.json  <-- This would be accessible to anyone via http://yourdomain/credentials.json
// Instead, keep sensitive files in a non-public data/ directory with restricted permissions.
```
*Passwords are never stored in plaintext; only hashes are saved.*

---

## 6. Insecure Sessions
Insecure session management can allow attackers to hijack user sessions.

**Example:**
- Predictable session IDs.
- Not expiring sessions after logout or inactivity.

**Mitigation:**
- Use secure, random session identifiers.
- Set appropriate session timeouts and invalidate sessions on logout.
- Use secure cookies (HttpOnly, Secure, SameSite).

**Code Snippet (Session Security):**
```javascript
// Session configuration
app.use(session({
	secret: 'voting-app-secret-key-2024',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,        // Prevents JavaScript access
		secure: false,         // Set to true with HTTPS in production
		sameSite: 'strict',    // Prevents CSRF
		maxAge: 24 * 60 * 60 * 1000  // 24 hours
	}
}));

// Destroy session on logout
app.get('/logout', (req, res) => {
	req.session.destroy((err) => {
		if (err) console.error('Session destruction error:', err);
		res.redirect('/login');
	});
});
```
*Sessions are securely managed, isolated, and destroyed on logout.*

---

**Note:**
This file is for documentation and awareness only. No changes have been made to the application’s codebase.

---

## 7. Broken Access Control (Admin Privileges)
Improper access control can allow regular users to access admin-only features or data.

**Example:**
- Missing or weak middleware checks for admin routes.

**Mitigation:**
- Always use middleware to verify admin status before allowing access to admin routes.

**Code Snippet (Admin Route Protection):**
```javascript
function isAdmin(req, res, next) {
	if (req.session && req.session.isAdmin) {
		next();
	} else {
		res.redirect('/admin-login');
	}
}

// Usage in route
app.get('/admin', isAdmin, (req, res) => {
	// Only accessible to admins
	res.render('dashboard');
});
```
*This ensures only authenticated admins can access admin pages.*

---

## 8. Insecure Direct Object Reference (IDOR) in Admin Actions
If admin actions (like deleting users or viewing sensitive data) are not properly checked, attackers can manipulate parameters to perform unauthorized actions.

**Example:**
- Allowing any user to access URLs like `/admin/delete-user?id=123` without verifying admin status.

**Mitigation:**
- Always check user roles and permissions on sensitive actions, not just on the client side.

**Code Snippet (IDOR Prevention):**
```javascript
app.post('/admin/delete-user', isAdmin, (req, res) => {
	const userId = req.body.id;
	// Only admins can reach this point
	// ...delete user logic...
	res.send('User deleted');
});
```
*Sensitive admin actions are protected by server-side checks, not just hidden in the UI.*
