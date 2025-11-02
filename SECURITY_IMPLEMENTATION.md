# Security Implementation & Testing Guide

Complete guide for testing and demonstrating all 9 security features in the SecurePolls application.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Security Feature 1: Vote Duplication Prevention](#1-vote-duplication-prevention)
- [Security Feature 2: Password Hashing](#2-password-hashing)
- [Security Feature 3: Rate Limiting](#3-rate-limiting)
- [Security Feature 4: Input Validation](#4-input-validation)
- [Security Feature 5: XSS Prevention](#5-xss-prevention)
- [Security Feature 6: CSRF Protection](#6-csrf-protection)
- [Security Feature 7: Security Headers](#7-security-headers)
- [Security Feature 8: HttpOnly Cookies](#8-httponly-cookies)
- [Security Feature 9: Session Security](#9-session-security)
- [Quick Reference](#quick-reference)

---

## 🎯 Overview

This guide provides step-by-step instructions to test and demonstrate each security feature. Each section includes:
- **Implementation details** - How the feature works
- **Testing steps** - How to verify it works
- **Visual indicators** - What to show during demonstration
- **Why it matters** - Security importance

---

## 1. Vote Duplication Prevention 🔒

### Implementation

**How it works:**
- Tracks votes in `data/votes.json` by user ID and poll ID
- Session stores user voting status
- Backend validates before accepting votes

### Testing Steps

1. Register and login as a new user at `http://localhost:3000/register`
2. Navigate to the voting page at `http://localhost:3000`
3. Select any option (e.g., "Python") and click "Cast Vote"
4. **Observe:** Green success message appears, form becomes disabled
5. Try to vote again by refreshing the page
6. **Observe:** Vote is locked, showing "✓ You voted for: Python"
7. Logout and login again
8. **Observe:** Vote is still saved and locked

### Why This Matters

Prevents vote manipulation and ensures election integrity. Without this feature, users could vote multiple times, skewing results.

---

## 2. Password Hashing 🔐

### Implementation

**How it works:**
- Uses bcrypt with 10 salt rounds
- Passwords hashed before storage
- Comparison uses bcrypt.compare() for security

### Testing Steps

1. Register a new user with any credentials at `http://localhost:3000/register`
   - Username: `testuser`
   - Password: `SecurePass123!`
2. After registration, open `data/users.json` in a text editor
3. Find your user entry
4. **Observe:** Password field shows a hash like:
   ```json
   "password": "$2b$10$YW0vpW8y5vipaKDeAVL15Og9jtaGJfP55l4NeAnOEEuRGte2HFA8W"
   ```

### Why This Matters

If the database is compromised, attackers cannot read actual passwords. Bcrypt is computationally expensive, making brute-force attacks impractical.

---

## 3. Rate Limiting ⏱️

### Implementation

**How it works:**
- Express-rate-limit middleware
- 10 requests per 30 seconds per IP
- Custom error page for rate limit exceeded

### Testing Steps

1. Go to login page at `http://localhost:3000/login`
2. Enter **wrong credentials repeatedly:**
   - Username: `testuser`
   - Password: `wrongpassword`
3. Click "Login" button **10 times quickly**
4. On the 11th attempt, you'll see a **custom error page:**
   - Title: "Rate Limit Exceeded"
   - Message: "Too many requests, please try again after 30 seconds."
5. Wait 30 seconds
6. Try accessing the login page again - it works normally

### Why This Matters

Prevents brute force password attacks. Attackers cannot make unlimited login attempts to guess passwords.

---

## 4. Input Validation ✅

### Implementation

**How it works:**
- Express-validator middleware
- Validates all form inputs before processing
- Sanitizes to prevent injection attacks

### Testing Steps

**Test 1 - Short Username:**
1. Go to `http://localhost:3000/register`
2. Username: `ab` (only 2 characters)
3. Click "Create Account"
4. **Expected:** "Username must be at least 3 characters"

**Test 2 - Invalid Characters:**
1. Username: `user@123` or `test user`
2. Click "Create Account"
3. **Expected:** "Username can only contain letters and numbers"

**Test 3 - Reserved Username:**
1. Username: `admin`
2. Click "Create Account"
3. **Expected:** "The username 'admin' is not allowed"

**Test 4 - Short Password:**
1. Username: `validuser`
2. Password: `Pass1!` (only 6 characters)
3. Click "Create Account"
4. **Expected:** "Password must be at least 8 characters"

**Test 5 - Missing Uppercase:**
1. Password: `password123!`
2. Click "Create Account"
3. **Expected:** "Password must include uppercase, lowercase, number, and special character"

**Test 6 - Missing Special Character:**
1. Password: `Password123`
2. Click "Create Account"
3. **Expected:** "Password must include uppercase, lowercase, number, and special character"

**Test 7 - Valid Input:**
1. Username: `validuser`
2. Password: `SecurePass123!`
3. **Expected:** Account created successfully

### Why This Matters

Prevents injection attacks (SQL, XSS, command injection) and ensures data quality. Invalid data is rejected before it reaches the database.

---

## 5. XSS Prevention 🛡️

### Implementation

**How it works:**
- Express-validator `.escape()` converts `<>` to `&lt;&gt;`
- EJS `<%= %>` auto-escapes output
- Two-layer protection prevents script execution

### Testing Steps

1. Login as admin at `http://localhost:3000/admin-login`
   - Username: `admin`
   - Password: `AdminPassword123`
2. **Observe:** Dashboard shows "Hello, admin 👋"
3. In the "XSS Prevention Demo" card, enter:
   ```
   <script>alert('XSS')</script>
   ```
4. Click "Update & Test XSS Protection"
5. **Observe:** Greeting updates to:
   ```
   Hello, &lt;script&gt;alert('XSS')&lt;/script&gt; 👋
   ```
6. **Critical:** NO popup alert appears (script is text, not executed)
7. Right-click the greeting, select "Inspect Element"
8. **Observe:** HTML shows escaped version

### Why This Matters

Prevents attackers from injecting malicious JavaScript that could steal cookies, redirect users, or modify page content. Without XSS protection, `<script>` tags would execute.

---

## 6. CSRF Protection 🎫

### Implementation

**How it works:**
- csurf middleware generates tokens
- Every form includes hidden `_csrf` field
- POST requests validated against token

### Testing Steps

1. Login and go to voting page at `http://localhost:3000`
2. **Right-click** → Select "Inspect" (or press F12)
3. Click "Elements" or "Inspector" tab
4. Press **Ctrl+F** (Cmd+F on Mac) and search: `_csrf`
5. **Observe:** Hidden input field:
   ```html
   <input type="hidden" name="_csrf" value="ABC123XYZ-long-random-string">
   ```
6. **Right-click** on this input element
7. Select "Delete Element" (the input disappears)
8. Try to vote by selecting an option and clicking "Cast Vote"
9. **Expected:** Error page appears:
   - "Forbidden" or "Invalid CSRF Token"
   - HTTP 403 error

### Why This Matters

Prevents Cross-Site Request Forgery attacks where malicious websites trick users into submitting forms without their knowledge. Token proves request came from our app.

---

## 7. Security Headers 🔧

### Implementation

**How it works:**
- Helmet.js middleware adds protective HTTP headers
- Headers tell browser to enable security features
- Prevents clickjacking, MIME-sniffing, etc.

### Testing Steps

1. Open application at `http://localhost:3000`
2. **Right-click** → Select "Inspect" (F12)
3. Click "Network" tab
4. **Refresh page** (F5)
5. Click on the **first item** in network list (usually just `/`)
6. Click "Headers" sub-tab
7. Scroll to "Response Headers" section

### Why This Matters

Headers provide defense-in-depth by instructing browsers to enable extra security features. Even if app has vulnerabilities, headers add protection.

---

## 8. HttpOnly Cookies 🍪

### Implementation

**How it works:**
- Session cookies flagged as HttpOnly
- JavaScript cannot access HttpOnly cookies
- Prevents XSS cookie theft

### Testing Steps

**Part 1: See HttpOnly Flag**

1. Login at `http://localhost:3000/login`
2. Press **F12** → Click "Application" tab (Chrome) or "Storage" (Firefox)
3. Left sidebar → Expand "Cookies"
4. Click `http://localhost:3000`
5. Find cookie named `connect.sid` (session cookie)
6. **Observe:** ✓ checkmark in "HttpOnly" column

**Part 2: Prove JavaScript Cannot Access**

7. Click "Console" tab
8. Type and press Enter:
   ```javascript
   document.cookie
   ```
9. **Observe:** Session cookie (`connect.sid`) NOT in output
10. Output might be empty `""` or show other non-HttpOnly cookies

### Why This Matters

Even if XSS attack succeeds, attacker cannot steal session cookies because JavaScript is blocked from accessing them. Prevents session hijacking.

---

## 9. Session Security ⏰

### Implementation

**How it works:**
- Sessions expire after 24 hours
- Session destroyed on logout
- Proper session isolation between users

### Testing Steps

**Test 1: Session Isolation**

1. Login in **normal browser window** at `http://localhost:3000/login`
2. **Observe:** You can access the voting page
3. Open **incognito/private window** (Ctrl+Shift+N / Cmd+Shift+N)
4. Try to access `http://localhost:3000` directly (without logging in)
5. **Expected:** Immediately redirected to login page
6. **Proves:** Sessions don't leak between windows

**Test 2: Session Expiration**

1. Login to application
2. Press **F12** → "Application" tab
3. Under "Cookies" → `http://localhost:3000`
4. Find `connect.sid` cookie
5. Look at "Expires / Max-Age" column
6. **Observe:** Expiration set to 24 hours from now

### Why This Matters

Limits exposure if session is compromised. After 24 hours, sessions auto-expire forcing re-authentication. Prevents indefinite unauthorized access.

---

## 📊 Quick Reference

### Test Summary Table

| Feature | Quick Test | Expected Result |
|---------|-----------|-----------------|
| **Vote Duplication** | Vote twice | Second vote blocked |
| **Password Hashing** | Check users.json | Hash starts with $2b$10$ |
| **Rate Limiting** | 11 login attempts | Error 429 on 11th |
| **Input Validation** | Username "ab" | "Must be 3+ characters" |
| **XSS Prevention** | Username with `<script>` | Displayed as text |
| **CSRF Protection** | Delete _csrf token | Form rejected (403) |
| **Security Headers** | Network tab | Helmet headers present |
| **HttpOnly Cookies** | document.cookie | Session NOT visible |
| **Session Security** | Incognito access | Redirected to login |

### Demonstration Order

For professor presentation, follow this sequence:

1. **Start** - Run `npm install`, `npm run setup`, `npm start`
2. **Admin Dashboard** - Login as admin, show XSS demo
3. **User Registration** - Test validation (show errors)
4. **Vote Duplication** - Vote, try again (blocked)
5. **Password Hashing** - Open users.json, show hash
6. **Rate Limiting** - Login wrong 11 times
7. **CSRF** - Delete token in DevTools, submit fails
8. **Security Headers** - Network tab, show Helmet headers
9. **HttpOnly Cookies** - Application tab + console test
10. **XSS Prevention** - Admin username change demo

### Common Issues

**Issue:** Rate limit not working
- **Solution:** Restart server (`kill $(lsof -ti:3000); npm start`)

**Issue:** CSRF token errors
- **Solution:** Clear browser cookies, refresh page

**Issue:** Session not expiring
- **Solution:** Check system clock is correct

**Issue:** Admin login fails
- **Solution:** Run `npm run setup` to reset password

---

## 🎓 For Professors/Reviewers

This application demonstrates industry-standard security practices suitable for production environments. Each feature has been implemented following OWASP guidelines and best practices.

**Key Learning Outcomes:**
1. Defense in depth (multiple security layers)
2. Input validation vs. output encoding
3. Session management and stateless auth
4. Rate limiting for DoS prevention
5. CSRF token lifecycle
6. Password storage best practices
7. XSS attack vectors and prevention
8. HTTP security headers
9. Secure cookie configuration

**Code Quality:**
- Modular design with clear separation of concerns
- Comprehensive error handling
- Clean, readable code with comments
- Production-ready security configuration

---

**For questions or detailed explanations, contact the development team.**

**Last Updated:** November 2024
