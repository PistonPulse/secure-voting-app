# Swarni Chouhan's Contribution# Swarni Chouhan - Contribution Summary



## Role: Admin Portal & Security Features Developer## Part 4: Admin Portal & Session Management



### Responsibilities### Responsibilities

- Implemented admin authentication system

- Created admin dashboardImplemented complete admin authentication system, session management, and access control middleware.

- Built security features documentation page

- Implemented CSRF error handling### Files Contributed



---**1. admin-login.ejs** - Admin Login Page

- Designed admin-specific login interface

## Code Contributions- Distinguished visual design from user login

- Added password change success message

### 1. Admin Authentication System- Admin-only branding and styling



**Admin Login Route:****2. dashboard.ejs** - Admin Dashboard

```javascript- Created admin control panel

app.post('/admin/login', loginLimiter, [- Shows registered user count

    body('password').notEmpty()- Links to security settings

], async (req, res) => {- Links to results and public poll

    const errors = validationResult(req);- Clean card-based layout

    if (!errors.isEmpty()) {

        return res.render('admin-login', {**3. security.ejs** - Admin Password Change Page

            title: 'Admin Login',- Password change form

            error: 'Please enter the admin password',- Current password verification

            csrfToken: req.csrfToken(),- New password confirmation

            isAuthenticated: false,- Error and success message display

            showNav: false

        });**4. admin_routes.js** - Admin System Implementation

    }- Session configuration with express-session

- requireUserLogin middleware

    const { password } = req.body;- requireAdmin middleware

    const credentials = readJSON(CREDENTIALS_FILE);- Admin login route (GET and POST)

- Admin logout functionality

    // Verify admin password with bcrypt- Admin dashboard route

    const passwordMatch = await bcrypt.compare(password, credentials.adminPasswordHash);- Admin password change system

    - HttpOnly cookie management

    if (!passwordMatch) {

        return res.render('admin-login', {### Security Features Implemented

            title: 'Admin Login',

            error: 'Invalid admin password',🔒 **Session Security (express-session)**

            csrfToken: req.csrfToken(),- Configured secure session management

            isAuthenticated: false,- HttpOnly cookies prevent JavaScript access

            showNav: false- SameSite: strict for CSRF protection

        });- 24-hour session lifetime

    }- Secure: false (set to true in production with HTTPS)

- resave: false, saveUninitialized: false

    // Set admin session

    req.session.isAdmin = true;🍪 **HttpOnly Cookies**

    req.session.adminAuthenticated = true;- Admin authentication via httpOnly cookie

- Cookie inaccessible to client-side JavaScript

    res.redirect('/admin/dashboard');- Prevents XSS-based session theft

});- Proper cookie clearing on logout

```

🛡️ **Access Control Middleware**

---- requireUserLogin: Protects user routes

- requireAdmin: Protects admin routes

### 2. Admin Authorization Middleware- Automatic redirect if not authenticated

- Session-based user identification

**RequireAdmin Middleware:**

```javascript🔐 **Admin Password Security**

function requireAdmin(req, res, next) {- bcrypt password hashing for admin

    if (!req.session.isAdmin) {- Current password verification before change

        return res.status(403).render('error', {- Password confirmation requirement

            title: 'Access Denied',- Minimum 8 character password requirement

            statusCode: 403,- Forced logout after password change

            message: 'Admin access required',

            details: 'You must be logged in as an administrator to access this page.',### Technical Skills Demonstrated

            isAuthenticated: !!req.session.userId,

            csrfToken: req.csrfToken()- Express.js middleware development

        });- Session management configuration

    }- Cookie security (httpOnly, sameSite)

    next();- bcrypt password comparison

}- Access control logic

```- Route protection

- Admin authentication flow

---- Password change workflow



### 3. Admin Dashboard### Lines of Code



**Admin Dashboard Route:**- admin_routes.js: 210 lines

```javascript- admin-login.ejs: 85 lines

app.get('/admin/dashboard', requireAdmin, (req, res) => {- dashboard.ejs: 70 lines

    const polls = readJSON(POLLS_FILE);- security.ejs: 95 lines

    const users = readJSON(USERS_FILE);- **Total: ~460 lines**

    const votes = readJSON(VOTES_FILE);

### Key Implementation Details

    const stats = {

        totalUsers: users.length,**Session Configuration:**

        totalVotes: Object.values(votes).flat().length,```javascript

        totalPolls: polls.lengthapp.use(session({

    };    secret: 'your-secret-key-change-in-production',

    resave: false,

    res.render('dashboard', {    saveUninitialized: false,

        title: 'Admin Dashboard',    cookie: { 

        isAdmin: true,        httpOnly: true,

        stats,        secure: false,

        polls,        sameSite: 'strict',

        isAuthenticated: true,        maxAge: 24 * 60 * 60 * 1000

        csrfToken: req.csrfToken()    }

    });}));

});```

```

**Middleware Logic:**

---```javascript

const requireAdmin = (req, res, next) => {

### 4. Enhanced CSRF Error Handling    if (req.cookies.isAdmin === 'true') {

        req.session.isAdmin = true;

**CSRF Error Handler:**        next();

```javascript    } else {

app.use((err, req, res, next) => {        res.redirect('/admin/login');

    if (err.code === 'EBADCSRFTOKEN') {    }

        return res.status(403).render('error', {};

            title: 'CSRF Token Error',```

            statusCode: 403,

            message: 'Invalid or missing CSRF token.',**Admin Authentication Flow:**

            details: 'This error occurred because your session may have expired or the form was submitted from an unauthorized source. Please refresh the page and try again. This is a security feature to protect against Cross-Site Request Forgery attacks.',1. User visits /admin/login

            isAuthenticated: !!req.session.userId,2. Submits username and password

            csrfToken: req.csrfToken ? req.csrfToken() : ''3. System verifies username is 'admin'

        });4. bcrypt compares password with stored hash

    }5. If valid, sets httpOnly cookie: isAdmin = 'true'

    next(err);6. Redirects to /admin/dashboard

});7. Dashboard protected by requireAdmin middleware

```

**Password Change Security:**

---1. Verify current password with bcrypt

2. Check new password matches confirmation

### 5. Security Features Documentation Page3. Hash new password with bcrypt (10 salt rounds)

4. Save new hash to credentials.json

**Security Page Route:**5. Clear admin cookie (forces re-login)

```javascript6. Redirect to login with success message

app.get('/security', (req, res) => {

    res.render('security', {**Security Logging:**

        title: 'Security Features',- Failed admin login attempts

        isAuthenticated: !!req.session.userId,- Successful admin logins

        csrfToken: req.csrfToken()- Password change attempts (success and failure)

    });- IP address tracking

});

```---



**Security Features Documented:****Contribution Date:** October 2025  

1. Vote Duplication Prevention**Project:** SecurePolls - Secure Voting Application

2. Password Hashing (bcrypt)
3. Rate Limiting
4. Input Validation & Sanitization
5. XSS Prevention
6. CSRF Protection
7. Security Headers (Helmet.js)
8. HttpOnly Cookies
9. Session Expiry

---

### 6. Error Page with Visual Hierarchy

**Error Rendering:**
```javascript
// Enhanced error page with color-coded sections
res.render('error', {
    title: 'Error Title',
    statusCode: 403,
    message: 'What went wrong',
    details: 'How to fix it',
    isAuthenticated: !!req.session.userId,
    csrfToken: req.csrfToken()
});
```

---

## Files Modified/Created

1. **index.js** (Admin sections)
   - Admin login route (~50 lines)
   - Admin middleware (~20 lines)
   - Admin dashboard route (~35 lines)
   - CSRF error handler (~25 lines)
   - Security page route (~15 lines)

2. **views/admin-login.ejs**
   - Admin login form
   - Security notice section

3. **views/security.ejs**
   - Complete security documentation
   - Feature descriptions with examples

4. **views/error.ejs**
   - Enhanced error page
   - Color-coded sections (red ERROR, yellow "What Happened", blue "What You Can Do")

---

## Testing & Validation

### Admin Authentication Tested:
- ✅ Password verification with bcrypt
- ✅ Session creation for admin
- ✅ Rate limiting (5 attempts per 15 min)
- ✅ Unauthorized access prevention

### Admin Dashboard Tested:
- ✅ Statistics display (users, votes, polls)
- ✅ Poll data visualization
- ✅ Admin-only access control

### Security Features Tested:
- ✅ CSRF token validation
- ✅ Error handling for expired tokens
- ✅ Clear error messages
- ✅ Security headers active

### Documentation Tested:
- ✅ All 9 features documented
- ✅ Code examples provided
- ✅ Clear explanations
- ✅ Visual hierarchy

---

## Key Achievements

1. **Admin Portal**: Created secure admin authentication and dashboard
2. **CSRF Protection**: Implemented comprehensive CSRF error handling with helpful messages
3. **Security Documentation**: Documented all 9 security features with examples
4. **Error Handling**: Enhanced error pages with visual hierarchy and actionable guidance

---

## Lines of Code: ~460

**Breakdown:**
- Admin authentication: ~120 lines
- Admin dashboard: ~80 lines
- Error handling: ~90 lines
- Security documentation: ~120 lines
- Middleware: ~50 lines

---

## Skills Demonstrated

- Admin Portal Development
- Authorization & Access Control
- CSRF Protection
- Error Handling
- Technical Documentation
- Security Best Practices
- User Experience Design

---

**Date:** November 2024  
**Project:** Secure Voting Application  
**Status:** ✅ Complete
