// Swarni Chouhan - Admin Portal & Session Management
// Part 4: Admin Authentication, Dashboard, Access Control

const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

// Admin Login Route
app.get('/admin-login', csrfProtection, (req, res) => {
    res.render('admin-login', { 
        errorMessage: null,
        csrfToken: req.csrfToken()
    });
});

app.post('/admin-login', 
    authLimiter, 
    csrfProtection, 
    [
        body('username').trim().escape(),
        body('password').trim()
    ], 
    async (req, res) => {
        try {
            const errors = validationResult(req);
            const username = req.body.username;
            const password = req.body.password;

            const credentials = readJSON(CREDENTIALS_FILE);

            // Verify admin username
            if (username !== credentials.username) {
                logSecurityEvent(`Failed admin login attempt: ${username}`);
                return res.render('admin-login', { 
                    errorMessage: 'Invalid admin credentials.',
                    csrfToken: req.csrfToken()
                });
            }

            // Verify admin password with bcrypt
            const validPassword = await bcrypt.compare(password, credentials.password);

            if (!validPassword) {
                logSecurityEvent(`Failed admin login attempt (wrong password): ${username}`);
                return res.render('admin-login', { 
                    errorMessage: 'Invalid admin credentials.',
                    csrfToken: req.csrfToken()
                });
            }

            // Set admin session
            req.session.isAdmin = true;
            req.session.adminUsername = username;
            req.session.username = username;

            logSecurityEvent(`Successful admin login: ${username}`);
            res.redirect('/admin');
        } catch (error) {
            console.error('Admin login error:', error);
            res.render('admin-login', { 
                errorMessage: 'An error occurred during login.',
                csrfToken: req.csrfToken()
            });
        }
    }
);

// Admin Authorization Middleware
function isAdmin(req, res, next) {
    if (req.session && req.session.isAdmin) {
        next();
    } else {
        res.redirect('/admin-login');
    }
}

// Admin Dashboard Route
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

// Admin Username Change Route (XSS Demo Feature)
app.post('/admin/change-username', 
    isAdmin, 
    csrfProtection, 
    [
        body('newUsername')
            .trim()
            .isLength({ min: 3 }).withMessage('Username must be at least 3 characters')
            .escape()  // Sanitize dangerous characters
    ], 
    (req, res) => {
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
            
            logSecurityEvent(`Admin username changed to: ${newUsername}`);
            
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
    }
);

// Admin Logout Routes
app.get('/admin/logout', (req, res) => {
    const username = req.session.adminUsername;
    req.session.destroy();
    logSecurityEvent(`Admin logged out: ${username}`);
    res.redirect('/admin-login');
});

app.post('/admin/logout', csrfProtection, (req, res) => {
    const username = req.session.adminUsername;
    req.session.destroy();
    logSecurityEvent(`Admin logged out: ${username}`);
    res.redirect('/admin-login');
});

// Session Security Configuration
const sessionConfig = {
    secret: 'voting-app-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,         // Prevents JavaScript access
        secure: false,          // Set true in production with HTTPS
        sameSite: 'strict',     // CSRF protection
        maxAge: 24 * 60 * 60 * 1000  // 24 hours
    }
};

// CSRF Error Handler with Enhanced Error Page
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        logSecurityEvent(`CSRF token error from IP: ${req.ip}`);
        return res.status(403).render('error', {
            session: req.session,
            csrfToken: '',
            errorTitle: 'Security Error',
            errorMessage: 'Invalid security token. Please refresh the page and try again.',
            details: 'This error occurred because your session may have expired or the form was submitted from an unauthorized source. This is a security feature to protect against Cross-Site Request Forgery attacks.'
        });
    }
    next(err);
});

// General Error Handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    logSecurityEvent(`Server error: ${err.message}`);
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

module.exports = {
    isAdmin,
    sessionConfig
};
