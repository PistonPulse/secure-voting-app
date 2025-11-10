// Tanish Shah - Authentication & User Management
// Part 2: Registration, Login, Password Hashing, Input Validation

const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

// Input Sanitization Function
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input.trim().replace(/[<>]/g, ''); // Remove dangerous characters
}

// User Registration Route with Validation
app.post('/register', 
    authLimiter,
    csrfProtection,
    [
        // Username validation
        body('username')
            .trim()
            .isLength({ min: 3 }).withMessage('Username must be at least 3 characters')
            .isAlphanumeric().withMessage('Username must only contain letters and numbers (no spaces or symbols)')
            .custom(value => {
                if (value.toLowerCase() === 'admin') {
                    throw new Error('The username "admin" is not allowed');
                }
                return true;
            }),
        
        // Password validation - Strong requirements
        body('password')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]/)
            .withMessage('Password must include uppercase, lowercase, number, and special character (@$!%*?&#)')
    ],
    async (req, res) => {
        try {
            // Check validation errors
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                const errorMessages = errors.array().map(e => e.msg).join(', ');
                return res.render('register', { 
                    errorMessage: errorMessages,
                    csrfToken: req.csrfToken()
                });
            }

            const username = sanitizeInput(req.body.username);
            const password = req.body.password;

            const users = readJSON(USERS_FILE);

            // Check for duplicate username
            if (users.find(u => u.username === username)) {
                return res.render('register', { 
                    errorMessage: 'Username already exists.',
                    csrfToken: req.csrfToken()
                });
            }

            // Hash password with bcrypt (10 salt rounds)
            const hashedPassword = await bcrypt.hash(password, 10);
            
            const newUser = {
                id: Date.now().toString(),
                username,
                passwordHash: hashedPassword,
                lastVote: null,
                createdAt: new Date().toISOString()
            };

            users.push(newUser);
            writeJSON(USERS_FILE, users);

            // Log successful registration
            logSecurityEvent(`User registered: ${username}`);

            // Auto-login after registration
            req.session.userId = newUser.id;
            req.session.username = newUser.username;
            res.redirect('/');
        } catch (error) {
            console.error('Registration error:', error);
            res.render('register', { 
                errorMessage: 'An error occurred during registration.',
                csrfToken: req.csrfToken()
            });
        }
    }
);

// User Login Route with bcrypt Password Verification
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
                logSecurityEvent(`Failed login attempt (user not found): ${username}`);
                return res.render('login', { 
                    errorMessage: 'Invalid username or password.',
                    csrfToken: req.csrfToken()
                });
            }

            // Verify password with bcrypt
            const validPassword = await bcrypt.compare(password, user.passwordHash || user.password);

            if (!validPassword) {
                logSecurityEvent(`Failed login attempt (wrong password): ${username}`);
                return res.render('login', { 
                    errorMessage: 'Invalid username or password.',
                    csrfToken: req.csrfToken()
                });
            }

            // Create session
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.isAdmin = false;

            logSecurityEvent(`Successful login: ${username}`);
            res.redirect('/');
        } catch (error) {
            console.error('Login error:', error);
            res.render('login', { 
                errorMessage: 'An error occurred during login.',
                csrfToken: req.csrfToken()
            });
        }
    }
);

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Logout Route - Destroys session
app.get('/logout', (req, res) => {
    const username = req.session.username;
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        logSecurityEvent(`User logged out: ${username}`);
        res.redirect('/login');
    });
});

app.post('/logout', csrfProtection, (req, res) => {
    const username = req.session.username;
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        logSecurityEvent(`User logged out: ${username}`);
        res.redirect('/login');
    });
});

// Export functions
module.exports = {
    sanitizeInput,
    isAuthenticated
};
