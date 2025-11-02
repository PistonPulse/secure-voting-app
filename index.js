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

const app = express();
const PORT = 3000;

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
}

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
            imgSrc: ["'self'", "data:", "https:", "https://images.unsplash.com"]
        }
    }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());

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

const generalLimiter = rateLimit({
    windowMs: 30 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).render('error', {
            session: req.session,
            csrfToken: req.csrfToken ? req.csrfToken() : '',
            errorTitle: 'Rate Limit Exceeded',
            errorMessage: 'Too many requests, please try again after 30 seconds.'
        });
    }
});

app.use(generalLimiter);

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

function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input.trim().replace(/[<>]/g, '');
}

function logSecurityEvent(message) {
    const logStream = fs.createWriteStream(path.join(logsDir, 'security.log'), { flags: 'a' });
    logStream.write(`[${new Date().toISOString()}] ${message}\n`);
    logStream.end();
}

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

app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { 
        errorMessage: null,
        csrfToken: req.csrfToken()
    });
});

app.post('/register', 
    csrfProtection,
    [
        // --- New, Stronger Username Rules ---
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
        
        // --- Password Rule ---
        body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
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
        const password = req.body.password;

        const users = readJSON(USERS_FILE);

        if (users.find(u => u.username === username)) {
            return res.render('register', { 
                errorMessage: 'Username already exists.',
                csrfToken: req.csrfToken()
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Date.now().toString(),
            username,
            passwordHash: hashedPassword,
            lastVote: null
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
});

app.get('/login', csrfProtection, (req, res) => {
    res.render('login', { 
        errorMessage: null,
        csrfToken: req.csrfToken()
    });
});

app.post('/login', 
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

        const validPassword = await bcrypt.compare(password, user.passwordHash || user.password);

        if (!validPassword) {
            logSecurityEvent(`Failed login attempt (wrong password): ${username}`);
            return res.render('login', { 
                errorMessage: 'Invalid username or password.',
                csrfToken: req.csrfToken()
            });
        }

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
});

app.get('/voting', isAuthenticated, csrfProtection, (req, res) => {
    res.redirect('/vote');
});

app.get('/vote', isAuthenticated, csrfProtection, (req, res) => {
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
    const userVoteRecord = votes[poll.id.toString()]?.find(userId => userId === req.session.userId);
    const hasVoted = !!userVoteRecord || (currentUser && currentUser.lastVote === poll.id);
    const userVote = hasVoted && currentUser ? poll.options[currentUser.lastVote] : null;

    res.render('index', { 
        session: req.session,
        csrfToken: req.csrfToken(),
        poll: poll,
        hasVoted: hasVoted,
        userVote: userVote,
        isAdmin: false
    });
});

app.post('/vote', isAuthenticated, csrfProtection, (req, res) => {
    try {
        const pollId = parseInt(sanitizeInput(req.body.pollId));
        const optionIndex = parseInt(sanitizeInput(req.body.option));

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
        if (votes[pollId.toString()].includes(req.session.userId)) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Already Voted',
                errorMessage: 'You have already voted in this poll. Vote duplication is not allowed.'
            });
        }

        // Record vote
        votes[pollId.toString()].push(req.session.userId);
        writeJSON(VOTES_FILE, votes);

        // Update user's lastVote
        if (currentUser) {
            currentUser.lastVote = optionIndex;
            writeJSON(USERS_FILE, users);
        }

        // Log vote
        logSecurityEvent(`Vote cast by user: ${req.session.username} for poll: ${pollId}`);

        res.redirect('/results');
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

app.get('/results', isAuthenticated, csrfProtection, (req, res) => {
    const polls = readJSON(POLLS_FILE);
    const votes = readJSON(VOTES_FILE);
    const users = readJSON(USERS_FILE);

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
    
    // Count votes per option
    const results = {};
    users.forEach(user => {
        if (user.lastVote !== null && user.lastVote !== undefined && pollVotes.includes(user.id)) {
            results[user.lastVote] = (results[user.lastVote] || 0) + 1;
        }
    });

    res.render('results', { 
        session: req.session,
        csrfToken: req.csrfToken(),
        poll: poll,
        results: results
    });
});

app.get('/admin-login', csrfProtection, (req, res) => {
    res.render('admin-login', { 
        errorMessage: null,
        csrfToken: req.csrfToken()
    });
});

app.post('/admin-login', csrfProtection, [
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
    req.session.destroy();
    res.redirect('/admin-login');
});

app.post('/admin/logout', csrfProtection, (req, res) => {
    req.session.destroy();
    res.redirect('/admin-login');
});

// User Logout Routes
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.post('/logout', csrfProtection, (req, res) => {
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
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Security features enabled:');
    console.log('✓ Helmet security headers');
    console.log('✓ Session management with HttpOnly cookies');
    console.log('✓ Rate limiting');
    console.log('✓ CSRF protection');
    console.log('✓ Input validation and sanitization');
    console.log('✓ Enhanced password validation');
    console.log('✓ Password hashing with bcrypt');
    console.log('✓ Vote duplication prevention');
    console.log('✓ XSS prevention');
});
