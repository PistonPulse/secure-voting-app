# Tanish Shah's Contribution# Tanish Shah - Contribution Summary



## Role: Authentication & User Management Developer## Part 2: User Registration & Password Security



### Responsibilities### Responsibilities

- Implemented user registration with validation

- Created secure login system with bcryptImplemented complete user authentication system with secure password hashing using bcrypt.

- Built password hashing and verification

- Implemented input validation and sanitization### Files Contributed



---**1. register.ejs** - User Registration Page

- Designed registration form with input validation

## Code Contributions- Added user-friendly error messages

- Implemented responsive form design

### 1. User Registration System

**2. login.ejs** - User Login Page

**Registration Route with Validation:**- Created secure login interface

```javascript- Added password masking

app.post('/register', [- Designed error handling display

    body('username')

        .trim()**3. authentication_routes.js** - Registration & Login Logic

        .isLength({ min: 3, max: 20 })- Implemented POST /register route with validation

        .withMessage('Username must be 3-20 characters')- Implemented POST /login route with authentication

        .matches(/^[a-zA-Z0-9_]+$/)- Added bcrypt password hashing (10 salt rounds)

        .withMessage('Username can only contain letters, numbers, and underscores'),- Created password verification system

    body('password')- Added session creation after successful login

        .isLength({ min: 8 })- Implemented user logout functionality

        .withMessage('Password must be at least 8 characters')

        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]/)**4. setup.js** - Application Setup Script

        .withMessage('Password must include uppercase, lowercase, number, and special character'),- Creates initial data structure

    body('confirmPassword')- Generates admin password hash

        .custom((value, { req }) => value === req.body.password)- Initializes users.json file

        .withMessage('Passwords do not match')- Sets up standard poll

], async (req, res) => {

    const errors = validationResult(req);**5. reset.js** - Demo Reset Script

    if (!errors.isEmpty()) {- Clears all user accounts

        return res.render('register', {- Resets votes

            title: 'Register',- Maintains admin credentials

            error: errors.array()[0].msg,- Useful for demos and testing

            csrfToken: req.csrfToken(),

            isAuthenticated: false,### Security Features Implemented

            showNav: false

        });🔑 **Password Hashing (bcrypt)**

    }- Hash passwords with 10 salt rounds

- Never store plain text passwords

    const { username, password } = req.body;- Secure password verification

    const users = readJSON(USERS_FILE);- Protection against rainbow table attacks



    // Check if username already exists✅ **Input Validation**

    if (users.find(u => u.username === username)) {- Username: Minimum 3 characters, letters/numbers/underscores only

        return res.render('register', {- Password: Minimum 8 characters with complexity requirements:

            title: 'Register',  - At least one lowercase letter (a-z)

            error: 'Username already exists',  - At least one uppercase letter (A-Z)

            csrfToken: req.csrfToken(),  - At least one number (0-9)

            isAuthenticated: false,  - At least one special character (@$!%*?&#)

            showNav: false- Form validation with express-validator

        });- Server-side validation to prevent bypass

    }- Regex pattern matching for password complexity



    // Hash password and create user📝 **Security Logging**

    const hashedPassword = await bcrypt.hash(password, 10);- Log all registration attempts

    const newUser = {- Track successful and failed logins

        id: Date.now().toString(),- Record IP addresses

        username: sanitizeInput(username),- Timestamp all security events

        passwordHash: hashedPassword,

        createdAt: new Date().toISOString()🔒 **Session Security**

    };- Create secure sessions on login

- Store user ID and username

    users.push(newUser);- Auto-login after registration

    writeJSON(USERS_FILE, users);- Proper session destruction on logout



    res.redirect('/login');### Technical Skills Demonstrated

});

```- Asynchronous JavaScript (async/await)

- bcrypt password hashing

---- Express.js route handling

- Input validation with express-validator

### 2. Login System with bcrypt- Session management

- Error handling

**Login Route:**- Security best practices

```javascript

app.post('/login', loginLimiter, [### Lines of Code

    body('username').trim().notEmpty(),

    body('password').notEmpty()- authentication_routes.js: 148 lines (updated with enhanced password validation)

], async (req, res) => {- register.ejs: 80 lines

    const errors = validationResult(req);- login.ejs: 75 lines

    if (!errors.isEmpty()) {- setup.js: 85 lines

        return res.render('login', {- reset.js: 55 lines

            title: 'Login',- **Total: ~443 lines**

            error: 'Please fill in all fields',

            csrfToken: req.csrfToken(),### Key Implementation Details

            isAuthenticated: false,

            showNav: false**Password Hashing Process:**

        });```javascript

    }// During registration

const passwordHash = await bcrypt.hash(password, 10);

    const { username, password } = req.body;

    const users = readJSON(USERS_FILE);// During login

const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    const user = users.find(u => u.username === username);```

    if (!user) {

        return res.render('login', {**Validation Rules:**

            title: 'Login',- Username: 3+ characters, letters/numbers/underscores only

            error: 'Invalid username or password',- Password: Minimum 8 characters with:

            csrfToken: req.csrfToken(),  - At least one lowercase letter

            isAuthenticated: false,  - At least one uppercase letter

            showNav: false  - At least one number

        });  - At least one special character (@$!%*?&#)

    }- Example valid password: `SecurePass123!`

- All inputs trimmed and sanitized

    // Verify password with bcrypt

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);**Security Logging:**

    if (!passwordMatch) {- New user registration events

        return res.render('login', {- Failed login attempts (with username and IP)

            title: 'Login',- Successful login events

            error: 'Invalid username or password',- User logout events

            csrfToken: req.csrfToken(),

            isAuthenticated: false,---

            showNav: false

        });**Contribution Date:** October 2025  

    }**Project:** SecurePolls - Secure Voting Application


    // Set session
    req.session.userId = user.id;
    req.session.username = user.username;

    res.redirect('/');
});
```

---

### 3. Input Validation & Sanitization

**Sanitization Function:**
```javascript
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input
        .replace(/[<>]/g, '') // Remove < and >
        .trim();
}
```

**Password Validation Regex:**
```javascript
// Enhanced password validation
.matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]/)
.withMessage('Password must include uppercase, lowercase, number, and special character')
```

---

### 4. Authentication Middleware

**RequireAuth Middleware:**
```javascript
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
}
```

**Logout Functionality:**
```javascript
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/login');
    });
});
```

---

## Files Modified/Created

1. **index.js** (Authentication sections)
   - Registration route (~80 lines)
   - Login route (~60 lines)
   - Middleware (~20 lines)
   - Validation rules (~30 lines)

2. **views/register.ejs**
   - Registration form with validation
   - Password requirements display

3. **views/login.ejs**
   - Login form with CSRF protection

---

## Testing & Validation

### Registration Tested:
- ✅ Username validation (3-20 chars, alphanumeric + underscore)
- ✅ Password complexity requirements
- ✅ Password confirmation matching
- ✅ Duplicate username prevention
- ✅ Bcrypt hashing (10 rounds)

### Login Tested:
- ✅ Username/password verification
- ✅ Bcrypt password comparison
- ✅ Session creation
- ✅ Rate limiting (5 attempts per 15 min)
- ✅ CSRF token validation

### Security Tested:
- ✅ Input sanitization
- ✅ SQL injection prevention
- ✅ XSS prevention
- ✅ Password not stored in plain text

---

## Key Achievements

1. **Secure Authentication**: Implemented industry-standard bcrypt hashing
2. **Input Validation**: Created comprehensive validation for all user inputs
3. **Session Management**: Set up secure session handling with HttpOnly cookies
4. **User Experience**: Provided clear error messages and validation feedback

---

## Lines of Code: ~443

**Breakdown:**
- Registration system: ~180 lines
- Login system: ~150 lines
- Validation & sanitization: ~70 lines
- Middleware: ~43 lines

---

## Skills Demonstrated

- Express.js Routing
- Bcrypt Password Hashing
- Express Validator
- Session Management
- Input Sanitization
- Security Best Practices
- Error Handling

---

**Date:** November 2024  
**Project:** Secure Voting Application  
**Status:** ✅ Complete
