/**
 * Security Middleware
 * Provides authentication, authorization, and email verification middleware
 */

const { ROLES, PERMISSIONS, hasPermission } = require('./rbac-config');
const { AUDIT_EVENTS } = require('./audit-logger');

/**
 * Middleware to check if user is authenticated
 */
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        if (req.auditLogger) {
            req.auditLogger.logEvent(AUDIT_EVENTS.ACCESS_DENIED, {
                ip: req.ip,
                userAgent: req.get('user-agent'),
                resource: req.path,
                message: 'Unauthenticated user attempted to access protected resource'
            });
        }
        res.redirect('/login');
    }
}

/**
 * Middleware to check if user has a specific permission
 * @param {string} permission - Required permission
 */
function requirePermission(permission) {
    return (req, res, next) => {
        const userRole = req.session?.role || ROLES.GUEST;
        
        if (hasPermission(userRole, permission)) {
            next();
        } else {
            if (req.auditLogger) {
                req.auditLogger.logEvent(AUDIT_EVENTS.PERMISSION_DENIED, {
                    userId: req.session?.userId || 'anonymous',
                    username: req.session?.username || 'anonymous',
                    ip: req.ip,
                    userAgent: req.get('user-agent'),
                    resource: req.path,
                    message: `Permission denied: ${permission}`,
                    metadata: { requiredPermission: permission, userRole }
                });
            }
            
            res.status(403).render('error', {
                session: req.session,
                csrfToken: req.csrfToken ? req.csrfToken() : '',
                errorTitle: 'Access Denied',
                errorMessage: 'You do not have permission to access this resource.'
            });
        }
    };
}

/**
 * Middleware to check if user has any of the specified permissions
 * @param {Array<string>} permissions - Array of permissions
 */
function requireAnyPermission(...permissions) {
    return (req, res, next) => {
        const userRole = req.session?.role || ROLES.GUEST;
        
        const hasAnyPerm = permissions.some(permission => hasPermission(userRole, permission));
        
        if (hasAnyPerm) {
            next();
        } else {
            if (req.auditLogger) {
                req.auditLogger.logEvent(AUDIT_EVENTS.PERMISSION_DENIED, {
                    userId: req.session?.userId || 'anonymous',
                    username: req.session?.username || 'anonymous',
                    ip: req.ip,
                    userAgent: req.get('user-agent'),
                    resource: req.path,
                    message: `Permission denied: requires any of ${permissions.join(', ')}`,
                    metadata: { requiredPermissions: permissions, userRole }
                });
            }
            
            res.status(403).render('error', {
                session: req.session,
                csrfToken: req.csrfToken ? req.csrfToken() : '',
                errorTitle: 'Access Denied',
                errorMessage: 'You do not have permission to access this resource.'
            });
        }
    };
}

/**
 * Middleware to check if user has a specific role
 * @param {string} role - Required role
 */
function requireRole(role) {
    return (req, res, next) => {
        const userRole = req.session?.role || ROLES.GUEST;
        
        if (userRole === role) {
            next();
        } else {
            if (req.auditLogger) {
                req.auditLogger.logEvent(AUDIT_EVENTS.ACCESS_DENIED, {
                    userId: req.session?.userId || 'anonymous',
                    username: req.session?.username || 'anonymous',
                    ip: req.ip,
                    userAgent: req.get('user-agent'),
                    resource: req.path,
                    message: `Role-based access denied: requires ${role}`,
                    metadata: { requiredRole: role, userRole }
                });
            }
            
            res.status(403).render('error', {
                session: req.session,
                csrfToken: req.csrfToken ? req.csrfToken() : '',
                errorTitle: 'Access Denied',
                errorMessage: 'You do not have the required role to access this resource.'
            });
        }
    };
}

/**
 * Middleware to check if user is admin (backward compatibility)
 */
function isAdmin(req, res, next) {
    return requireRole(ROLES.ADMINISTRATOR)(req, res, next);
}

/**
 * Middleware to check if email is verified
 */
function requireEmailVerification(req, res, next) {
    if (req.session && req.session.emailVerified) {
        next();
    } else {
        if (req.auditLogger) {
            req.auditLogger.logEvent(AUDIT_EVENTS.ACCESS_DENIED, {
                userId: req.session?.userId || 'anonymous',
                username: req.session?.username || 'anonymous',
                ip: req.ip,
                userAgent: req.get('user-agent'),
                resource: req.path,
                message: 'Unverified email attempted to access protected resource'
            });
        }
        
        res.status(403).render('error', {
            session: req.session,
            csrfToken: req.csrfToken ? req.csrfToken() : '',
            errorTitle: 'Email Verification Required',
            errorMessage: 'Please verify your email address to access this feature. Check your email for the verification link.'
        });
    }
}

/**
 * Middleware to attach user role to session (use after authentication)
 */
function attachUserRole(readJSON, USERS_FILE) {
    return (req, res, next) => {
        if (req.session && req.session.userId) {
            const users = readJSON(USERS_FILE);
            const user = users.find(u => u.id === req.session.userId);
            
            if (user) {
                req.session.role = user.role || ROLES.CUSTOMER;
                req.session.emailVerified = user.emailVerified || false;
            } else {
                req.session.role = ROLES.GUEST;
                req.session.emailVerified = false;
            }
        } else {
            req.session.role = ROLES.GUEST;
            req.session.emailVerified = false;
        }
        next();
    };
}

/**
 * Security middleware chain for sensitive operations
 * Combines authentication, email verification, and permission checks
 * @param {string} permission - Required permission
 */
function secureRoute(permission) {
    return [
        isAuthenticated,
        requireEmailVerification,
        requirePermission(permission)
    ];
}

module.exports = {
    isAuthenticated,
    requirePermission,
    requireAnyPermission,
    requireRole,
    isAdmin,
    requireEmailVerification,
    attachUserRole,
    secureRoute
};
