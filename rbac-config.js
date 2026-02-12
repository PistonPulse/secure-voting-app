/**
 * Role-Based Access Control (RBAC) Configuration
 * Defines roles, permissions, and access control matrix
 */

// Define user roles
const ROLES = {
    GUEST: 'guest',           // Unauthenticated users
    CUSTOMER: 'customer',     // Basic authenticated users
    EDITOR: 'editor',         // Can create/edit polls
    ADMINISTRATOR: 'admin'    // Full system access
};

// Define permissions
const PERMISSIONS = {
    // Public access
    VIEW_HOME: 'view_home',
    VIEW_SECURITY_PAGE: 'view_security_page',
    
    // Authentication
    REGISTER: 'register',
    LOGIN: 'login',
    
    // Voting
    VIEW_POLLS: 'view_polls',
    CAST_VOTE: 'cast_vote',
    VIEW_RESULTS: 'view_results',
    
    // Poll management
    CREATE_POLL: 'create_poll',
    EDIT_POLL: 'edit_poll',
    DELETE_POLL: 'delete_poll',
    
    // User management
    VIEW_USERS: 'view_users',
    EDIT_USER: 'edit_user',
    DELETE_USER: 'delete_user',
    
    // Admin functions
    ACCESS_ADMIN_PANEL: 'access_admin_panel',
    VIEW_AUDIT_LOGS: 'view_audit_logs',
    CHANGE_USER_ROLES: 'change_user_roles',
    MANAGE_SYSTEM_SETTINGS: 'manage_system_settings'
};

// Permission Matrix: Maps roles to their allowed permissions
const PERMISSION_MATRIX = {
    [ROLES.GUEST]: [
        PERMISSIONS.VIEW_HOME,
        PERMISSIONS.VIEW_SECURITY_PAGE,
        PERMISSIONS.REGISTER,
        PERMISSIONS.LOGIN
    ],
    
    [ROLES.CUSTOMER]: [
        PERMISSIONS.VIEW_HOME,
        PERMISSIONS.VIEW_SECURITY_PAGE,
        PERMISSIONS.VIEW_POLLS,
        PERMISSIONS.CAST_VOTE,
        PERMISSIONS.VIEW_RESULTS
    ],
    
    [ROLES.EDITOR]: [
        PERMISSIONS.VIEW_HOME,
        PERMISSIONS.VIEW_SECURITY_PAGE,
        PERMISSIONS.VIEW_POLLS,
        PERMISSIONS.CAST_VOTE,
        PERMISSIONS.VIEW_RESULTS,
        PERMISSIONS.CREATE_POLL,
        PERMISSIONS.EDIT_POLL,
        PERMISSIONS.DELETE_POLL
    ],
    
    [ROLES.ADMINISTRATOR]: [
        // Admins have all permissions
        ...Object.values(PERMISSIONS)
    ]
};

/**
 * Check if a role has a specific permission
 * @param {string} role - User role
 * @param {string} permission - Permission to check
 * @returns {boolean}
 */
function hasPermission(role, permission) {
    if (!role || !permission) return false;
    const rolePermissions = PERMISSION_MATRIX[role] || [];
    return rolePermissions.includes(permission);
}

/**
 * Check if a role has any of the specified permissions
 * @param {string} role - User role
 * @param {Array<string>} permissions - Array of permissions
 * @returns {boolean}
 */
function hasAnyPermission(role, permissions) {
    return permissions.some(permission => hasPermission(role, permission));
}

/**
 * Check if a role has all specified permissions
 * @param {string} role - User role
 * @param {Array<string>} permissions - Array of permissions
 * @returns {boolean}
 */
function hasAllPermissions(role, permissions) {
    return permissions.every(permission => hasPermission(role, permission));
}

/**
 * Get all permissions for a role
 * @param {string} role - User role
 * @returns {Array<string>}
 */
function getRolePermissions(role) {
    return PERMISSION_MATRIX[role] || [];
}

/**
 * Get the default role for new users
 * @returns {string}
 */
function getDefaultRole() {
    return ROLES.CUSTOMER; // Lowest privilege for authenticated users
}

/**
 * Validate if a role exists
 * @param {string} role - Role to validate
 * @returns {boolean}
 */
function isValidRole(role) {
    return Object.values(ROLES).includes(role);
}

module.exports = {
    ROLES,
    PERMISSIONS,
    PERMISSION_MATRIX,
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    getRolePermissions,
    getDefaultRole,
    isValidRole
};
