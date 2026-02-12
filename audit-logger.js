/**
 * Audit Logging System
 * Tracks and logs all security-related events
 */

const fs = require('fs');
const path = require('path');

// Event types for audit logging
const AUDIT_EVENTS = {
    // Authentication events
    LOGIN_SUCCESS: 'LOGIN_SUCCESS',
    LOGIN_FAILURE: 'LOGIN_FAILURE',
    LOGOUT: 'LOGOUT',
    REGISTRATION: 'REGISTRATION',
    
    // Authorization events
    ACCESS_DENIED: 'ACCESS_DENIED',
    PERMISSION_DENIED: 'PERMISSION_DENIED',
    
    // Account management
    EMAIL_VERIFIED: 'EMAIL_VERIFIED',
    EMAIL_VERIFICATION_SENT: 'EMAIL_VERIFICATION_SENT',
    PASSWORD_CHANGE: 'PASSWORD_CHANGE',
    USERNAME_CHANGE: 'USERNAME_CHANGE',
    ROLE_CHANGE: 'ROLE_CHANGE',
    
    // Voting events
    VOTE_CAST: 'VOTE_CAST',
    VOTE_UPDATED: 'VOTE_UPDATED',
    VOTE_DUPLICATE_ATTEMPT: 'VOTE_DUPLICATE_ATTEMPT',
    
    // Poll management
    POLL_CREATED: 'POLL_CREATED',
    POLL_EDITED: 'POLL_EDITED',
    POLL_DELETED: 'POLL_DELETED',
    
    // Security events
    SQL_INJECTION_BLOCKED: 'SQL_INJECTION_BLOCKED',
    XSS_ATTEMPT_BLOCKED: 'XSS_ATTEMPT_BLOCKED',
    CSRF_TOKEN_INVALID: 'CSRF_TOKEN_INVALID',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
    SESSION_TIMEOUT: 'SESSION_TIMEOUT',
    
    // Admin actions
    ADMIN_LOGIN: 'ADMIN_LOGIN',
    USER_DELETED: 'USER_DELETED',
    SYSTEM_SETTINGS_CHANGED: 'SYSTEM_SETTINGS_CHANGED',
    AUDIT_LOG_VIEWED: 'AUDIT_LOG_VIEWED'
};

// Severity levels
const SEVERITY = {
    INFO: 'INFO',
    WARNING: 'WARNING',
    ERROR: 'ERROR',
    CRITICAL: 'CRITICAL'
};

class AuditLogger {
    constructor(logDirectory) {
        this.logDir = logDirectory;
        this.auditLogPath = path.join(this.logDir, 'audit.log');
        this.securityLogPath = path.join(this.logDir, 'security.log');
        
        // Ensure log directory exists
        if (!fs.existsSync(this.logDir)) {
            fs.mkdirSync(this.logDir, { recursive: true });
        }
    }
    
    /**
     * Log an audit event
     * @param {string} eventType - Type of event from AUDIT_EVENTS
     * @param {object} details - Event details
     */
    logEvent(eventType, details = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            eventType,
            severity: this._determineSeverity(eventType),
            userId: details.userId || 'anonymous',
            username: details.username || 'anonymous',
            ip: details.ip || 'unknown',
            userAgent: details.userAgent || 'unknown',
            message: details.message || '',
            action: details.action || '',
            resource: details.resource || '',
            result: details.result || 'success',
            metadata: details.metadata || {}
        };
        
        // Write to audit log
        this._writeToFile(this.auditLogPath, logEntry);
        
        // Write security-critical events to separate security log
        if (this._isSecurityEvent(eventType)) {
            this._writeToFile(this.securityLogPath, logEntry);
        }
    }
    
    /**
     * Log authentication event
     */
    logAuthentication(success, username, ip, userAgent, details = {}) {
        this.logEvent(
            success ? AUDIT_EVENTS.LOGIN_SUCCESS : AUDIT_EVENTS.LOGIN_FAILURE,
            {
                username,
                ip,
                userAgent,
                message: success ? `User ${username} logged in successfully` : `Failed login attempt for ${username}`,
                result: success ? 'success' : 'failure',
                ...details
            }
        );
    }
    
    /**
     * Log authorization event
     */
    logAuthorization(granted, username, resource, permission, ip, details = {}) {
        this.logEvent(
            granted ? AUDIT_EVENTS.ACCESS_DENIED : AUDIT_EVENTS.PERMISSION_DENIED,
            {
                username,
                ip,
                resource,
                message: granted ? `Access granted to ${resource}` : `Access denied to ${resource}`,
                result: granted ? 'success' : 'failure',
                metadata: { permission },
                ...details
            }
        );
    }
    
    /**
     * Log voting event
     */
    logVote(userId, username, pollId, option, ip, details = {}) {
        this.logEvent(
            AUDIT_EVENTS.VOTE_CAST,
            {
                userId,
                username,
                ip,
                resource: `poll_${pollId}`,
                message: `User ${username} cast vote for option ${option}`,
                metadata: { pollId, option },
                ...details
            }
        );
    }
    
    /**
     * Log security threat
     */
    logSecurityThreat(threatType, details = {}) {
        this.logEvent(
            threatType,
            {
                severity: SEVERITY.CRITICAL,
                result: 'blocked',
                ...details
            }
        );
    }
    
    /**
     * Read recent audit logs
     * @param {number} lines - Number of recent lines to read
     * @returns {Array<object>}
     */
    getRecentLogs(lines = 100) {
        try {
            if (!fs.existsSync(this.auditLogPath)) {
                return [];
            }
            
            const content = fs.readFileSync(this.auditLogPath, 'utf8');
            const logLines = content.trim().split('\n').filter(line => line);
            const recentLines = logLines.slice(-lines);
            
            return recentLines.map(line => {
                try {
                    return JSON.parse(line);
                } catch {
                    return null;
                }
            }).filter(entry => entry !== null);
        } catch (error) {
            console.error('Error reading audit logs:', error);
            return [];
        }
    }
    
    /**
     * Search audit logs
     * @param {object} criteria - Search criteria
     * @returns {Array<object>}
     */
    searchLogs(criteria = {}) {
        const allLogs = this.getRecentLogs(1000);
        
        return allLogs.filter(log => {
            if (criteria.eventType && log.eventType !== criteria.eventType) return false;
            if (criteria.userId && log.userId !== criteria.userId) return false;
            if (criteria.username && log.username !== criteria.username) return false;
            if (criteria.severity && log.severity !== criteria.severity) return false;
            if (criteria.startDate && new Date(log.timestamp) < new Date(criteria.startDate)) return false;
            if (criteria.endDate && new Date(log.timestamp) > new Date(criteria.endDate)) return false;
            return true;
        });
    }
    
    /**
     * Determine severity based on event type
     */
    _determineSeverity(eventType) {
        const criticalEvents = [
            AUDIT_EVENTS.SQL_INJECTION_BLOCKED,
            AUDIT_EVENTS.XSS_ATTEMPT_BLOCKED,
            AUDIT_EVENTS.USER_DELETED,
            AUDIT_EVENTS.SYSTEM_SETTINGS_CHANGED
        ];
        
        const warningEvents = [
            AUDIT_EVENTS.LOGIN_FAILURE,
            AUDIT_EVENTS.ACCESS_DENIED,
            AUDIT_EVENTS.PERMISSION_DENIED,
            AUDIT_EVENTS.CSRF_TOKEN_INVALID,
            AUDIT_EVENTS.RATE_LIMIT_EXCEEDED,
            AUDIT_EVENTS.VOTE_DUPLICATE_ATTEMPT
        ];
        
        if (criticalEvents.includes(eventType)) return SEVERITY.CRITICAL;
        if (warningEvents.includes(eventType)) return SEVERITY.WARNING;
        return SEVERITY.INFO;
    }
    
    /**
     * Check if event is security-related
     */
    _isSecurityEvent(eventType) {
        const securityEvents = [
            AUDIT_EVENTS.SQL_INJECTION_BLOCKED,
            AUDIT_EVENTS.XSS_ATTEMPT_BLOCKED,
            AUDIT_EVENTS.CSRF_TOKEN_INVALID,
            AUDIT_EVENTS.RATE_LIMIT_EXCEEDED,
            AUDIT_EVENTS.ACCESS_DENIED,
            AUDIT_EVENTS.PERMISSION_DENIED,
            AUDIT_EVENTS.LOGIN_FAILURE
        ];
        return securityEvents.includes(eventType);
    }
    
    /**
     * Write log entry to file
     */
    _writeToFile(filePath, logEntry) {
        try {
            const logLine = JSON.stringify(logEntry) + '\n';
            fs.appendFileSync(filePath, logLine, 'utf8');
        } catch (error) {
            console.error('Error writing to audit log:', error);
        }
    }
}

module.exports = {
    AuditLogger,
    AUDIT_EVENTS,
    SEVERITY
};
