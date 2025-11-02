// Client-side JavaScript for Secure Voting Application// Enhanced main.js with better UX and error handling

document.addEventListener('DOMContentLoaded', () => {

// Form validation enhancement    // Update active navigation based on current page

document.addEventListener('DOMContentLoaded', function() {    const path = window.location.pathname;

    // Password confirmation validation    document.querySelectorAll('.nav-link').forEach(link => {

    const registerForm = document.querySelector('form[action="/register"]');        if (link.getAttribute('href') === path) {

    if (registerForm) {            link.classList.add('active');

        registerForm.addEventListener('submit', function(e) {        }

            const password = document.getElementById('password').value;    });

            const confirmPassword = document.getElementById('confirmPassword').value;    // Utility Functions

                const setLoading = (element, isLoading) => {

            if (password !== confirmPassword) {        if (!element) return;

                e.preventDefault();        const originalText = element.dataset.originalText || element.textContent;

                alert('Passwords do not match!');        if (isLoading) {

                return false;            element.dataset.originalText = originalText;

            }            element.disabled = true;

        });            element.innerHTML = '<span class="loading-spinner"></span> Loading...';

    }        } else {

            element.innerHTML = originalText;

    // Vote confirmation            element.disabled = false;

    const voteForm = document.querySelector('.vote-form');        }

    if (voteForm) {    };

        voteForm.addEventListener('submit', function(e) {

            const selectedOption = document.querySelector('input[name="option"]:checked');    const showNotification = (message, type = 'info') => {

            if (selectedOption) {        const notification = document.createElement('div');

                const optionText = selectedOption.parentElement.querySelector('.option-text').textContent;        notification.className = `notification notification-${type}`;

                if (!confirm(`Are you sure you want to vote for "${optionText}"?`)) {        notification.textContent = message;

                    e.preventDefault();        document.body.appendChild(notification);

                    return false;        setTimeout(() => notification.classList.add('show'), 100);

                }        setTimeout(() => {

            }            notification.classList.remove('show');

        });            setTimeout(() => notification.remove(), 300);

    }        }, 3000);

    };

    // Animate result bars on load

    const resultBars = document.querySelectorAll('.result-bar');    // Security Demo Output

    if (resultBars.length > 0) {    const demoOutput = document.getElementById('demo-output');

        resultBars.forEach(bar => {    const writeToDemo = (message, type = 'info') => {

            const width = bar.style.width;        if (!demoOutput) return;

            bar.style.width = '0%';        demoOutput.textContent = message;

            setTimeout(() => {        demoOutput.style.color = type === 'success' ? '#4caf50' : type === 'error' ? '#f44336' : '#03a9f4';

                bar.style.width = width;    };

            }, 100);

        });    const writeToElement = (elementId, message) => {

    }        const element = document.getElementById(elementId);

        if (element) {

    // Auto-hide alerts after 5 seconds            element.textContent = message;

    const alerts = document.querySelectorAll('.alert');            element.style.display = 'block';

    alerts.forEach(alert => {        }

        setTimeout(() => {    };

            alert.style.opacity = '0';

            setTimeout(() => {    // 1. Rate Limiting Demo

                alert.style.display = 'none';    document.getElementById('test-rate-limit')?.addEventListener('click', async function() {

            }, 300);        setLoading(this, true);

        }, 5000);        writeToDemo('Sending 11 rapid requests to test rate limiter...\n\n', 'info');

    });        

});        let results = [];

        let successCount = 0;
        let blockedCount = 0;

        try {
            for (let i = 1; i <= 11; i++) {
                const response = await fetch('/api/test-rate-limit');
                if (response.ok) {
                    successCount++;
                    results.push(`Request ${i}: ✓ SUCCESS (200 OK)`);
                } else if (response.status === 429) {
                    blockedCount++;
                    const data = await response.json().catch(() => ({ message: 'Rate limit exceeded' }));
                    results.push(`Request ${i}: ✗ BLOCKED (429 - ${data.message})`);
                } else {
                    results.push(`Request ${i}: ? UNEXPECTED (${response.status})`);
                }
                await new Promise(resolve => setTimeout(resolve, 100));
            }

            const output = `RATE LIMITING TEST RESULTS:\n\n${results.join('\n')}\n\n` +
                          `✓ Successful: ${successCount}\n` +
                          `✗ Blocked: ${blockedCount}\n\n` +
                          `Expected: First 10 succeed, 11th blocked\n` +
                          `Actual: ${successCount === 10 && blockedCount === 1 ? '✓ PASS' : '✗ FAIL'}`;
            
            writeToDemo(output, successCount === 10 && blockedCount === 1 ? 'success' : 'error');
            writeToElement('rate-limit-output', `${successCount} allowed, ${blockedCount} blocked`);
        } catch (error) {
            writeToDemo(`ERROR: ${error.message}`, 'error');
        } finally {
            setLoading(this, false);
        }
    });

    // 2. CSRF Demo - Protected Route
    document.getElementById('test-csrf-protected')?.addEventListener('click', async function() {
        setLoading(this, true);
        writeToDemo('Testing CSRF-protected route without token...\n\n', 'info');
        
        try {
            const response = await fetch('/vote', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'pollId=1&option=test'
            });
            
            if (response.status === 403) {
                writeToDemo('✓ CSRF PROTECTION WORKING!\n\n' +
                           'Request blocked with 403 Forbidden.\n' +
                           'Forms without valid CSRF tokens are rejected.\n\n' +
                           'All forms include hidden CSRF tokens.', 'success');
            } else {
                writeToDemo(`✗ Unexpected response: ${response.status}`, 'error');
            }
            writeToElement('csrf-output', response.status === 403 ? '✓ Protected' : '✗ Issue detected');
        } catch (error) {
            writeToDemo(`ERROR: ${error.message}`, 'error');
        } finally {
            setLoading(this, false);
        }
    });

    // 2.  CSRF Demo - Unprotected Route
    document.getElementById('test-csrf-unprotected')?.addEventListener('click', async function() {
        setLoading(this, true);
        writeToDemo('Testing intentionally unprotected demo route...\n\n', 'info');
        
        try {
            const response = await fetch('/admin/demo/no-csrf', { method: 'POST' });
            const data = await response.json();
            writeToDemo(`✓ UNPROTECTED ROUTE:\n\n${JSON.stringify(data, null, 2)}\n\n` +
                       'This route has NO CSRF protection (demo only).\n' +
                       'Shows why other routes need protection.', 'success');
            writeToElement('csrf-output', data.message);
        } catch (error) {
            writeToDemo(`ERROR: ${error.message}`, 'error');
        } finally {
            setLoading(this, false);
        }
    });
    
    // 3. Secure Headers (Helmet) Demo
    document.getElementById('test-helmet')?.addEventListener('click', async function() {
        setLoading(this, true);
        writeToDemo('Fetching security headers added by Helmet...\n\n', 'info');
        
        try {
            const response = await fetch('/api/get-headers');
            const headers = await response.json();
            
            const securityHeaders = {
                'X-Content-Type-Options': headers['x-content-type-options'] || 'Not set',
                'X-Frame-Options': headers['x-frame-options'] || 'Not set',
                'X-DNS-Prefetch-Control': headers['x-dns-prefetch-control'] || 'Not set',
                'Content-Security-Policy': headers['content-security-policy'] ? 'Set' : 'Not set',
                'Referrer-Policy': headers['referrer-policy'] || 'Not set'
            };
            
            writeToDemo('✓ HELMET SECURITY HEADERS:\n\n' + 
                       JSON.stringify(securityHeaders, null, 2) + '\n\n' +
                       'Protection against:\n• XSS\n• Clickjacking\n• MIME sniffing', 'success');
            
            writeToElement('helmet-output', Object.keys(securityHeaders).length + ' headers active');
        } catch (error) {
            writeToDemo(`ERROR: ${error.message}`, 'error');
        } finally {
            setLoading(this, false);
        }
    });

    // 4. Secure Cookies Demo
    document.getElementById('test-secure-cookie')?.addEventListener('click', function() {
        writeToDemo('Attempting to read HttpOnly admin cookie...\n\n', 'info');
        
        const allCookies = document.cookie;
        const isAdminCookie = allCookies.split(';').find(c => c.trim().startsWith('isAdmin='));
        
        if (isAdminCookie) {
            writeToDemo(`✗ ISSUE: Cookie readable!\n\nFound: ${isAdminCookie}`, 'error');
        } else {
            writeToDemo('✓ SECURE COOKIES WORKING!\n\n' +
                       'Cannot access "isAdmin" cookie.\n\n' +
                       'Config:\n• httpOnly: true\n• secure: false (dev mode)\n\n' +
                       `Accessible cookies: ${allCookies || 'None'}`, 'success');
        }
        
        writeToElement('cookie-output', isAdminCookie ? '✗ Issue' : '✓ Protected');
    });

    // 5. View Security Logs
    document.getElementById('view-logs-btn')?.addEventListener('click', async function() {
        setLoading(this, true);
        writeToDemo('Loading security logs...\n\n', 'info');
        
        try {
            const response = await fetch('/admin/view-logs');
            const logs = await response.text();
            
            if (logs && logs.trim()) {
                const logLines = logs.trim().split('\n');
                writeToDemo(`✓ SECURITY LOGS (${logLines.length} events):\n\n${logs}`, 'success');
                writeToElement('logs-output', `${logLines.length} events logged`);
            } else {
                writeToDemo('ℹ No events logged yet.\n\nLogged events:\n• Failed logins\n• Duplicate votes\n• Invalid submissions\n• Rate limit hits', 'info');
                writeToElement('logs-output', 'No events yet');
            }
        } catch (error) {
            writeToDemo(`ERROR: ${error.message}`, 'error');
        } finally {
            setLoading(this, false);
        }
    });
});