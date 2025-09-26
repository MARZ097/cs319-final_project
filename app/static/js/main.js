// Main JavaScript file for the Access Control System

// Session timeout handling
document.addEventListener('DOMContentLoaded', function() {
    // Track user activity
    let lastActivity = new Date();
    const sessionTimeout = 1800000; // 30 minutes in milliseconds
    
    function resetActivity() {
        lastActivity = new Date();
    }
    
    // Check for session timeout
    function checkTimeout() {
        const now = new Date();
        const elapsed = now - lastActivity;
        
        // If more than session timeout has elapsed, redirect to login
        if (elapsed > sessionTimeout) {
            alert('Your session has expired due to inactivity. Please log in again.');
            window.location.href = '/login';
        }
    }
    
    // Monitor user activity
    document.addEventListener('click', resetActivity);
    document.addEventListener('keydown', resetActivity);
    document.addEventListener('mousemove', resetActivity);
    document.addEventListener('scroll', resetActivity);
    
    // Check for timeout every minute
    setInterval(checkTimeout, 60000);
});

// Password strength meter
document.addEventListener('DOMContentLoaded', function() {
    const passwordField = document.querySelector('input[type="password"][name="password"], input[type="password"][name="new_password"]');
    
    if (passwordField) {
        // Create strength meter
        const meterContainer = document.createElement('div');
        meterContainer.classList.add('password-strength-meter', 'mt-2');
        
        const meter = document.createElement('div');
        meter.classList.add('progress');
        meter.style.height = '5px';
        
        const meterBar = document.createElement('div');
        meterBar.classList.add('progress-bar');
        meterBar.style.width = '0%';
        
        const meterText = document.createElement('div');
        meterText.classList.add('small', 'text-muted', 'mt-1');
        meterText.textContent = 'Password strength: None';
        
        meter.appendChild(meterBar);
        meterContainer.appendChild(meter);
        meterContainer.appendChild(meterText);
        
        passwordField.parentNode.insertBefore(meterContainer, passwordField.nextSibling);
        
        // Check password strength
        passwordField.addEventListener('input', function() {
            const password = passwordField.value;
            const strength = calculatePasswordStrength(password);
            
            // Update meter
            meterBar.style.width = `${strength.score * 25}%`;
            meterText.textContent = `Password strength: ${strength.label}`;
            
            // Update meter color
            meterBar.className = 'progress-bar';
            if (strength.score === 0) {
                meterBar.classList.add('bg-danger');
            } else if (strength.score === 1) {
                meterBar.classList.add('bg-warning');
            } else if (strength.score === 2) {
                meterBar.classList.add('bg-info');
            } else if (strength.score === 3) {
                meterBar.classList.add('bg-primary');
            } else {
                meterBar.classList.add('bg-success');
            }
        });
    }
    
    function calculatePasswordStrength(password) {
        if (!password) {
            return { score: 0, label: 'None' };
        }
        
        let score = 0;
        
        // Length check
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        
        // Character variety check
        if (/[A-Z]/.test(password)) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        if (/[0-9]/.test(password)) score += 1;
        if (/[^A-Za-z0-9]/.test(password)) score += 1;
        
        // Calculate final score (max 4)
        const finalScore = Math.min(4, Math.floor(score / 2));
        
        // Return score and label
        const labels = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'];
        return { score: finalScore, label: labels[finalScore] };
    }
});
