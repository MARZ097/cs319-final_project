// Session timeout handling
document.addEventListener('DOMContentLoaded', function() {
    // Track user activity
    let lastActivity = new Date();
    const sessionTimeout = 1800000; // 30 minutes in milliseconds (should match server setting)
    let timeoutWarningShown = false;
    
    function resetActivity() {
        lastActivity = new Date();
        if (timeoutWarningShown) {
            hideTimeoutWarning();
        }
    }
    
    // Check for session timeout
    function checkTimeout() {
        const now = new Date();
        const elapsed = now - lastActivity;
        
        // If more than session timeout has elapsed, redirect to login
        if (elapsed > sessionTimeout) {
            window.location.href = '/tailwind/login';
        }
        
        // Show warning 2 minutes before timeout
        if (elapsed > sessionTimeout - (2 * 60 * 1000) && !timeoutWarningShown) {
            showTimeoutWarning();
        }
    }
    
    function showTimeoutWarning() {
        // Create and show the warning
        const warningDiv = document.createElement('div');
        warningDiv.id = 'session-timeout-warning';
        warningDiv.className = 'fixed bottom-4 right-4 bg-yellow-50 border border-yellow-300 rounded-md p-4 shadow-lg z-50';
        warningDiv.innerHTML = `
            <div class="flex">
                <div class="flex-shrink-0">
                    <svg class="h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                </div>
                <div class="ml-3">
                    <h3 class="text-sm font-medium text-yellow-800">Session timeout warning</h3>
                    <div class="mt-2 text-sm text-yellow-700">
                        <p>Your session will expire soon due to inactivity.</p>
                    </div>
                    <div class="mt-4">
                        <div class="-mx-2 -my-1.5 flex">
                            <button id="session-continue-btn" type="button" class="bg-yellow-50 px-2 py-1.5 rounded-md text-sm font-medium text-yellow-800 hover:bg-yellow-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-yellow-50 focus:ring-yellow-600">Continue session</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(warningDiv);
        document.getElementById('session-continue-btn').addEventListener('click', resetActivity);
        
        timeoutWarningShown = true;
    }
    
    function hideTimeoutWarning() {
        const warningDiv = document.getElementById('session-timeout-warning');
        if (warningDiv) {
            warningDiv.remove();
            timeoutWarningShown = false;
        }
    }
    
    // Monitor user activity
    document.addEventListener('click', resetActivity);
    document.addEventListener('keypress', resetActivity);
    document.addEventListener('mousemove', resetActivity);
    document.addEventListener('scroll', resetActivity);
    
    // Check for timeout every minute
    setInterval(checkTimeout, 60000);
});

// Password strength meter
function evaluatePasswordStrength(password) {
    if (!password) {
        return 'None';
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
    
    // Return score label
    const labels = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'];
    return labels[finalScore];
}

function getPasswordStrengthWidth(strength) {
    switch (strength) {
        case 'None': return '0%';
        case 'Very Weak': return '20%';
        case 'Weak': return '40%';
        case 'Medium': return '60%';
        case 'Strong': return '80%';
        case 'Very Strong': return '100%';
        default: return '0%';
    }
}

function getPasswordStrengthColor(strength) {
    switch (strength) {
        case 'None':
        case 'Very Weak':
            return 'bg-red-500';
        case 'Weak':
            return 'bg-orange-500';
        case 'Medium':
            return 'bg-yellow-500';
        case 'Strong':
            return 'bg-blue-500';
        case 'Very Strong':
            return 'bg-green-500';
        default:
            return 'bg-gray-200';
    }
}

// Table sorting
function sortTable(tableId, columnIndex) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const headerCells = table.querySelectorAll('th');
    const headerCell = headerCells[columnIndex];
    
    // Determine if we're sorting ascending or descending
    const currentOrder = headerCell.getAttribute('data-order') || 'asc';
    const newOrder = currentOrder === 'asc' ? 'desc' : 'asc';
    
    // Reset all header cells
    headerCells.forEach(cell => {
        cell.setAttribute('data-order', '');
        cell.querySelector('svg')?.remove();
    });
    
    // Update this header cell with new order and icon
    headerCell.setAttribute('data-order', newOrder);
    
    // Add sort icon
    const sortIcon = document.createElement('span');
    sortIcon.innerHTML = newOrder === 'asc' 
        ? '<svg class="ml-1 w-3 h-3 inline" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M5.293 7.707a1 1 0 0 1 0-1.414l4-4a1 1 0 0 1 1.414 0l4 4a1 1 0 0 1-1.414 1.414L10 4.414l-3.293 3.293a1 1 0 0 1-1.414 0z" clip-rule="evenodd"></path></svg>'
        : '<svg class="ml-1 w-3 h-3 inline" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M14.707 12.293a1 1 0 0 1 0 1.414l-4 4a1 1 0 0 1-1.414 0l-4-4a1 1 0 0 1 1.414-1.414L10 15.586l3.293-3.293a1 1 0 0 1 1.414 0z" clip-rule="evenodd"></path></svg>';
    headerCell.appendChild(sortIcon);
    
    // Sort the rows
    rows.sort((a, b) => {
        const cellA = a.querySelectorAll('td')[columnIndex]?.textContent.trim() || '';
        const cellB = b.querySelectorAll('td')[columnIndex]?.textContent.trim() || '';
        
        // Try to determine if the content is a date
        const dateA = new Date(cellA);
        const dateB = new Date(cellB);
        
        if (!isNaN(dateA) && !isNaN(dateB)) {
            // Sort as dates
            return newOrder === 'asc' ? dateA - dateB : dateB - dateA;
        } else {
            // Sort as strings
            return newOrder === 'asc' 
                ? cellA.localeCompare(cellB) 
                : cellB.localeCompare(cellA);
        }
    });
    
    // Remove existing rows and add the sorted ones
    rows.forEach(row => tbody.appendChild(row));
}