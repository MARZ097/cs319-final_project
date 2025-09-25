# Access Control System - User Manual

## Table of Contents
1. [Getting Started](#getting-started)
2. [User Authentication](#user-authentication)
3. [Profile Management](#profile-management)
4. [Security Settings](#security-settings)
5. [Admin Functions](#admin-functions)
6. [Troubleshooting](#troubleshooting)

## Getting Started

### System Requirements
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Internet connection
- JavaScript enabled

### Accessing the System
1. Open your web browser
2. Navigate to the system URL provided by your administrator
3. You will be redirected to the login page

## User Authentication

### Logging In
1. Enter your username or email address
2. Enter your password
3. If Two-Factor Authentication (2FA) is enabled:
   - Enter the 6-digit code from your authenticator app
   - Or use one of your backup codes
4. Check "Remember Me" if you want to stay logged in longer
5. Click "Sign In"

### Account Security
- **Account Lockout**: After 5 failed login attempts, your account will be temporarily locked for 5 minutes
- **Session Timeout**: Your session will expire after 30 minutes of inactivity
- **Secure Logout**: Always log out when finished, especially on shared computers

## Profile Management

### Viewing Your Profile
1. Click on your name in the top-right corner
2. Select "Profile" from the dropdown menu
3. View your account information and security status

### Editing Your Profile
1. Go to your profile page
2. Click "Edit Profile"
3. Update the following information:
   - First Name
   - Last Name
   - Email Address
   - Profile Picture (optional)
4. Click "Update Profile" to save changes

### Profile Picture Guidelines
- **Supported formats**: PNG, JPG, JPEG, GIF
- **Maximum size**: 16MB
- **Recommended size**: 300x300 pixels
- Images are automatically resized and optimized

## Security Settings

### Changing Your Password
1. Go to Profile → Security Settings
2. Click "Change Password"
3. Enter your current password
4. Enter your new password (must meet complexity requirements)
5. Confirm your new password
6. Click "Change Password"

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- Not found in known data breaches

### Two-Factor Authentication (2FA)

#### Setting Up 2FA
1. Go to Profile → Security Settings
2. Click "Enable Two-Factor Authentication"
3. Install an authenticator app on your phone:
   - Google Authenticator
   - Authy
   - Microsoft Authenticator
4. Scan the QR code with your authenticator app
5. Enter the 6-digit code to verify setup
6. Save your backup codes in a secure location

#### Using 2FA
- When logging in, enter the 6-digit code from your authenticator app
- Codes change every 30 seconds
- If you can't access your authenticator app, use a backup code

#### Backup Codes
- Each backup code can only be used once
- Store them securely (print or save to a password manager)
- Generate new codes if you run out

#### Disabling 2FA
1. Go to Profile → Security Settings
2. Click "Disable 2FA"
3. Enter your password to confirm
4. Your 2FA will be disabled and backup codes invalidated

### Viewing Your Activity
1. Go to Profile → Activity
2. Review your recent account activity
3. Report any suspicious activity to an administrator

## Admin Functions

*Note: These functions are only available to users with Administrator role.*

### User Management

#### Creating Users
1. Go to Administration → Manage Users
2. Click "Create New User"
3. Fill in the required information:
   - Username (unique)
   - Email address (unique)
   - First and last name
   - Initial password
   - User role (Admin or User)
4. Click "Create User"

#### Managing Existing Users
1. Go to Administration → Manage Users
2. Find the user in the list
3. Click the eye icon to view user details
4. Available actions:
   - **View Details**: See user information and activity
   - **Enable/Disable**: Activate or deactivate user accounts
   - **Unlock**: Remove account locks from failed login attempts
   - **Change Role**: Promote users to admin or demote to regular user
   - **Delete**: Permanently remove user accounts

#### User Status Indicators
- **Active**: User can log in and use the system
- **Inactive**: User account is disabled
- **Locked**: Account temporarily locked due to failed login attempts
- **2FA Enabled**: User has two-factor authentication enabled

### Audit Logs
1. Go to Administration → Audit Logs
2. View system-wide activity logs
3. Filter by:
   - Action type
   - User
   - Date range
4. Use for security monitoring and compliance

### System Statistics
1. Go to Administration → System Statistics
2. View system metrics:
   - Total users
   - Active users
   - Locked accounts
   - Users with 2FA enabled
   - Recent login activity
   - Failed login attempts

## Troubleshooting

### Common Issues

#### Can't Log In
**Problem**: Login fails with correct credentials
**Solutions**:
1. Check if Caps Lock is on
2. Verify username/email spelling
3. Wait 5 minutes if account is locked
4. Contact administrator if problem persists

#### Forgot Password
**Problem**: Can't remember password
**Solutions**:
1. Contact your system administrator for a password reset
2. Administrator can reset your password using the admin panel

#### Lost Authenticator App
**Problem**: Can't access 2FA codes
**Solutions**:
1. Use a backup code if available
2. Contact administrator to disable 2FA on your account
3. Set up 2FA again with a new device

#### Session Expired
**Problem**: Automatically logged out
**Solutions**:
1. This is normal after 30 minutes of inactivity
2. Simply log in again
3. Use "Remember Me" for longer sessions

#### Profile Picture Won't Upload
**Problem**: Image upload fails
**Solutions**:
1. Check file format (PNG, JPG, JPEG, GIF only)
2. Ensure file is under 16MB
3. Try a different image
4. Contact administrator if problem persists

### Getting Help

#### For Regular Users
1. Check this user manual first
2. Try the troubleshooting steps
3. Contact your system administrator
4. Provide specific error messages if any

#### For Administrators
1. Check the system logs for errors
2. Review audit logs for security issues
3. Verify system configuration
4. Contact technical support if needed

### Security Best Practices

#### For All Users
- Use a strong, unique password
- Enable two-factor authentication
- Log out when finished
- Don't share your credentials
- Report suspicious activity
- Keep your contact information updated

#### For Administrators
- Regularly review user accounts
- Monitor audit logs
- Keep the system updated
- Backup data regularly
- Follow the principle of least privilege
- Document any changes made

### Contact Information

For technical support or security concerns:
- Contact your system administrator
- In case of security incidents, report immediately

---

*This manual covers version 1.0 of the Access Control System. For the latest updates and features, please refer to the system documentation.*
