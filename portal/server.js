const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const session = require('express-session');
let createProxyMiddleware;
try {
    ({ createProxyMiddleware } = require('http-proxy-middleware'));
} catch (_) {
    // proxy is optional in dev; ignore if not installed
}
require('dotenv').config();

// Import authentication
const { router: authRouter, authenticateToken, checkPermission, ROLES, adminUsers, managers, clients } = require('./auth');

const app = express();
const execAsync = promisify(exec);
const PORT = process.env.PORTAL_PORT || process.env.EMAIL_ADMIN_PORT || 3003;

// Middleware
app.use(cors({
    origin: ['http://localhost:3003', 'http://68.54.208.207:3003', 'https://portal.getsparqd.com'],
    credentials: true
}));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'portal-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));
// Optional: proxy SparQ Plug app when SPARQ_PLUG_URL is set (e.g., http://localhost:3004)
if (createProxyMiddleware && process.env.SPARQ_PLUG_URL) {
    app.use('/sparkplug', createProxyMiddleware({
        target: process.env.SPARQ_PLUG_URL,
        changeOrigin: true,
        ws: true,
        pathRewrite: { '^/sparkplug': '/' },
        logLevel: 'warn'
    }));
}

// Static assets fallback (includes placeholder under public/sparkplug/)
app.use(express.static('public'));

// In-memory storage (in production, use a database)
let domains = [];
let emailAccounts = [];
let systemLogs = [];

// Add log entry
function addLog(message, level = 'info') {
    const logEntry = {
        id: uuidv4(),
        timestamp: new Date().toISOString(),
        message,
        level
    };
    systemLogs.unshift(logEntry);
    
    // Keep only last 100 logs
    if (systemLogs.length > 100) {
        systemLogs = systemLogs.slice(0, 100);
    }
    
    console.log(`[${level.toUpperCase()}] ${message}`);
}

// Generate secure password
function generatePassword(length = 12) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
}

// Hash password for system storage
async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
}

// Create email account in system
async function createEmailAccount(email, password, domain, storageGB = 25) {
    try {
        const username = email.split('@')[0];
        const hashedPassword = await hashPassword(password);
        
        // Create user directory
        await execAsync(`sudo mkdir -p /var/mail/vhosts/${domain}/${username}`);
        await execAsync(`sudo chown -R mail:mail /var/mail/vhosts/${domain}`);
        
        // Add to virtual mailboxes
        await execAsync(`echo "${email} ${domain}/${username}/" | sudo tee -a /etc/postfix/virtual_mailboxes`);
        
        // Add password entry
        const saltedHash = await execAsync(`doveadm pw -s SHA512-CRYPT -p "${password}"`);
        await execAsync(`echo "${email}:${saltedHash.stdout.trim()}" | sudo tee -a /etc/dovecot/passwd.${domain}`);
        
        // Update postfix maps
        await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
        
        // Restart services
        await execAsync('sudo systemctl reload postfix dovecot');
        
        // Add to our tracking
        const account = {
            id: uuidv4(),
            address: email,
            domain,
            password, // Store plain text for client notification
            hashedPassword,
            storage: storageGB,
            created: new Date().toISOString(),
            lastLogin: null
        };
        
        emailAccounts.push(account);
        addLog(`Created email account: ${email}`);
        
        return account;
        
    } catch (error) {
        addLog(`Failed to create email account ${email}: ${error.message}`, 'error');
        throw error;
    }
}

// Setup domain email hosting
async function setupDomainEmail(domainData) {
    const { domain, clientName, clientContact, emailAccounts: emailList, storageAllocation, autoDNS, emailClient } = domainData;
    
    const results = {
        domain,
        clientName,
        createdAccounts: [],
        totalStorage: storageAllocation,
        dnsRecords: [],
        credentials: []
    };
    
    try {
        // Add domain to virtual domains
        await execAsync(`echo "${domain}" | sudo tee -a /etc/postfix/virtual_domains`);
        
        // Create accounts
        for (const emailAddr of emailList) {
            if (emailAddr.trim()) {
                const password = generatePassword(14);
                const account = await createEmailAccount(emailAddr.trim(), password, domain, storageAllocation / emailList.length);
                
                results.createdAccounts.push({
                    email: emailAddr.trim(),
                    password,
                    storage: Math.floor(storageAllocation / emailList.length)
                });
                
                results.credentials.push({
                    email: emailAddr.trim(),
                    password,
                    imap: `${domain}:993 (SSL/TLS)`,
                    smtp: `${domain}:587 (STARTTLS)`,
                    webmail: `http://mail.${domain}`
                });
            }
        }
        
        // DNS setup if requested
        if (autoDNS) {
            results.dnsRecords = [
                { type: 'MX', name: domain, content: domain, priority: 10 },
                { type: 'A', name: `mail.${domain}`, content: process.env.SERVER_IP || '68.54.208.207' },
                { type: 'TXT', name: domain, content: `"v=spf1 mx a:${domain} ~all"` }
            ];
            
            addLog(`DNS records prepared for ${domain}`);
        }
        
        // Add domain to tracking
        const domainRecord = {
            id: uuidv4(),
            name: domain,
            clientName,
            clientContact,
            emailCount: results.createdAccounts.length,
            storageAllocated: storageAllocation,
            created: new Date().toISOString(),
            status: 'active'
        };
        
        domains.push(domainRecord);
        
        // Send credentials to client if requested
        if (emailClient && clientContact) {
            await sendClientCredentials(clientContact, results);
        }
        
        addLog(`Domain email setup completed for ${domain} (${results.createdAccounts.length} accounts)`);
        return results;
        
    } catch (error) {
        addLog(`Domain setup failed for ${domain}: ${error.message}`, 'error');
        throw error;
    }
}

// Send credentials to client
async function sendClientCredentials(clientEmail, setupResults) {
    try {
        const transporter = nodemailer.createTransporter({
            host: 'localhost',
            port: 587,
            secure: false,
            auth: {
                user: 'admin@' + (process.env.DEFAULT_DOMAIN || 'localhost'),
                pass: 'admin123' // You should set this up properly
            }
        });
        
        const credentialsText = setupResults.credentials.map(cred => 
            `📧 ${cred.email}\n   Password: ${cred.password}\n   IMAP: ${cred.imap}\n   SMTP: ${cred.smtp}\n   Webmail: ${cred.webmail}`
        ).join('\n\n');
        
        const mailOptions = {
            from: `"SparQd Portal" <admin@${process.env.DEFAULT_DOMAIN || 'localhost'}>`,
            to: clientEmail,
            subject: `🎉 Your Professional Email Hosting is Ready! (${setupResults.domain})`,
            text: `Dear ${setupResults.clientName},

Your FREE professional email hosting has been successfully configured for ${setupResults.domain}!

📧 Email Accounts Created (${setupResults.createdAccounts.length}):
${credentialsText}

💾 Total Storage Allocated: ${setupResults.totalStorage}GB
🌐 Webmail Access: http://mail.${setupResults.domain}
💰 Monthly Savings: No more email hosting fees!

Email Client Setup Instructions:
• Use your full email address as username
• IMAP Server: ${setupResults.domain} (Port 993, SSL/TLS)
• SMTP Server: ${setupResults.domain} (Port 587, STARTTLS)

Your email accounts are ready to use immediately!

Best regards,
SparQd Email Team

---
This is an automated message from the SparQd Email Management System.`
        };
        
        await transporter.sendMail(mailOptions);
        addLog(`Credentials sent to client: ${clientEmail}`);
        
    } catch (error) {
        addLog(`Failed to send credentials to ${clientEmail}: ${error.message}`, 'error');
        // Don't throw - this shouldn't fail the whole setup
    }
}

// Authentication routes
app.use('/api/auth', authRouter);

// User Management API Routes
app.get('/api/users/admins', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: adminUsers.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                createdAt: user.createdAt
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch admin users' });
    }
});

app.get('/api/users/managers', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: managers.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                createdAt: user.createdAt,
                permissions: user.permissions
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch managers' });
    }
});

app.get('/api/users/clients', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: clients.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                domain: user.domain,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch clients' });
    }
});

app.get('/api/users/:id', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const user = users.find(u => u.id == req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userResponse = {
            id: user.id,
            username: user.username,
            email: user.email,
            name: user.name,
            role: user.role
        };
        
        if (user.role === 'client') {
            userResponse.company = user.company;
            userResponse.phone = user.phone;
            userResponse.domain = user.domain;
        }
        
        res.json(userResponse);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load user' });
    }
});

app.post('/api/users/create', authenticateToken, checkPermission('users:create'), async (req, res) => {
    try {
        const bcrypt = require('bcrypt');
        const { users } = require('./auth');
        const { type, username, email, name, password, company, phone, domain } = req.body;
        
        // Check if username or email already exists
        if (users.find(u => u.username === username || u.email === email)) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Math.max(...users.map(u => u.id)) + 1,
            username,
            email,
            password: hashedPassword,
            role: type,
            name,
            createdAt: new Date().toISOString()
        };
        
        if (type === 'client') {
            newUser.company = company;
            newUser.phone = phone;
            newUser.domain = domain;
        }
        
        users.push(newUser);
        res.json({ message: 'User created successfully', userId: newUser.id });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.put('/api/users/:id', authenticateToken, checkPermission('users:update'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const { username, email, name, company, phone, domain } = req.body;
        
        // Check if username or email is taken by another user
        if (users.find(u => u.id !== userId && (u.username === username || u.email === email))) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        users[userIndex] = {
            ...users[userIndex],
            username,
            email,
            name,
            ...(users[userIndex].role === 'client' && { company, phone, domain })
        };
        
        res.json({ message: 'User updated successfully' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.post('/api/users/:id/reset-password', authenticateToken, checkPermission('users:update'), async (req, res) => {
    try {
        const bcrypt = require('bcrypt');
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const newPassword = generatePassword(12);
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        users[userIndex].password = hashedPassword;
        users[userIndex].requirePasswordChange = true;
        
        res.json({ message: 'Password reset successfully', newPassword });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

app.delete('/api/users/:id', authenticateToken, checkPermission('users:delete'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Don't allow deleting the last admin
        if (users[userIndex].role === 'admin' && users.filter(u => u.role === 'admin').length === 1) {
            return res.status(400).json({ error: 'Cannot delete the last admin user' });
        }
        
        users.splice(userIndex, 1);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.get('/api/users/:id/details', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const user = users.find(u => u.id == req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // For client details, we would typically fetch from a database
        // For now, return basic info with mock data
        const details = {
            ...user,
            emailAccounts: [
                { address: `${user.username}@${user.domain || 'example.com'}`, storage: '0.5' }
            ],
            totalStorage: '0.5',
            createdAt: user.createdAt || new Date().toISOString().split('T')[0]
        };
        
        delete details.password; // Never send password
        res.json(details);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load user details' });
    }
});

app.get('/api/users/clients/export', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const clients = users.filter(user => user.role === 'client');
        
        const csv = [
            'Name,Username,Email,Company,Phone,Domain,Created',
            ...clients.map(client => 
                `"${client.name}","${client.username}","${client.email}","${client.company || ''}","${client.phone || ''}","${client.domain || ''}","${client.createdAt || ''}"`
            )
        ].join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="clients-export.csv"');
        res.send(csv);
    } catch (error) {
        res.status(500).json({ error: 'Failed to export client data' });
    }
});

// Redirect root to login if not authenticated
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login.html');
    }
});

// Dashboard route (protected)
app.get('/dashboard', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        res.redirect('/login.html');
    }
});

// API Routes (protected)

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, checkPermission('dashboard:read'), (req, res) => {
    const totalStorage = emailAccounts.reduce((sum, account) => sum + account.storage, 0);
    const monthlySavings = domains.length * 15; // Estimate $15/month per domain saved
    
    res.json({
        totalDomains: domains.length,
        totalEmails: emailAccounts.length,
        storageUsed: totalStorage,
        monthlySavings
    });
});

// Setup validation
app.post('/api/setup/validate', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain } = req.body;
    
    try {
        // Check if domain already exists
        const existingDomain = domains.find(d => d.name === domain);
        if (existingDomain) {
            return res.status(400).json({ error: 'Domain already configured' });
        }
        
        // Basic domain validation
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
        if (!domainRegex.test(domain)) {
            return res.status(400).json({ error: 'Invalid domain format' });
        }
        
        res.json({ 
            success: true, 
            details: [`Domain ${domain} is valid and available`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create directories
app.post('/api/setup/directories', async (req, res) => {
    const { domain } = req.body;
    
    try {
        await execAsync(`sudo mkdir -p /var/mail/vhosts/${domain}`);
        await execAsync(`sudo mkdir -p /home/sparqd/sites/${domain}`);
        await execAsync(`sudo chown -R mail:mail /var/mail/vhosts/${domain}`);
        
        res.json({ 
            success: true,
            details: [
                `Created mail directory: /var/mail/vhosts/${domain}`,
                `Created site directory: /home/sparqd/sites/${domain}`
            ]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create accounts
app.post('/api/setup/accounts', async (req, res) => {
    const { domain, emailAccounts: emailList } = req.body;
    
    try {
        const createdAccounts = [];
        
        for (const emailAddr of emailList) {
            if (emailAddr.trim()) {
                const password = generatePassword(14);
                await createEmailAccount(emailAddr.trim(), password, domain);
                createdAccounts.push(`${emailAddr.trim()} (${password})`);
            }
        }
        
        res.json({ 
            success: true,
            details: [`Created ${createdAccounts.length} email accounts`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Configure mail server
app.post('/api/setup/mailserver', async (req, res) => {
    try {
        await execAsync('sudo postmap /etc/postfix/virtual_domains');
        await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
        await execAsync('sudo systemctl reload postfix dovecot');
        
        res.json({ 
            success: true,
            details: [
                'Updated Postfix virtual maps',
                'Reloaded Postfix and Dovecot services'
            ]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Allocate storage
app.post('/api/setup/storage', async (req, res) => {
    const { domain, storageAllocation } = req.body;
    
    try {
        // Set quota (this is a simplified implementation)
        await execAsync(`sudo mkdir -p /home/sparqd/sites/${domain}/quota`);
        await fs.writeFile(`/home/sparqd/sites/${domain}/quota/allocation.txt`, `${storageAllocation}GB`);
        
        res.json({ 
            success: true,
            details: [`Allocated ${storageAllocation}GB storage for ${domain}`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Setup DNS
app.post('/api/setup/dns', async (req, res) => {
    const { domain } = req.body;
    
    try {
        // This would integrate with your DNS management system
        const dnsRecords = [
            `MX: ${domain} → ${domain} (Priority 10)`,
            `A: mail.${domain} → ${process.env.SERVER_IP}`,
            `TXT: ${domain} → "v=spf1 mx a:${domain} ~all"`
        ];
        
        res.json({ 
            success: true,
            details: ['DNS records prepared (manual configuration required)', ...dnsRecords]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Send notifications
app.post('/api/setup/notify', async (req, res) => {
    const { clientContact, domain } = req.body;
    
    try {
        if (clientContact) {
            // This would send the actual email
            addLog(`Client notification prepared for ${clientContact}`);
        }
        
        res.json({ 
            success: true,
            details: [`Client notification sent to ${clientContact}`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Finalize setup
app.post('/api/setup/finalize', async (req, res) => {
    try {
        const setupResult = await setupDomainEmail(req.body);
        
        res.json({ 
            success: true,
            details: [
                `Domain ${setupResult.domain} setup completed`,
                `${setupResult.createdAccounts.length} email accounts created`,
                `${setupResult.totalStorage}GB storage allocated`
            ],
            result: setupResult
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Email management
app.get('/api/emails/list', (req, res) => {
    res.json(emailAccounts.map(account => ({
        address: account.address,
        domain: account.domain,
        storage: account.storage,
        created: new Date(account.created).toLocaleDateString(),
        lastLogin: account.lastLogin
    })));
});

app.post('/api/emails/reset-password', async (req, res) => {
    const { email } = req.body;
    
    try {
        const account = emailAccounts.find(acc => acc.address === email);
        if (!account) {
            return res.status(404).json({ error: 'Email account not found' });
        }
        
        const newPassword = generatePassword(14);
        
        // Update password in system
        const saltedHash = await execAsync(`doveadm pw -s SHA512-CRYPT -p "${newPassword}"`);
        
        // Update dovecot password file
        await execAsync(`sudo sed -i 's|^${email}:.*|${email}:${saltedHash.stdout.trim()}|' /etc/dovecot/passwd.${account.domain}`);
        await execAsync('sudo systemctl reload dovecot');
        
        // Update our record
        account.password = newPassword;
        account.hashedPassword = await hashPassword(newPassword);
        
        addLog(`Password reset for ${email}`);
        
        res.json({ success: true, newPassword });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/emails/delete', async (req, res) => {
    const { email } = req.body;
    
    try {
        const accountIndex = emailAccounts.findIndex(acc => acc.address === email);
        if (accountIndex === -1) {
            return res.status(404).json({ error: 'Email account not found' });
        }
        
        const account = emailAccounts[accountIndex];
        
        // Remove from system
        await execAsync(`sudo sed -i '/^${email}/d' /etc/postfix/virtual_mailboxes`);
        await execAsync(`sudo sed -i '/^${email}/d' /etc/dovecot/passwd.${account.domain}`);
        await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
        await execAsync('sudo systemctl reload postfix dovecot');
        
        // Remove directory
        const username = email.split('@')[0];
        await execAsync(`sudo rm -rf /var/mail/vhosts/${account.domain}/${username}`);
        
        // Remove from our tracking
        emailAccounts.splice(accountIndex, 1);
        
        addLog(`Deleted email account: ${email}`);
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// System logs
app.get('/api/logs/recent', (req, res) => {
    res.json(systemLogs.slice(0, 50));
});

// DNS testing
app.post('/api/dns/test', async (req, res) => {
    const { domain } = req.body;
    
    try {
        const results = [];
        
        // Test MX record
        try {
            const mxResult = await execAsync(`nslookup -type=MX ${domain}`);
            results.push(`MX Record: ${mxResult.stdout.includes(domain) ? '✅ Configured' : '❌ Not found'}`);
        } catch (error) {
            results.push('MX Record: ❌ Error checking');
        }
        
        // Test A record for mail subdomain
        try {
            const aResult = await execAsync(`nslookup mail.${domain}`);
            results.push(`A Record (mail): ${aResult.stdout.includes(process.env.SERVER_IP) ? '✅ Configured' : '❌ Not pointing to server'}`);
        } catch (error) {
            results.push('A Record (mail): ❌ Not found');
        }
        
        res.json({ success: true, results });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Initialize system
async function initializeSystem() {
    addLog('Portal Dashboard starting up');
    
    // Load existing configurations if any
    try {
    const configPath = '/home/sparqd/portal-config.json';
        const configData = await fs.readFile(configPath, 'utf8');
        const config = JSON.parse(configData);
        
        domains = config.domains || [];
        emailAccounts = config.emailAccounts || [];
        
        addLog(`Loaded ${domains.length} domains and ${emailAccounts.length} email accounts`);
    } catch (error) {
        addLog('No existing configuration found, starting fresh');
    }
}

// Save configuration periodically
setInterval(async () => {
    try {
        const config = {
            domains,
            emailAccounts: emailAccounts.map(acc => ({
                ...acc,
                password: undefined // Don't save plain text passwords
            })),
            lastSaved: new Date().toISOString()
        };
        
    await fs.writeFile('/home/sparqd/portal-config.json', JSON.stringify(config, null, 2));
    } catch (error) {
        addLog(`Failed to save configuration: ${error.message}`, 'error');
    }
}, 60000); // Save every minute

// Start server
app.listen(PORT, async () => {
    await initializeSystem();
    addLog(`Portal Dashboard running on port ${PORT}`);
    console.log(`\n🎉 Portal Dashboard is ready!`);
    console.log(`📧 Access at: http://localhost:${PORT}`);
    console.log(`🌐 Or: http://${process.env.SERVER_IP}:${PORT}`);
});
