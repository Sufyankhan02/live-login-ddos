const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret-key', resave: false, saveUninitialized: true }));

// Rate limiting to prevent DDoS attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: 'Too many requests, try again later.'
});
app.use(limiter);

// MySQL Database Connection (Use db4free.net or your own MySQL server)
const db = mysql.createConnection({
    host: 'db4free.net',
    user: 'yourusername', // Change this
    password: 'yourpassword', // Change this
    database: 'yourdbname' // Change this
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err.message);
    } else {
        console.log('Connected to MySQL database.');
    }
});

// Create users table if not exists
db.query(`
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
    )
`, err => {
    if (err) console.error('Table creation error:', err.message);
});

// Register Route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query('INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashedPassword], (err) => {
            if (err) return res.status(500).send('User already exists or DB error.');
            res.send('User registered successfully.');
        });
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT password FROM users WHERE username = ?', [username], async (err, results) => {
        if (err || results.length === 0) return res.status(401).send('Invalid credentials.');
        
        const match = await bcrypt.compare(password, results[0].password);
        if (!match) return res.status(401).send('Invalid credentials.');

        req.session.user = username;
        res.send('Login successful.');
    });
});

// Serve Frontend
app.use(express.static('public'));

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
