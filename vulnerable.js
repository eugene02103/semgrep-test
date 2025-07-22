const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const csrf = require('csurf');
const mysql = require('mysql');
const cookieParser = require('cookie-parser');

// Body parser middleware to parse incoming request bodies
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());  // CSRF 보호에 필요

// CSRF protection middleware
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// XSS 취약점 수정: Sanitize user input before sending in response
app.get('/search', (req, res) => {
    const query = req.query.q;
    const sanitizedQuery = sanitizeInput(query);
    res.send(`<h1>Search results for: ${sanitizedQuery}</h1>`);
});

// SQL Injection 취약점 수정: Use parameterized queries to prevent SQL injection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'your_user',
    password: process.env.DB_PASSWORD,
    database: 'your_database'
});

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const query = 'SELECT * FROM users WHERE id = ?';
    connection.query(query, [userId], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json(results);
        }
    });
});

// Hard-coded secrets should be stored securely, not in code
if (!process.env.API_SECRET) {
    throw new Error("API_SECRET must be set in environment variables.");
}
const API_SECRET = process.env.API_SECRET;

// ✅ Function to sanitize user input to prevent XSS attacks
function sanitizeInput(input) {
    return escapeHtml(input);
}

// ✅ Function to escape HTML entities
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Server start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
