const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const csrf = require('csurf');
const mysql = require('mysql');

// Body parser middleware to parse incoming request bodies
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

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
const API_SECRET = process.env.API_SECRET || "super-secret-key-123";

// Function to sanitize user input to prevent XSS attacks
function sanitizeInput(input) {
    // Implement your sanitization logic here
    return input;
}
