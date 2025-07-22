const express = require('express');
const app = express();

// XSS 취약점
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<h1>Search results for: ${query}</h1>`);
});

// SQL Injection 취약점
const mysql = require('mysql');
app.get('/user', (req, res) => {
    const userId = req.params.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (err, results) => {
        res.json(results);
    });
});

// Hard-coded secrets
const API_SECRET = "super-secret-key-123";