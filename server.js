const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = 5000;
const SECRET_KEY = "your_secret_key";

app.use(express.json());
app.use(cors());

// Database connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "77673345",
    database: "object_detection"
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed: ", err);
    } else {
        console.log("Connected to MySQL database!");
    }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Access denied" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
};

// Signup Route
app.post("/signup", async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
    db.query(query, [username, email, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ error: "Database error" });
        res.json({ message: "User registered successfully" });
    });
});

// Login Route
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    const query = "SELECT * FROM users WHERE email = ?";

    db.query(query, [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ error: "Invalid credentials" });

        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "7d" });
        res.json({ message: "Login successful", token });
    });
});

// Protected Route (Example: Fetch Detection History)
app.get("/history", authenticateToken, (req, res) => {
    const query = "SELECT * FROM detections WHERE user_id = ?";
    db.query(query, [req.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        res.json(results);
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
