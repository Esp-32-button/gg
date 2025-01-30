require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const port = 3000;

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Required for NeonDB
});

pool.connect()
    .then(() => console.log("✅ Connected to Neon PostgreSQL Database"))
    .catch(err => console.error("❌ Database Connection Error:", err));

app.use(cors());
app.use(express.json()); // Parse JSON requests

// User Registration
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [username, email, hashedPassword]);
    res.json({ message: "User registered successfully!" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid email or password" });

    const user = result.rows[0];
    if (!(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

// Middleware for authentication
function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Forbidden" });
    req.user = user;
    next();
  });
}

// Servo Control (Protected Route)
let servoState = "OFF"; // Default state

app.post("/servo", authenticateToken, (req, res) => {
  const { state } = req.body;
  if (state !== "ON" && state !== "OFF") return res.status(400).json({ error: "Invalid state" });

  servoState = state;
  res.json({ message: `Servo set to ${state}` });
});

// ESP32 Fetches State
app.get("/servo", (req, res) => {
  res.json({ state: servoState });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
