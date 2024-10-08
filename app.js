
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Serve static files from the frontend directory
app.use(express.static("frontend"));

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connected to MySQL");
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

// Middleware to check if the user is authenticated
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Middleware to check if the user is a librarian
const checkLibrarian = (req, res, next) => {
  if (req.user.role !== "LIBRARIAN") {
    return res
      .status(403)
      .json({ message: "Access denied. Librarian rights required." });
  }
  next();
};

// Signup Route
app.post("/api/auth/signup", async (req, res) => {
  const { username, password, email, full_name, role } = req.body;
  
  if (!username || !email || !password || !full_name || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }
  // Hash the password
  const hashedPassword = bcrypt.hashSync(password, 10);

  const query =
    "INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)";
  db.execute(
    query,
    [username, email, hashedPassword, full_name, role],
    (err, result) => {
      if (err)
        return res
          .status(500)
          .json({ message: "Signup failed", error: err.message });
      res.json({ message: "User registered successfully" });
    }
  );
});

// Login Route
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;

  const query = "SELECT * FROM users WHERE username = ?";
  db.execute(query, [username], (err, results) => {
    if (err)
      return res
        .status(500)
        .json({ message: "Login failed", error: err.message });

    const user = results[0];
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: "1y",
    });
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  });
});

// Get all books
app.get("/api/books", authenticateToken, (req, res) => {
  const query = "SELECT * FROM books";
  db.execute(query, (err, results) => {
    if (err)
      return res
        .status(500)
        .json({ message: "Failed to fetch books", error: err.message });
    res.json(results);
  });
});

// Add Book
app.post("/api/books", authenticateToken, checkLibrarian, (req, res) => {
  const { title, author } = req.body;
  const query =
    'INSERT INTO books (title, author, status) VALUES (?, ?, "available")';
  db.execute(query, [title, author], (err, result) => {
    if (err)
      return res
        .status(500)
        .json({ message: "Failed to add book", error: err.message });
    res.json({ message: "Book added successfully", id: result.insertId });
  });
});

// Update Book
app.put("/api/books/:id", authenticateToken, checkLibrarian, (req, res) => {
  const { id } = req.params;
  const { title, author } = req.body;
  const query = "UPDATE books SET title = ?, author = ? WHERE id = ?";
  db.execute(query, [title, author, id], (err, result) => {
    if (err)
      return res
        .status(500)
        .json({ message: "Failed to update book", error: err.message });
    if (result.affectedRows === 0)
      return res.status(404).json({ message: "Book not found" });
    res.json({ message: "Book updated successfully" });
  });
});

// Delete Book
app.delete("/api/books/:id", authenticateToken, checkLibrarian, (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM books WHERE id = ?";
  db.execute(query, [id], (err, result) => {
    if (err)
      return res
        .status(500)
        .json({ message: "Failed to delete book", error: err.message });
    if (result.affectedRows === 0)
      return res.status(404).json({ message: "Book not found" });
    res.json({ message: "Book deleted successfully" });
  });
});

// Delete Member
app.delete("/api/users/:id", authenticateToken, checkLibrarian, (req, res) => {
  const { id } = req.params;
  const query = 'DELETE FROM users WHERE id = ? AND role != "LIBRARIAN"';
  db.execute(query, [id], (err, result) => {
    if (err)
      return res
        .status(500)
        .json({ message: "Failed to delete member", error: err.message });
    if (result.affectedRows === 0)
      return res
        .status(404)
        .json({ message: "Member not found or cannot be deleted" });
    res.json({ message: "Member deleted successfully" });
  });
});

// Borrow Book
app.post("/api/borrow", async (req, res) => {
  const { userId, bookId } = req.body;
  const borrowedAt = new Date();

  // Check if the book is available
  const checkBookQuery = "SELECT * FROM books WHERE id = ?";
  db.execute(checkBookQuery, [bookId], (err, results) => {
    if (err){
      return res
      .status(500)
      .json({ message: "Error checking book status", error: err.message });
    }
    if (results.length === 0 || results[0].status !== "available") {
      return res
      .status(400)
      .json({ message: "Book not found" });
    }
    if (results[0].status !== "available") {
      return res.status(400).json({ message: "Book is not available for borrowing", currentStatus: results[0].status });
    }

    // Insert into borrow_history
    const insertQuery =
      "INSERT INTO borrow_history (user_id, book_id, borrowed_at) VALUES (?, ?, ?)";
    db.execute(insertQuery, [userId, bookId, borrowedAt], (err, result) => {
      if (err)
        return res
          .status(500)
          .json({ message: "Failed to borrow book", error: err.message });

      // Update book status to 'borrowed'
      const updateBookQuery =
        'UPDATE books SET status = "borrowed" WHERE id = ?';
      db.execute(updateBookQuery, [bookId], (err) => {
        if (err)
          return res
            .status(500)
            .json({
              message: "Failed to update book status",
              error: err.message,
            });
        res.json({ message: "Book borrowed successfully" });
      });
    });
  });
});

// Return Book
app.post("/api/return", authenticateToken, (req, res) => {
  const { userId, bookId } = req.body;
  const returnedAt = new Date();

  // Update borrow_history with returned_at
  const updateBorrowQuery =
    "UPDATE borrow_history SET returned_at = ? WHERE user_id = ? AND book_id = ? AND returned_at IS NULL";
  db.execute(updateBorrowQuery, [returnedAt, userId, bookId], (err, result) => {
    if (err)
      return res
        .status(500)
        .json({ message: "Failed to return book", error: err.message });
    if (result.affectedRows === 0)
      return res.status(400).json({ message: "No active borrow record found" });

    // Update book status back to 'available'
    const updateBookQuery =
      'UPDATE books SET status = "available" WHERE id = ?';
    db.execute(updateBookQuery, [bookId], (err) => {
      if (err)
        return res
          .status(500)
          .json({
            message: "Failed to update book status",
            error: err.message,
          });
      res.json({ message: "Book returned successfully" });
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
