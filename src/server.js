const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT;

// Create MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  console.log('Connected to database!');
});

app.use(express.json());

// Middleware to verify access token
const verifyToken = (req, res, next) => {
  // const token = req.header('Authorization');
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Invalid or missing Authorization header.' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  // Check if token is revoked
  db.query('SELECT * FROM revoked_token WHERE token = ?', [token], (err, results) => {
    if (err) {
      console.error('Error checking revoked token:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }

    if (results.length > 0) {
      return res.status(401).json({ message: 'Token revoked. Please log in again.' });
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid token.' });
      }

      req.user = decoded;
      next();
    });
  });
};

// Generate access token
const generateAccessToken = (user) => {
  return jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
};

// Generate refresh token
const generateRefreshToken = (user) => {
  return jwt.sign({ username: user.username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};

// Product routes
app.get('/products', (req, res) => {
  db.query('SELECT * FROM product', (err, results) => {
    if (err) {
      console.error('Error getting products:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }
    res.json(results);
  });
});

app.post('/products', verifyToken, (req, res) => {
  const { name, price } = req.body;
  db.query('INSERT INTO product (name, price) VALUES (?, ?)', [name, price], (err) => {
    if (err) {
      console.error('Error inserting product:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }
    res.status(200).json({ 'message': 'Product inserted successfully' });
  });
});

app.put('/products/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { name, price } = req.body;
  db.query('UPDATE product SET name = ?, price = ? WHERE id = ?', [name, price, id], (err) => {
    if (err) {
      console.error('Error updating product:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }
    res.status(200).json({ 'message': 'Product updated successfully' });
  });
});

app.delete('/products/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM product WHERE id = ?', [id], (err) => {
    if (err) {
      console.error('Error deleting product:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }
    res.status(200).json({ 'message': 'Product deleted successfully' });
  });
});

// User routes
// Register route
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Check if username already exists
  db.query('SELECT * FROM user WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Error checking existing username:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }

    if (results.length > 0) {
      return res.status(409).json({ message: 'Username already exists. Please choose a different username.' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    db.query('INSERT INTO user (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
      if (err) {
        console.error('Error registering user:', err);
        return res.status(500).json({ message: 'Internal server error.' });
      }
      res.status(200).json({ 'message': 'User registered successfully' });
    });
  });
});


// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM user WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Error logging in:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }
    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    const user = results[0];
    const passwordMatch = bcrypt.compareSync(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    res.json({ accessToken, refreshToken });
  });
});

// Refresh token route
app.post('/refresh-token', verifyToken, (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token provided.' });
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid refresh token.' });
    }

    const username = decoded.username;
    db.query('SELECT * FROM user WHERE username = ?', [username], (err, results) => {
      if (err) {
        console.error('Error refreshing token:', err);
        return res.status(500).json({ message: 'Internal server error.' });
      }
      if (results.length === 0) {
        return res.status(401).json({ message: 'Invalid refresh token.' });
      }

      const user = results[0];
      const accessToken = generateAccessToken(user);
      res.json({ accessToken });
    });
  });
});

// Blacklist JWT token
// Logout route
app.post('/logout', verifyToken, (req, res) => {
  // const token = req.header('Authorization');
  const authHeader = req.headers.authorization;
  const token = authHeader.split(' ')[1];
  const { username } = req.user;

  // Retrieve the user ID from the database
  db.query('SELECT id FROM user WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Error retrieving user ID:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid user.' });
    }

    const userId = results[0].id;

    // Insert the user ID into the revoked_token table
    db.query('INSERT INTO revoked_token (user_id, token) VALUES (?, ?)', [userId, token], (err) => {
      if (err) {
        console.error('Error inserting token into revoked_token table:', err);
        return res.status(500).json({ message: 'Internal server error.' });
      }

      res.status(200).json({ message: 'Token revoked successfully.' });
    });
  });
});

// Protected route
app.get('/protected', verifyToken, (req, res) => {
    // Access user information from the decoded token
    const { username } = req.user;
  
    // You can perform any actions or return any data related to the authenticated user
    res.json({ message: `Protected route accessed by ${username}.` });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
