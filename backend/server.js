const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8080;
const SECRET = 'secret-key';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database(path.join(__dirname, 'db.sqlite'));

// Initialize DB Tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    role TEXT,
    email TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    product_name TEXT,
    description TEXT,
    category TEXT,
    price REAL,
    color TEXT,
    size TEXT,
    discount REAL,
    available_stock INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS carts (
    cart_id TEXT PRIMARY KEY,
    user_id TEXT,
    products TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS orders (
    order_id TEXT PRIMARY KEY,
    user_id TEXT,
    products TEXT
  )`);
});

// Signup
app.post('/signup', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = uuidv4();
    db.run(`INSERT INTO users (id, email, password, role) VALUES (?, ?, ?, ?)`, 
      [id, email, hashedPassword, role], (err) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ message: 'User created successfully' });
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, role: user.role }, SECRET);
    res.json({ message: 'Login successful', token, role: user.role }); // ✅ Include role
  });
});


// Middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// /all_products
app.get('/all_products', authenticate, (req, res) => {
  const search = req.query.search || '';
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 12;
  const offset = (page - 1) * limit;

  const query = `
    SELECT * FROM products
    WHERE LOWER(product_name) LIKE ?
    LIMIT ? OFFSET ?
  `;
  const countQuery = `
    SELECT COUNT(*) AS total FROM products
    WHERE LOWER(product_name) LIKE ?
  `;
  const searchParam = `%${search.toLowerCase()}%`;

  db.all(query, [searchParam, limit, offset], (err, products) => {
    if (err) return res.status(500).json({ error: err.message });

    db.get(countQuery, [searchParam], (err2, countResult) => {
      if (err2) return res.status(500).json({ error: err2.message });
      const totalPages = Math.ceil(countResult.total / limit);
      res.json({
        products,
        totalPages,
        totalCount: countResult.total
      });
    });
  });
});



// /add_product
app.post('/add_product', authenticate, (req, res) => {
  const id = uuidv4();
  const { product_name, description, category, price, color, size, discount, available_stock } = req.body;
  db.run(`INSERT INTO products (id, product_name, description, category, price, color, size, discount, available_stock)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, product_name, description, category, price, color, size, discount, available_stock],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id, ...req.body });
    });
});

// /edit_product
app.post('/edit_product', authenticate, (req, res) => {
  const { id, product_name, description, category, price, color, size, discount, available_stock } = req.body;
  db.run(`UPDATE products SET product_name=?, description=?, category=?, price=?, color=?, size=?, discount=?, available_stock=? WHERE id=?`,
    [product_name, description, category, price, color, size, discount, available_stock, id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Product updated successfully' });
    });
});

// /add_to_cart
app.post('/add_to_cart', (req, res) => {
  const { user_id, products } = req.body;
  const productsString = JSON.stringify(products);
  db.get(`SELECT * FROM carts WHERE user_id=?`, [user_id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) {
      db.run(`UPDATE carts SET products=? WHERE user_id=?`, [productsString, user_id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Cart updated' });
      });
    } else {
      db.run(`INSERT INTO carts (cart_id, user_id, products) VALUES (?, ?, ?)`, [uuidv4(), user_id, productsString], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Cart created' });
      });
    }
  });
});

// /view_cart
app.post('/view_cart', (req, res) => {
  const { user_id } = req.body;
  db.get(`SELECT products FROM carts WHERE user_id=?`, [user_id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.json({ products: [] });
    res.json({ products: JSON.parse(row.products) });
  });
});

// /order
app.post('/order', (req, res) => {
  const { user_id, products } = req.body;
  const productsString = JSON.stringify(products);
  db.run(`INSERT INTO orders (order_id, user_id, products) VALUES (?, ?, ?)`, [uuidv4(), user_id, productsString], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Order placed' });
  });
});

// /view_orders
app.post('/view_orders', (req, res) => {
  const { user_id } = req.body;

  db.all(`SELECT products FROM orders WHERE user_id = ?`, [user_id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!rows || rows.length === 0) return res.json({ orders: [] });

    // Step 1: Parse product_ids from each order
    const orderProductIdArrays = rows.map(r => JSON.parse(r.products));
    
    // Step 2: Get all unique product IDs
    const allProductIds = [...new Set(orderProductIdArrays.flat())];

    // Step 3: Fetch product details
    db.all(
      `SELECT * FROM products WHERE id IN (${allProductIds.map(() => '?').join(',')})`,
      allProductIds,
      (err, productRows) => {
        if (err) return res.status(500).json({ error: err.message });

        const productMap = {};
        productRows.forEach(p => {
          productMap[p.id] = p;
        });

        // Step 4: Build response orders array
        const orders = orderProductIdArrays.map(product_ids => ({
          product_ids,
          products: product_ids.map(id => productMap[id]).filter(Boolean)
        }));

        res.json({ orders });
      }
    );
  });
});


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});