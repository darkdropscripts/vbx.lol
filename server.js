const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('vbx.db');
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  username TEXT UNIQUE,
  password TEXT,
  bio TEXT DEFAULT 'no bio yet',
  avatar_url TEXT,
  banner_url TEXT,
  theme TEXT DEFAULT 'dark',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: 'vbx-super-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 }
}));

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/signup', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'views', 'signup.html'));
});

app.post('/signup', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password || password.length < 6) {
    return res.send('Email, username, and password (min 6 chars) required.');
  }
  const hashed = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
    [email, username, hashed], (err) => {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.send('Email or username already taken.');
        }
        return res.send('Error creating account.');
      }
      res.redirect('/login');
    });
});

app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      return res.send('Invalid credentials.');
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/dashboard');
  });
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

app.get('/api/user', requireAuth, (req, res) => {
  db.get('SELECT id, email, username, bio, avatar_url, banner_url, theme FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

app.post('/api/update', requireAuth, (req, res) => {
  const { bio, avatar_url, banner_url, theme } = req.body;
  db.run('UPDATE users SET bio = ?, avatar_url = ?, banner_url = ?, theme = ? WHERE id = ?',
    [bio || '', avatar_url || null, banner_url || null, theme || 'dark', req.session.userId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
});

app.get('/api/check-username', (req, res) => {
  const username = req.query.username;
  if (!username || username.length < 3) {
    return res.json({ available: false });
  }
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ available: !row });
  });
});

app.get('/@:username', (req, res) => {
  db.get('SELECT username, bio, avatar_url, banner_url, theme, created_at FROM users WHERE username = ?', [req.params.username], (err, user) => {
    if (err || !user) {
      return res.status(404).send('User not found');
    }
    const themeBg = user.theme === 'light' ? '#f5f5f5' : '#0a0a0c';
    const themeText = user.theme === 'light' ? '#000' : '#fff';
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>${user.username} // vbx.lol</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          * { margin:0; padding:0; box-sizing:border-box; }
          body {
            background: ${themeBg};
            color: ${themeText};
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
          }
          .card {
            max-width: 500px;
            width: 100%;
            text-align: center;
            background: ${user.theme === 'light' ? 'white' : 'rgba(0,0,0,0.6)'};
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border: 1px solid ${user.theme === 'light' ? '#eee' : '#222'};
          }
          .avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            object-fit: cover;
            margin-bottom: 20px;
            border: 2px solid ${user.theme === 'light' ? '#ddd' : '#444'};
          }
          h1 { font-size: 1.8rem; margin-bottom: 10px; }
          .bio { margin: 20px 0; opacity: 0.8; }
          .footer { margin-top: 30px; font-size: 0.7rem; opacity: 0.5; }
        </style>
      </head>
      <body>
        <div class="card">
          <img class="avatar" src="${user.avatar_url || 'https://ui-avatars.com/api/?background=000&color=fff&size=100&name=' + user.username.charAt(0)}" onerror="this.src='https://ui-avatars.com/api/?background=000&color=fff&size=100&name=?'">
          <h1>@${user.username}</h1>
          <div class="bio">${user.bio || 'no bio yet'}</div>
          <div class="footer">vbx.lol</div>
        </div>
      </body>
      </html>
    `);
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log('vbx.lol running on port ' + PORT);
});