const express = require('express');
const app = express();
const path = require('path');

// Udostępnij katalog uploads jako statyczny
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const sanitizeHtml = require('sanitize-html');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const db = new sqlite3.Database('data/users.db'); // <-- tylko raz!

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firstName TEXT,
  lastName TEXT,
  userClass TEXT,
  phone TEXT,
  messenger TEXT,
  instagram TEXT,
  mail TEXT UNIQUE,
  password TEXT
)`);
db.run(`CREATE TABLE IF NOT EXISTS books (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT,
  title TEXT,
  publisher TEXT,
  year TEXT,
  grade TEXT,
  price TEXT,
  stan TEXT,
  photo TEXT,
  date TEXT,
  userMail TEXT,
  userFirstName TEXT,
  userLastName TEXT,
  userClass TEXT,
  userPhone TEXT,
  userMessenger TEXT,
  userInstagram TEXT
)`);
db.run(`CREATE TABLE IF NOT EXISTS spotet (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  text TEXT,
  photo TEXT,
  date TEXT,
  authorMail TEXT
)`);
db.run(`CREATE TABLE IF NOT EXISTS spotet_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  spotetId INTEGER,
  text TEXT,
  date TEXT,
  authorMail TEXT,
  isAnonymous INTEGER DEFAULT 0
)`);
db.run(`CREATE TABLE IF NOT EXISTS ogloszenia (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  text TEXT,
  photo TEXT,
  date TEXT,
  authorMail TEXT,
  authorRole TEXT,
  pending INTEGER DEFAULT 0
)`);
db.run(`CREATE TABLE IF NOT EXISTS ogloszenia_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ogloszenieId INTEGER,
  text TEXT,
  date TEXT,
  authorMail TEXT,
  isAnonymous INTEGER DEFAULT 0
)`);

// Dodawanie konta admin i testowego (tylko raz)
async function addUsers() {
  const hash = await bcrypt.hash('Qazwsx678', 10);

  // Konto admin
  db.run(
    `INSERT OR IGNORE INTO users (firstName, lastName, userClass, phone, messenger, instagram, mail, password, role)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ['Admin', 'Systemu', 'admin', '', '', '', 'admin@lo2.przemysl.edu.pl', hash, 'admin']
  );




}

 addUsers(); 
 // Odkomentuj, aby dodać konta przy pierwszym uruchomieniu

app.use(cors({
  origin: '*', // lub konkretny adres frontendu
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-user-mail', 'x-user-role', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Upewnij się, że folder 'uploads' istnieje
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Serwowanie statycznych plików (np. zdjęć)
app.use('/uploads', express.static(uploadsDir));

// Pamięć na oferty (tymczasowa, bez bazy danych)
const offers = [];

// Konfiguracja Multera do zapisu zdjęć
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads'); // katalog musi istnieć!
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// Endpoint POST - dodawanie oferty
app.post('/api/books', authAndBlockCheck, upload.single('photo'), (req, res) => {
  // Dane książki z formularza
  const { subject, title, publisher, year, grade, price, stan } = req.body;

  // Dane użytkownika z konta (z middleware)
  const user = req.user;
  if (!user || !user.mail || !user.mail.endsWith('@lo2.przemysl.edu.pl')) {
    return res.status(400).json({ message: 'Musisz być zalogowany, aby dodać książkę.' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'Brak zdjęcia (photo)' });
  }

  const photoUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  const date = new Date().toISOString();

  db.run(
    `INSERT INTO books (subject, title, publisher, year, grade, price, stan, photo, date, userMail, userFirstName, userLastName, userClass, userPhone, userMessenger, userInstagram)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [subject, title, publisher, year, grade, price, stan, photoUrl, date, user.mail, user.firstName, user.lastName, user.userClass, user.phone, user.messenger, user.instagram],
    function (err) {
      if (err) return res.status(500).json({ message: 'Błąd serwera przy dodawaniu książki.' });
      res.status(201).json({ id: this.lastID });
    }
  );
});

// Pobierz wszystkie oferty
app.get('/api/books', (req, res) => {
  db.all('SELECT * FROM books ORDER BY date DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu książek.' });
    res.json(rows);
  });
});

// Pobierz jedną ofertę po ID
app.get('/api/books/:id', (req, res) => {
  db.get('SELECT * FROM books WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
    if (!row) return res.status(404).json({ message: 'Nie znaleziono oferty' });
    res.json(row);
  });
});

// Edytuj ofertę po ID
app.put('/api/books/:id', (req, res) => {
  const { subject, title, publisher, year, grade, price, stan, photo } = req.body;
  db.run(
    `UPDATE books SET subject = ?, title = ?, publisher = ?, year = ?, grade = ?, price = ?, stan = ?, photo = ? WHERE id = ?`,
    [subject, title, publisher, year, grade, price, stan, photo, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ message: 'Błąd aktualizacji oferty' });
      res.json({ message: 'Oferta zaktualizowana' });
    }
  );
});

// Usuń ofertę (admin/przewodniczący dowolną, user tylko swoją)
app.delete('/api/books/:id', (req, res) => {
  const { id } = req.params;
  // Pobierz mail i rolę z nagłówków lub body
  const userMail = req.headers['x-user-mail'] || req.body?.mail;
  const userRole = (req.headers['x-user-role'] || req.body?.role || '').toLowerCase();

  db.get('SELECT * FROM books WHERE id = ?', [id], (err, book) => {
    if (err || !book) return res.status(404).json({ message: 'Nie znaleziono oferty' });

    // Pozwól adminowi/przewodniczącemu lub właścicielowi
    if (
      userMail === book.userMail ||
      userMail === 'admin@lo2.przemysl.edu.pl' ||
      userRole === 'admin' ||
      userRole === 'przewodniczący' ||
      userRole === 'przewodniczacy'
    ) {
      db.run('DELETE FROM books WHERE id = ?', [id], function (err2) {
        if (err2) return res.status(500).json({ message: 'Błąd serwera przy usuwaniu oferty' });
        res.json({ message: 'Oferta usunięta' });
      });
    } else {
      res.status(403).json({ message: 'Brak uprawnień do usunięcia tej oferty' });
    }
  });
});

// Połączenie z bazą SQLite


// Tworzenie tabeli users (już masz)
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firstName TEXT,
  lastName TEXT,
  userClass TEXT,
  phone TEXT,
  messenger TEXT,
  instagram TEXT,
  mail TEXT UNIQUE,
  password TEXT
)`);

// Tworzenie tabeli books (NOWE)
db.run(`CREATE TABLE IF NOT EXISTS books (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT,
  title TEXT,
  publisher TEXT,
  year TEXT,
  grade TEXT,
  price TEXT,
  stan TEXT,
  photo TEXT,
  date TEXT,
  userMail TEXT,
  userFirstName TEXT,
  userLastName TEXT,
  userClass TEXT,
  userPhone TEXT,
  userMessenger TEXT,
  userInstagram TEXT
)`);

// REJESTRACJA
app.post('/api/register', async (req, res) => {
  const { firstName, lastName, userClass, phone, messenger, instagram, mail, password } = req.body;
  db.get('SELECT * FROM users WHERE mail = ?', [mail], async (err, row) => {
    if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
    if (row) return res.status(400).json({ message: 'Użytkownik z tym mailem już istnieje' });

    const hash = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (firstName, lastName, userClass, phone, messenger, instagram, mail, password)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [firstName, lastName, userClass, phone, messenger, instagram, mail, hash],
      function (err) {
        if (err) return res.status(500).json({ message: 'Błąd zapisu do bazy' });
        res.json({
          message: 'Rejestracja zakończona',
          user: { firstName, lastName, userClass, phone, messenger, instagram, mail }
        });
      }
    );
  });
});

// LOGOWANIE
app.post('/api/login', (req, res) => {
  const { mail, password } = req.body;
  db.get('SELECT * FROM users WHERE mail = ?', [mail], async (err, user) => {
    if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
    if (!user) return res.status(400).json({ message: 'Nieprawidłowy e-mail lub hasło' });

    // SPRAWDŹ BLOKADĘ PRZED SPRAWDZENIEM HASŁA!
    if (user.blockedUntil && new Date(user.blockedUntil) > new Date()) {
      const ms = new Date(user.blockedUntil) - new Date();
      const min = Math.ceil(ms / 60000);
      return res.status(403).json({
        message: `Konto zablokowane do ${user.blockedUntil} (${min} min). Powód: ${user.blockReason || 'brak'}`
      });
    }

    // Dopiero teraz sprawdzaj hasło!
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Nieprawidłowy e-mail lub hasło' });

    // Generowanie tokenu JWT
    const token = jwt.sign({ mail: user.mail, role: user.role }, SECRET, { expiresIn: '7d' });

    // Usuń pole password z usera przed wysłaniem!
    const { password: _, ...userData } = user;

    res.json({ user: userData, token });
  });
});

// Usuń konto użytkownika (i powiązane książki)
app.delete('/api/users/:mail', (req, res) => {
  const mail = req.params.mail;
  db.run('DELETE FROM users WHERE mail = ?', [mail], function (err) {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy usuwaniu konta' });
    res.json({ message: 'Konto zostało usunięte' });
  });
});

app.put('/api/users/:mail', (req, res) => {
  const { firstName, lastName, userClass, phone, messenger, instagram, blockedUntil, blockReason, role } = req.body;
  db.run(
    `UPDATE users SET firstName = ?, lastName = ?, userClass = ?, phone = ?, messenger = ?, instagram = ?, blockedUntil = ?, blockReason = ?, role = ? WHERE mail = ?`,
    [firstName, lastName, userClass, phone, messenger, instagram, blockedUntil, blockReason, role, req.params.mail],
    function(err) {
      if (err) return res.status(500).json({ message: 'Błąd aktualizacji danych' });
      res.json({ message: 'Dane użytkownika zaktualizowane' });
    }
  );
});

// Middleware do sprawdzania roli admina (opcjonalnie, jeśli masz autoryzację po sesji/tokenie)
function isAdmin(req, res, next) {
  // Jeśli masz sesję lub JWT, sprawdź czy user jest adminem
  // Przykład: if (req.user && req.user.role === 'admin') next();
  // Jeśli nie masz autoryzacji, sprawdzaj po mailu (nie jest to bezpieczne, ale działa lokalnie):
  if (req.body.mail === 'admin@lo2.przemysl.edu.pl') return next();
  res.status(403).json({ message: 'Brak uprawnień' });
}

// Endpoint do usuwania wszystkich ofert (tylko admin)
app.delete('/api/books', isAdmin, (req, res) => {
  db.run('DELETE FROM books', function(err) {
    if (err) return res.status(500).json({ message: 'Błąd usuwania ofert' });
    res.json({ message: 'Wszystkie oferty zostały usunięte' });
  });
});

// Endpoint: zwracanie szczegółów żądania HTTP jako JSON
app.get('/request-info', (req, res) => {
  res.json({
    method: req.method,
    url: req.originalUrl,
    headers: req.headers,
    ip: req.ip,
    protocol: req.protocol,
    hostname: req.hostname,
    query: req.query,
    body: req.body
  });
});

// Uruchom serwer na wszystkich interfejsach
const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Serwer działa na http://0.0.0.0:${PORT} (lub przez domenę jeśli dostępna)`);
});

// Pobierz wszystkich użytkowników
app.get('/api/users', (req, res) => {
  db.all('SELECT * FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
    res.json(rows);
  });
});

app.get('/api/users/:mail', (req, res) => {
  db.get('SELECT * FROM users WHERE mail = ?', [req.params.mail], (err, row) => {
    if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
    if (!row) return res.status(404).json({ message: 'Nie znaleziono użytkownika' });
    res.json(row);
  });
});

// Dodawanie anonimowej wiadomości (z opcjonalnym zdjęciem)
const spotetUpload = multer({ storage }); // użyj tej samej konfiguracji co do książek

// DODANO: authAndBlockCheck jako middleware!
app.post('/api/spotet', authAndBlockCheck, spotetUpload.single('photo'), (req, res) => {
  const { text, authorMail } = req.body;
  if (!authorMail) return res.status(401).json({ message: 'Musisz być zalogowany.' });
  if (!text || text.trim().length === 0) return res.status(400).json({ message: 'Wiadomość nie może być pusta.' });

  let photoUrl = '';
  if (req.file) {
    photoUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  }
  const date = new Date().toISOString();

  db.run(
    `INSERT INTO spotet (text, photo, date, authorMail) VALUES (?, ?, ?, ?)`,
    [text, photoUrl, date, authorMail],
    function(err) {
      if (err) return res.status(500).json({ message: 'Błąd serwera przy dodawaniu wiadomości.' });
      res.status(201).json({ id: this.lastID });
    }
  );
});

// Pobierz wszystkie anonimowe wiadomości
app.get('/api/spotet', (req, res) => {
  db.all(`
    SELECT spotet.id, spotet.text, spotet.photo, spotet.date, spotet.authorMail, users.role as authorRole
    FROM spotet
    LEFT JOIN users ON spotet.authorMail = users.mail
    ORDER BY date DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu wiadomości.' });
    res.json(rows);
  });
});

app.delete('/api/spotet/:id', (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM spotet WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy usuwaniu.' });
    res.json({ message: 'Usunięto.' });
  });
});

// Dodawanie komentarza do wiadomości
app.post('/api/spotet/:id/comment', (req, res) => {
  const { id } = req.params;
  const { text, authorMail, isAnonymous } = req.body;

  if (!text || text.trim().length === 0) {
    return res.status(400).json({ message: 'Komentarz nie może być pusty.' });
  }

  const date = new Date().toISOString();

  db.run(
    `INSERT INTO spotet_comments (spotetId, text, date, authorMail, isAnonymous)
     VALUES (?, ?, ?, ?, ?)`,
    [id, text, date, authorMail, isAnonymous ? 1 : 0],
    function(err) {
      if (err) return res.status(500).json({ message: 'Błąd serwera przy dodawaniu komentarza.' });
      res.status(201).json({ id: this.lastID });
    }
  );
});

// Pobierz komentarze do wiadomości
app.get('/api/spotet/:id/comments', (req, res) => {
  const { id } = req.params;
  db.all('SELECT * FROM spotet_comments WHERE spotetId = ? ORDER BY date DESC', [id], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu komentarzy.' });
    res.json(rows);
  });
});

// Endpoint: liczba komentarzy do wiadomości Spotted
app.get('/api/spotet/:id/comments/count', (req, res) => {
  const { id } = req.params;
  db.get('SELECT COUNT(*) as count FROM spotet_comments WHERE spotetId = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy zliczaniu komentarzy.' });
    res.json({ count: row ? row.count : 0 });
  });
});

app.get('/api/ogloszenia', (req, res) => {
  const pending = req.query.pending;
  let sql = 'SELECT * FROM ogloszenia';
  if (pending === '1') {
    sql += ' WHERE pending = 1';
  } else {
    sql += ' WHERE pending = 0 OR pending IS NULL';
  }
  sql += ' ORDER BY date DESC';
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu ogłoszeń.' });
    res.json(rows);
  });
});

// Dodawanie ogłoszenia (z opcjonalnym zdjęciem)
app.post('/api/ogloszenia', upload.single('photo'), (req, res) => {
  const { title, text, authorMail, authorRole, pending } = req.body;
  const date = new Date().toISOString();
  let photo = null;
  if (req.file) {
    photo = '/uploads/' + req.file.filename;
  }
  db.run(
    `INSERT INTO ogloszenia (title, text, photo, date, authorMail, authorRole, pending)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [title, text, photo, date, authorMail, authorRole, pending ? 1 : 0],
    function(err) {
      if (err) return res.status(500).json({ message: 'Błąd serwera przy dodawaniu ogłoszenia.' });

      // Wyślij maila do usera jeśli ogłoszenie wymaga weryfikacji
      if (pending && authorMail) {
        const html = `
          <h2>Twoje ogłoszenie zostało przesłane do weryfikacji</h2>
          <p>Dziękujemy za dodanie ogłoszenia. Zostanie ono rozpatrzone przez administrację.<br>
          O decyzji poinformujemy Cię osobnym mailem.</p>
          <hr>
          <p><strong>Tytuł:</strong> ${title}</p>
          <p><strong>Treść:</strong><br>${text}</p>
          <small>Wysłano: ${new Date().toLocaleString()}</small>
        `;
        sendMail(authorMail, 'PEI: Twoje ogłoszenie czeka na akceptację', html)
          .catch(e => console.error('Mail error:', e));
      }

      res.status(201).json({ id: this.lastID });
    }
  );
});

// Edytuj ogłoszenie 
app.put('/api/ogloszenia/:id', upload.single('photo'), (req, res) => {
  let userMail = req.headers['x-user-mail'] || req.body?.userMail;
  let userRole = req.headers['x-user-role'] || req.body?.userRole;
  // Dekoduj nagłówki jeśli są zakodowane
  if (userMail) userMail = decodeURIComponent(userMail);
  if (userRole) userRole = decodeURIComponent(userRole);
  const { title, text } = req.body;

  db.get('SELECT authorMail FROM ogloszenia WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'Nie znaleziono ogłoszenia.' });

    // Tylko admin lub twórca może edytować
    if (userRole !== 'admin' && userMail !== row.authorMail) {
      return res.status(403).json({ message: 'Brak uprawnień do edycji ogłoszenia.' });
    }

    let photoSql = '';
    let params = [title, text];
    if (req.file) {
      photoSql = ', photo = ?';
      params.push('/uploads/' + req.file.filename);
    }
    params.push(req.params.id);

    db.run(
      `UPDATE ogloszenia SET title = ?, text = ?${photoSql} WHERE id = ?`,
      params,
      function(err2) {
        if (err2) return res.status(500).json({ message: 'Błąd serwera przy edycji ogłoszenia.' });
        res.json({ message: 'Zaktualizowano.' });
      }
    );
  });
});

// Usuń ogłoszenie (tylko admin lub autor)
app.delete('/api/ogloszenia/:id', (req, res) => {
  let userMail = req.headers['x-user-mail'] || req.body?.userMail;
  let userRole = req.headers['x-user-role'] || req.body?.userRole;
  // Dekoduj nagłówki jeśli są zakodowane
  if (userMail) userMail = decodeURIComponent(userMail);
  if (userRole) userRole = decodeURIComponent(userRole);

  db.get('SELECT authorMail FROM ogloszenia WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'Nie znaleziono ogłoszenia.' });

    if (userRole !== 'admin' && userMail !== row.authorMail) {
      return res.status(403).json({ message: 'Brak uprawnień do usunięcia ogłoszenia.' });
    }

    db.get('SELECT photo FROM ogloszenia WHERE id = ?', [req.params.id], (err2, row2) => {
      if (row2 && row2.photo) {
        const filePath = path.join(__dirname, row2.photo);
        fs.unlink(filePath, () => {});
      }
      db.run('DELETE FROM ogloszenia WHERE id = ?', [req.params.id], function(err3) {
        if (err3) return res.status(500).json({ message: 'Błąd serwera przy usuwaniu ogłoszenia' });
        res.json({ message: 'Usunięto.' });
      });
    });
  });
});

// Akceptacja ogłoszenia (ustawia pending=0)
app.post('/api/ogloszenia/:id/accept', (req, res) => {
  const { id } = req.params;
  db.run('UPDATE ogloszenia SET pending = 0 WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy akceptacji ogłoszenia.' });
    if (this.changes === 0) return res.status(404).json({ message: 'Nie znaleziono ogłoszenia.' });
    res.json({ message: 'Ogłoszenie zaakceptowane.' });
  });
});

// Odrzucenie ogłoszenia (usuwa ogłoszenie i wysyła maila)
app.post('/api/ogloszenia/:id/reject', (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  db.get('SELECT authorMail, title FROM ogloszenia WHERE id = ?', [id], (err, row) => {
    if (row && row.authorMail) {
      const html = `
        <h2>Twoje ogłoszenie zostało odrzucone</h2>
        <p>Ogłoszenie <strong>${row.title}</strong> zostało odrzucone przez administrację.</p>
        <p><strong>Powód:</strong> ${reason || 'brak podanego powodu'}</p>
        <hr>
        <small>Wysłano: ${new Date().toLocaleString()}</small>
      `;
      sendMail(row.authorMail, 'PEI: Twoje ogłoszenie zostało odrzucone', html)
        .catch(e => console.error('Mail error:', e));
    }
    db.run('DELETE FROM ogloszenia WHERE id = ?', [id], function(err2) {
      if (err2) return res.status(500).json({ message: 'Błąd serwera przy odrzucaniu ogłoszenia.' });
      res.json({ message: 'Ogłoszenie odrzucone.' });
    });
  });
});

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: 'peizamowieniaikontaktpei@gmail.com',
    pass: 'xmug cmsb fzey rurf'
  }
});

function sendMail(to, subject, html, replyTo) {
  return transporter.sendMail({
    from: 'Weryfikacja ogłoszenia LO2 <peizamowieniaikontaktpei@gmail.com>',
    to,
    subject,
    html,
    replyTo
  });
}

// Middleware autoryzacji i sprawdzania blokady
function authAndBlockCheck(req, res, next) {
  // DEBUG: logowanie nagłówków
  // console.log('Authorization header:', req.headers['authorization']);
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Brak tokenu lub nieprawidłowy format. Wyloguj się i zaloguj ponownie, aby korzystać z serwisu.' });
  }
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Brak tokenu. Wyloguj się i zaloguj ponownie, aby korzystać z serwisu.' });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Nieprawidłowy token. Wyloguj się i zaloguj ponownie, aby korzystać z serwisu.' });
    // Pobierz użytkownika z bazy
    db.get('SELECT * FROM users WHERE mail = ?', [decoded.mail], (err, user) => {
      if (err || !user) return res.status(401).json({ message: 'Brak użytkownika.' });
      // Sprawdź blokadę
      if (user.blockedUntil && new Date(user.blockedUntil) > new Date()) {
        const ms = new Date(user.blockedUntil) - new Date();
        const min = Math.ceil(ms / 60000);
        return res.status(403).json({
          message: `Konto zablokowane do ${user.blockedUntil} (${min} min). Powód: ${user.blockReason || 'brak'}`
        });
      }
      // Jeśli blokada została zdjęta, ale token jest stary, informuj o konieczności ponownego logowania
      if (!user.blockedUntil && decoded.blockedUntil) {
        return res.status(401).json({
          message: 'Twoja blokada została zdjęta. Wyloguj się i zaloguj ponownie, aby korzystać z serwisu.'
        });
      }
      req.user = user; // przekazujemy dalej
      next();
    });
  });
}

const SECRET = 'super_tajny_klucz'; // Ustaw swój klucz

// Sprawdzanie blokady użytkownika
app.post('/api/check-block', (req, res) => {
  const { mail } = req.body;
  if (!mail) return res.status(400).json({ message: 'Brak maila.' });
  db.get('SELECT blockedUntil, blockReason FROM users WHERE mail = ?', [mail], (err, user) => {
    if (err || !user) return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
    if (user.blockedUntil && new Date(user.blockedUntil) > new Date()) {
      const ms = new Date(user.blockedUntil) - new Date();
      const min = Math.ceil(ms / 60000);
      return res.status(403).json({
        message: `Konto zablokowane do ${user.blockedUntil} (${min} min). Powód: ${user.blockReason || 'brak'}`
      });
    }
    res.json({ ok: true });
  });
});

// Pobierz komentarze do ogłoszenia
app.get('/api/ogloszenia/:id/comments', (req, res) => {
  const { id } = req.params;
  db.all('SELECT * FROM ogloszenia_comments WHERE ogloszenieId = ? ORDER BY date DESC', [id], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu komentarzy.' });
    res.json(rows);
  });
});

// Liczba komentarzy do ogłoszenia
app.get('/api/ogloszenia/:id/comments/count', (req, res) => {
  const { id } = req.params;
  db.get('SELECT COUNT(*) as count FROM ogloszenia_comments WHERE ogloszenieId = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy zliczaniu komentarzy.' });
    res.json({ count: row ? row.count : 0 });
  });
});

// Dodawanie komentarza do ogłoszenia bez isAnonymous
app.post('/api/ogloszenia/:id/comment', (req, res) => {
  const { id } = req.params;
  const { text, authorMail } = req.body;

  // Debug log
  console.log('Dodawanie komentarza:', { id, text, authorMail });

  if (!text || text.trim().length === 0) {
    return res.status(400).json({ message: 'Komentarz nie może być pusty.' });
  }

  const date = new Date().toISOString();

  db.run(
    `INSERT INTO ogloszenia_comments (ogloszenieId, text, date, authorMail)
     VALUES (?, ?, ?, ?)`,
    [id, text, date, authorMail],
    function(err) {
      if (err) {
        console.error('Błąd SQL przy dodawaniu komentarza:', err);
        return res.status(500).json({ message: 'Błąd serwera przy dodawaniu komentarza.' });
      }
      res.status(201).json({ id: this.lastID });
    }
  );
});

// Usuń komentarz do ogłoszenia
app.delete('/api/ogloszenia/comments/:id', (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM ogloszenia_comments WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy usuwaniu komentarza.' });
    if (this.changes === 0) return res.status(404).json({ message: 'Nie znaleziono komentarza.' });
    res.json({ message: 'Komentarz usunięty.' });
  });
});



