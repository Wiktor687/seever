const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');

// Upewnij się, że katalog uploads istnieje
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('📁 Utworzono katalog uploads');
}

// Udostępnij katalog uploads jako statyczny z dodatkowymi headerami bezpieczeństwa
app.use('/uploads', (req, res, next) => {
  // Ustaw headery bezpieczeństwa dla plików
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'");
  
  // Sprawdź czy to jest rzeczywiście plik obrazka na podstawie rozszerzenia
  const filePath = req.path;
  const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  const ext = path.extname(filePath).toLowerCase();
  
  if (!allowedExts.includes(ext)) {
    return res.status(403).json({ error: 'Niedozwolony typ pliku' });
  }
  
  next();
}, express.static(path.join(__dirname, 'uploads')));

const multer = require('multer');
const cors = require('cors');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const sanitizeHtml = require('sanitize-html');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // Dodane dla obsługi cookies
const db = new sqlite3.Database('./users.db'); // <-- tylko raz!

// JWT Secret key - ładowany ze zmiennych środowiskowych
const SECRET = process.env.JWT_SECRET || 'super_tajny_klucz_ZMIEN_TO_W_PRODUKCJI';

/*
=== STRUKTURA BAZY DANYCH ===

1. TABELA users:
   - id (INTEGER, PRIMARY KEY, AUTOINCREMENT)
   - firstName, lastName, userClass, phone, messenger, instagram (TEXT)
   - mail (TEXT, UNIQUE)
   - password (TEXT) - zahashowane bcrypt
   - role (TEXT, DEFAULT 'user') - role: 'user', 'admin', 'przewodniczący'
   - blockedUntil (TEXT) - data końca blokady w formacie ISO
   - blockReason (TEXT) - powód blokady

2. TABELA books:
   - id (INTEGER, PRIMARY KEY, AUTOINCREMENT)
   - subject, title, publisher, year, grade, price, stan (TEXT)
   - photo (TEXT) - URL do zdjęcia
   - date (TEXT) - data dodania w formacie ISO
   - userMail, userFirstName, userLastName, userClass, userPhone, userMessenger, userInstagram (TEXT)

3. TABELA spotet:
   - id (INTEGER, PRIMARY KEY, AUTOINCREMENT)
   - text (TEXT) - treść wiadomości
   - photo (TEXT) - opcjonalne zdjęcie
   - date (TEXT) - data w formacie ISO
   - authorMail (TEXT) - mail autora

4. TABELA spotet_comments:
   - id (INTEGER, PRIMARY KEY, AUTOINCREMENT)
   - spotetId (INTEGER) - ID wiadomości spotet
   - text (TEXT) - treść komentarza
   - date (TEXT) - data w formacie ISO
   - authorMail (TEXT) - mail autora
   - isAnonymous (INTEGER, DEFAULT 0) - czy komentarz anonimowy

5. TABELA ogloszenia:
   - id (INTEGER, PRIMARY KEY, AUTOINCREMENT)
   - title (TEXT) - tytuł ogłoszenia
   - text (TEXT) - treść ogłoszenia
   - photo (TEXT) - opcjonalne zdjęcie
   - date (TEXT) - data w formacie ISO
   - authorMail (TEXT) - mail autora
   - authorRole (TEXT) - rola autora
   - pending (INTEGER, DEFAULT 0) - czy czeka na akceptację

6. TABELA ogloszenia_comments:
   - id (INTEGER, PRIMARY KEY, AUTOINCREMENT)
   - ogloszenieId (INTEGER) - ID ogłoszenia
   - text (TEXT) - treść komentarza
   - date (TEXT) - data w formacie ISO
   - authorMail (TEXT) - mail autora
   - isAnonymous (INTEGER, DEFAULT 0) - czy komentarz anonimowy
*/

// Tworzenie wszystkich tabel z pełnymi kolumnami
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firstName TEXT,
  lastName TEXT,
  userClass TEXT,
  phone TEXT,
  messenger TEXT,
  instagram TEXT,
  mail TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'user',
  blockedUntil TEXT,
  blockReason TEXT
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
  const hash = await bcrypt.hash('NpWz5678', 10);

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
  origin: [
    'https://wiktorksiazka.api.pei.pl', 
    'https://pei.pl', 
    'https://www.pei.pl', 
    'http://localhost:8081', 
    'http://localhost:8082',
    'http://192.168.74.225:8081',
    'http://192.168.74.225:8082',
    'exp://192.168.74.225:8081',
    'exp://192.168.74.225:8082',
    'exp://l_nwawc-anonymous-8082.exp.direct' // Expo tunnel
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-user-mail', 'x-user-role', 'Authorization'],
  credentials: true // Wymagane dla cookies
}));

// Middleware dla cookies
app.use(cookieParser());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Pamięć na oferty (tymczasowa, bez bazy danych)
const offers = [];

// Konfiguracja Multera do zapisu zdjęć z bezpieczeństwem
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads'); // katalog musi istnieć!
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    // Wymuś bezpieczne rozszerzenie
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const finalExt = allowedExts.includes(ext) ? ext : '.jpg';
    cb(null, uniqueSuffix + finalExt);
  }
});

// Filtr bezpieczeństwa dla plików
const fileFilter = (req, file, cb) => {
  // Sprawdź MIME type
  const allowedMimes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  if (!allowedMimes.includes(file.mimetype)) {
    return cb(new Error('Niedozwolony typ pliku. Dozwolone: JPG, PNG, GIF, WEBP'), false);
  }
  
  // Sprawdź rozszerzenie
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  if (!allowedExts.includes(ext)) {
    return cb(new Error('Niedozwolone rozszerzenie pliku'), false);
  }
  
  // Sprawdź nazwę pliku - usuń niebezpieczne znaki
  const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '');
  if (sanitizedName.length === 0) {
    return cb(new Error('Nieprawidłowa nazwa pliku'), false);
  }
  
  cb(null, true);
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1 // tylko 1 plik
  }
});

// Middleware do sprawdzania bezpieczeństwa plików
const validateUploadSecurity = (req, res, next) => {
  // Sprawdź Headers bezpieczeństwa
  req.headers['x-content-type-options'] = 'nosniff';
  req.headers['x-frame-options'] = 'DENY';
  
  next();
};

// Użyj middleware przed wszystkimi endpointami upload
app.use('/api/books', validateUploadSecurity);
app.use('/api/spotet', validateUploadSecurity);

// Endpoint POST - dodawanie oferty
app.post('/api/books', authAndBlockCheck, (req, res) => {
  console.log('�🚀🚀 NOWY REQUEST DO /api/books! 🚀🚀🚀');
  console.log('�🔄 /api/books POST - Otrzymane dane:', {
    body: req.body,
    hasFile: !!req.file,
    user: req.user ? req.user.mail : 'BRAK'
  });
  
  // Obsługa uploadu z multer
  upload.single('photo')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'Plik jest za duży. Maksymalny rozmiar: 5MB' });
      }
      return res.status(400).json({ error: 'Błąd uploadu: ' + err.message });
    } else if (err) {
      return res.status(400).json({ error: err.message });
    }

    // Dane książki z formularza
    const { subject, title, publisher, year, grade, price, stan } = req.body;

    // Dane użytkownika z konta (z middleware)
    const user = req.user;
    console.log('🔍 User z middleware:', user ? user.mail : 'BRAK');
    
    if (!user || !user.mail || !user.mail.endsWith('@lo2.przemysl.edu.pl')) {
      console.log('❌ Błąd autoryzacji:', { 
        hasUser: !!user, 
        mail: user?.mail, 
        endsWithSchool: user?.mail?.endsWith('@lo2.przemysl.edu.pl') 
      });
      return res.status(400).json({ message: 'Musisz być zalogowany, aby dodać książkę.' });
    }
    
    console.log('🔍 Sprawdzanie pliku:', { hasFile: !!req.file });
    if (!req.file) {
      console.log('❌ Brak zdjęcia');
      return res.status(400).json({ error: 'Brak zdjęcia (photo)' });
    }

    // Loguj informacje o uploadowanym pliku
    console.log('📸 Upload pliku:', {
      originalname: req.file.originalname,
      filename: req.file.filename,
      mimetype: req.file.mimetype,
      size: req.file.size,
      user: user.mail
    });

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
app.delete('/api/books/:id', authAndBlockCheck, (req, res) => {
  const { id } = req.params;
  const currentUser = req.user; // Z middleware authAndBlockCheck

  db.get('SELECT * FROM books WHERE id = ?', [id], (err, book) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy sprawdzaniu oferty.' });
    if (!book) return res.status(404).json({ message: 'Nie znaleziono oferty' });

    // Pozwól adminowi/przewodniczącemu lub właścicielowi
    if (
      currentUser.mail === book.userMail ||
      currentUser.mail === 'admin@lo2.przemysl.edu.pl' ||
      currentUser.role === 'admin' ||
      currentUser.role === 'przewodniczący' ||
      currentUser.role === 'przewodniczacy'
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

// ====================================================================
// ✅ SYSTEM WERYFIKACJI EMAILA PRZEZ KOD
// ====================================================================

// Tabela dla kodów weryfikacyjnych
db.run(`CREATE TABLE IF NOT EXISTS verification_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

// Funkcja generowania kodu weryfikacyjnego
function generateVerificationCode() {
  return Math.random().toString().slice(2, 8).padStart(6, '0');
}

// ✅ ENDPOINT: Wysłanie kodu weryfikacyjnego na email
app.post('/api/send-verification-code', async (req, res) => {
  try {
    const { email, name } = req.body;
    
    // Walidacja
    if (!email || !name) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email i imię są wymagane' 
      });
    }
    
    // Sprawdź format emaila
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Nieprawidłowy format email' 
      });
    }
    
    // Sprawdź czy email już nie istnieje w bazie
    db.get('SELECT * FROM users WHERE mail = ?', [email], async (err, existingUser) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Błąd serwera' 
        });
      }
      
      if (existingUser) {
        return res.status(400).json({ 
          success: false, 
          message: 'Użytkownik z tym emailem już istnieje' 
        });
      }
      
      // Wygeneruj kod
      const code = generateVerificationCode();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minut
      
      // Usuń stare kody dla tego emaila
      db.run('DELETE FROM verification_codes WHERE email = ?', [email], (deleteErr) => {
        if (deleteErr) {
          console.error('Error deleting old codes:', deleteErr);
        }
        
        // Zapisz nowy kod
        db.run(
          'INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)',
          [email, code, expiresAt],
          async function(insertErr) {
            if (insertErr) {
              console.error('Error saving verification code:', insertErr);
              return res.status(500).json({ 
                success: false, 
                message: 'Błąd zapisu kodu weryfikacyjnego' 
              });
            }
            
            // Wyślij email z kodem
            try {
              const htmlMessage = `
                <h2 style='color:#FF6B35;'>Wirtualny korytarz LO2</h2>
                <p style='font-size:1.1em;'>Weryfikacja konta:</p>
                <h3 style='color:#333;'>Twój kod weryfikacyjny</h3>
                <div style='border:2px dashed #FF6B35; background:#f9f9f9; padding:18px; font-size:2em; text-align:center; letter-spacing:4px; margin:18px 0 24px 0; color:#FF6B35; font-weight:bold;'>
                  ${code}
                </div>
                <p>Cześć <b>${name}</b>!</p>
                <p>Wpisz powyższy kod w aplikacji mobilnej, aby potwierdzić swój adres e-mail i zakończyć rejestrację.</p>
                <p><strong>Kod jest ważny przez 15 minut.</strong></p>
                <hr>
                <small style='color:#888;'>Wiadomość wygenerowana automatycznie przez aplikację Wirtualny korytarz LO2.<br>
                Wysłano: ${new Date().toLocaleString('pl-PL')} z IP: ${req.ip}</small>
              `;
              
              await sendMail(
                email,
                'Kod weryfikacyjny - Wirtualny korytarz LO2',
                htmlMessage,
                'peizamowieniaikontaktpei@gmail.com'
              );
              
              console.log(`✅ Kod weryfikacyjny wysłany na ${email}: ${code}`);
              
              res.json({
                success: true,
                message: 'Kod weryfikacyjny został wysłany na podany adres email',
                expiresIn: 15 // minuty
              });
              
            } catch (emailError) {
              console.error('Email sending error:', emailError);
              
              // Usuń kod z bazy jeśli nie udało się wysłać emaila
              db.run('DELETE FROM verification_codes WHERE id = ?', [this.lastID]);
              
              res.status(500).json({ 
                success: false, 
                message: 'Błąd wysyłania emaila. Spróbuj ponownie.' 
              });
            }
          }
        );
      });
    });
    
  } catch (error) {
    console.error('Send verification code error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Błąd serwera' 
    });
  }
});

// ✅ ENDPOINT: Weryfikacja kodu
app.post('/api/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    
    // Walidacja
    if (!email || !code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email i kod są wymagane' 
      });
    }
    
    // Znajdź kod w bazie
    db.get(
      'SELECT * FROM verification_codes WHERE email = ? AND code = ? AND used = 0 ORDER BY created_at DESC LIMIT 1',
      [email, code],
      (err, verificationRecord) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Błąd serwera' 
          });
        }
        
        if (!verificationRecord) {
          return res.status(400).json({ 
            success: false, 
            message: 'Nieprawidłowy kod weryfikacyjny' 
          });
        }
        
        // Sprawdź czy kod nie wygasł
        const now = new Date();
        const expiresAt = new Date(verificationRecord.expires_at);
        
        if (now > expiresAt) {
          return res.status(400).json({ 
            success: false, 
            message: 'Kod weryfikacyjny wygasł. Poproś o nowy kod.' 
          });
        }
        
        // NIE oznaczamy kodu jako użyty - zostanie oznaczony dopiero przy rejestracji
        console.log(`✅ Kod zweryfikowany pomyślnie dla ${email}`);
        
        res.json({
          success: true,
          message: 'Kod weryfikacyjny poprawny. Możesz kontynuować rejestrację.',
          verified: true
        });
      }
    );
    
  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Błąd serwera' 
    });
  }
});

// REJESTRACJA (ZMODYFIKOWANA - z weryfikacją kodu)
app.post('/api/register', async (req, res) => {
  console.log('🔄 /api/register - Otrzymane dane:', req.body);
  const { firstName, lastName, userClass, phone, messenger, instagram, mail, password, verificationCode } = req.body;
  
  console.log('🔍 Sprawdzanie czy użytkownik już istnieje:', mail);
  db.get('SELECT * FROM users WHERE mail = ?', [mail], async (err, row) => {
    if (err) {
      console.error('❌ Database error checking user:', err);
      return res.status(500).json({ message: 'Błąd bazy danych' });
    }
    if (row) {
      console.log('❌ Użytkownik już istnieje:', mail);
      return res.status(400).json({ message: 'Użytkownik z tym mailem już istnieje' });
    }

    console.log('🔍 Sprawdzanie kodu weryfikacyjnego:', verificationCode, 'dla:', mail);
    // Weryfikacja kodu
    db.get(
      'SELECT * FROM verification_codes WHERE email = ? AND code = ? AND used = 0',
      [mail, verificationCode],
      async (err, verificationRecord) => {
        if (err) {
          console.error('❌ Database error checking verification code:', err);
          return res.status(500).json({ message: 'Błąd bazy danych' });
        }
        if (!verificationRecord) {
          console.log('❌ Nieprawidłowy kod weryfikacyjny dla:', mail, 'kod:', verificationCode);
          return res.status(400).json({ message: 'Nieprawidłowy lub użyty kod weryfikacyjny' });
        }

        console.log('✅ Znaleziono kod weryfikacyjny:', verificationRecord);

        // Sprawdź czy kod nie wygasł
        const now = new Date();
        const expiresAt = new Date(verificationRecord.expires_at);
        
        if (now > expiresAt) {
          return res.status(400).json({ message: 'Kod weryfikacyjny wygasł. Poproś o nowy kod.' });
        }

        const hash = await bcrypt.hash(password, 10);
        db.run(
          `INSERT INTO users (firstName, lastName, userClass, phone, messenger, instagram, mail, password)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [firstName, lastName, userClass, phone, messenger, instagram, mail, hash],
          function (err) {
            if (err) return res.status(500).json({ message: 'Błąd zapisu do bazy' });
            
            // Generuj token JWT po udanej rejestracji
            const newUser = { firstName, lastName, userClass, phone, messenger, instagram, mail, role: 'user' };
            const token = jwt.sign(newUser, SECRET, { expiresIn: '30d' });
            
            // Ustaw httpOnly cookie z tokenem
            res.cookie('jwt_token', token, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production', // Secure tylko w production
              sameSite: 'strict',
              maxAge: 30 * 24 * 60 * 60 * 1000, // 30 dni
              domain: process.env.NODE_ENV === 'production' ? '.pei.pl' : undefined // Domain tylko w production
            });
            
            // Oznacz kod jako użyty
            db.run('UPDATE verification_codes SET used = 1 WHERE id = ?', [verificationRecord.id]);

            res.json({
              message: 'Rejestracja zakończona',
              user: newUser
            });
          }
        );
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

    // Ustaw httpOnly cookie z tokenem
    res.cookie('jwt_token', token, {
      httpOnly: true,        // Niedostępne dla JavaScript
      secure: process.env.NODE_ENV === 'production', // Secure tylko w production
      sameSite: 'strict',    // CSRF protection
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 dni w milisekundach
      domain: process.env.NODE_ENV === 'production' ? '.pei.pl' : undefined // Domain tylko w production
    });

    // Usuń pole password z usera przed wysłaniem!
    const { password: _, ...userData } = user;

    // Zwróć dane użytkownika bez tokenu (token jest w cookie)
    res.json({ user: userData, message: 'Zalogowano pomyślnie' });
  });
});

// WYLOGOWANIE - endpoint do usuwania cookie
app.post('/api/logout', (req, res) => {
  // Usuń cookie z tokenem
  res.clearCookie('jwt_token', {
    domain: process.env.NODE_ENV === 'production' ? '.pei.pl' : undefined,
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  
  res.json({ message: 'Wylogowano pomyślnie' });
});

// WERYFIKACJA TOKENU - endpoint do sprawdzania ważności tokenu i pobierania danych użytkownika
app.post('/api/verify-token', (req, res) => {
  // Sprawdź token tylko w cookie (już nie fallback na Authorization header)
  let token = req.cookies.jwt_token;
  
  if (!token) {
    return res.status(401).json({ message: 'Brak tokenu autoryzacji' });
  }

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Nieprawidłowy lub wygasły token' });
    }
    
    // Pobierz aktualną wersję użytkownika z bazy
    db.get('SELECT * FROM users WHERE mail = ?', [decoded.mail], (err, user) => {
      if (err || !user) {
        return res.status(401).json({ message: 'Użytkownik nie istnieje' });
      }
      
      // Sprawdź blokadę
      if (user.blockedUntil && new Date(user.blockedUntil) > new Date()) {
        const ms = new Date(user.blockedUntil) - new Date();
        const min = Math.ceil(ms / 60000);
        return res.status(403).json({
          message: `Konto zablokowane do ${user.blockedUntil} (${min} min). Powód: ${user.blockReason || 'brak'}`
        });
      }
      
      // Usuń hasło z odpowiedzi
      const { password: _, ...userData } = user;
      
      res.json({ 
        valid: true, 
        user: userData,
        token: token // zwróć ten sam token dla kompatybilności
      });
    });
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

// Test endpoint dla diagnozy połączenia
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Backend działa!', 
    timestamp: new Date().toISOString(),
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
});

// Uruchom serwer na wszystkich interfejsach
const PORT = 8000; // Zmieniono z 3000 na 8000
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Serwer działa na http://0.0.0.0:${PORT} (lub przez domenę jeśli dostępna)`);
});

// Pobierz wszystkich użytkowników (tylko admin)
app.get('/api/users', authAndBlockCheck, (req, res) => {
  // Tylko admin może przeglądać listę użytkowników
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Brak uprawnień. Tylko admin może przeglądać listę użytkowników.' });
  }
  
  db.all('SELECT id, firstName, lastName, userClass, phone, messenger, instagram, mail, role, blockedUntil, blockReason FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
    // Usuń hasła z odpowiedzi (dodatkowe zabezpieczenie)
    const usersWithoutPasswords = rows.map(user => {
      const { password, ...userWithoutPassword } = user;
      return userWithoutPassword;
    });
    res.json(usersWithoutPasswords);
  });
});

app.get('/api/users/:mail', authAndBlockCheck, (req, res) => {
  db.get('SELECT * FROM users WHERE mail = ?', [req.params.mail], (err, row) => {
    if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
    if (!row) return res.status(404).json({ message: 'Nie znaleziono użytkownika' });
    
    // Sprawdź czy użytkownik ma uprawnienia - może przeglądać tylko swoje dane lub admin może wszystkie
    const requestingUser = req.user; // z middleware authAndBlockCheck
    if (requestingUser.mail !== req.params.mail && requestingUser.role !== 'admin') {
      return res.status(403).json({ message: 'Brak uprawnień do przeglądania danych tego użytkownika' });
    }
    
    // Usuń hasło z odpowiedzi
    const { password, ...userData } = row;
    res.json(userData);
  });
});

// Dodawanie anonimowej wiadomości (z opcjonalnym zdjęciem)
// Użyj tej samej bezpiecznej konfiguracji multer dla spotted
const spotetUpload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1 // tylko 1 plik
  }
});

// DODANO: authAndBlockCheck jako middleware!
app.post('/api/spotet', authAndBlockCheck, (req, res) => {
  // Obsługa uploadu z multer
  spotetUpload.single('photo')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'Plik jest za duży. Maksymalny rozmiar: 5MB' });
      }
      return res.status(400).json({ error: 'Błąd uploadu: ' + err.message });
    } else if (err) {
      return res.status(400).json({ error: err.message });
    }

    const { text } = req.body;
    // BEZPIECZEŃSTWO: Pobierz authorMail z tokena, nie z requesta
    const user = req.user; // Z middleware authAndBlockCheck
    const authorMail = user.mail;
    
    if (!authorMail) return res.status(401).json({ message: 'Musisz być zalogowany.' });
    if (!text || text.trim().length === 0) return res.status(400).json({ message: 'Wiadomość nie może być pusta.' });

    let photoUrl = '';
    if (req.file) {
      // Loguj informacje o uploadowanym pliku
      console.log('📸 Upload pliku spotted:', {
        originalname: req.file.originalname,
        filename: req.file.filename,
        mimetype: req.file.mimetype,
        size: req.file.size,
        user: authorMail
      });
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
});

// Pobierz wszystkie anonimowe wiadomości
app.get('/api/spotet', (req, res) => {
  // Sprawdź czy user jest zalogowany i czy jest adminem - używaj cookies
  let token = req.cookies.jwt_token;
  let isUserAdmin = false;
  let currentUserMail = null;
  
  if (token) {
    try {
      const decoded = jwt.verify(token, SECRET);
      currentUserMail = decoded.mail;
      isUserAdmin = decoded.role === 'admin';
    } catch (err) {
      // Token nieprawidłowy, kontynuuj jako niezalogowany
    }
  }
  
  db.all(`
    SELECT spotet.id, spotet.text, spotet.photo, spotet.date, spotet.authorMail, users.role as authorRole
    FROM spotet
    LEFT JOIN users ON spotet.authorMail = users.mail
    ORDER BY date DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu wiadomości.' });
    
    // Filtruj dane w zależności od uprawnień użytkownika
    const filteredRows = rows.map(row => ({
      ...row,
      authorMail: isUserAdmin ? row.authorMail : null, // Tylko admin widzi emaile
      isCurrentUserAdmin: isUserAdmin,
      currentUserMail: currentUserMail
    }));
    
    res.json(filteredRows);
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
app.post('/api/spotet/:id/comment', authAndBlockCheck, (req, res) => {
  const { id } = req.params;
  const { text, isAnonymous } = req.body;
  
  // BEZPIECZEŃSTWO: Pobierz autorMail z tokena, nie z requesta
  const user = req.user; // Z middleware authAndBlockCheck
  const authorMail = user.mail;

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
  
  // Sprawdź czy user jest zalogowany i czy jest adminem - używaj cookies
  let token = req.cookies.jwt_token;
  let isUserAdmin = false;
  let currentUserMail = null;
  
  if (token) {
    try {
      const decoded = jwt.verify(token, SECRET);
      currentUserMail = decoded.mail;
      isUserAdmin = decoded.role === 'admin';
    } catch (err) {
      // Token nieprawidłowy, kontynuuj jako niezalogowany
    }
  }
  
  db.all('SELECT * FROM spotet_comments WHERE spotetId = ? ORDER BY date DESC', [id], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu komentarzy.' });
    
    // Filtruj dane w zależności od uprawnień użytkownika
    const filteredRows = rows.map(row => ({
      ...row,
      // Admin widzi wszystkie emaile, zwykły user tylko swoje podpisane komentarze
      displayAuthor: isUserAdmin ? (row.authorMail || 'Anonim') : 
                    (row.isAnonymous ? 'Anonim' : 
                     (row.authorMail === currentUserMail ? row.authorMail : 'Anonim')),
      isCurrentUserAdmin: isUserAdmin,
      currentUserMail: currentUserMail
    }));
    
    res.json(filteredRows);
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
  
  // Jeśli żądanie dotyczy ogłoszeń oczekujących (pending=1), wymagaj autoryzacji
  if (pending === '1') {
    return authAndBlockCheck(req, res, () => {
      const user = req.user;
      // Sprawdź uprawnienia do panelu moderacji
      if (user.role !== 'admin' && user.role !== 'przewodniczacy' && user.role !== 'przewodniczący') {
        return res.status(403).json({ message: 'Brak uprawnień do przeglądania ogłoszeń oczekujących.' });
      }
      
      db.all('SELECT * FROM ogloszenia WHERE pending = 1 ORDER BY date DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu ogłoszeń.' });
        res.json(rows);
      });
    });
  }
  
  // Dla zwykłych ogłoszeń (opublikowanych) nie wymagaj autoryzacji
  db.all('SELECT * FROM ogloszenia WHERE pending = 0 OR pending IS NULL ORDER BY date DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy pobieraniu ogłoszeń.' });
    res.json(rows);
  });
});

// Dodawanie ogłoszenia (z opcjonalnym zdjęciem)
app.post('/api/ogloszenia', authAndBlockCheck, upload.single('photo'), (req, res) => {
  const { title, text } = req.body;
  const user = req.user; // Z middleware authAndBlockCheck
  const date = new Date().toISOString();
  
  let photo = null;
  if (req.file) {
    photo = '/uploads/' + req.file.filename;
  }
  
  // Backend określa czy wymagana jest weryfikacja na podstawie roli z bazy danych
  const requiresVerification = ['user', 'uczen'].includes(user.role);
  const authorRole = user.role;
  const authorMail = user.mail;
  
  db.run(
    `INSERT INTO ogloszenia (title, text, photo, date, authorMail, authorRole, pending)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [title, text, photo, date, authorMail, authorRole, requiresVerification ? 1 : 0],
    function(err) {
      if (err) return res.status(500).json({ message: 'Błąd serwera przy dodawaniu ogłoszenia.' });

      // Wyślij maila do usera jeśli ogłoszenie wymaga weryfikacji
      if (requiresVerification && authorMail) {
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
app.put('/api/ogloszenia/:id', authAndBlockCheck, upload.single('photo'), (req, res) => {
  const currentUser = req.user; // Z middleware authAndBlockCheck
  const { title, text } = req.body;

  db.get('SELECT authorMail FROM ogloszenia WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'Nie znaleziono ogłoszenia.' });

    // Tylko admin lub twórca może edytować
    if (currentUser.role !== 'admin' && currentUser.mail !== row.authorMail) {
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
app.delete('/api/ogloszenia/:id', authAndBlockCheck, (req, res) => {
  const currentUser = req.user; // Z middleware authAndBlockCheck

  db.get('SELECT authorMail FROM ogloszenia WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'Nie znaleziono ogłoszenia.' });

    if (currentUser.role !== 'admin' && currentUser.mail !== row.authorMail) {
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

// Akceptacja ogłoszenia (ustawia pending=0) - tylko dla admin/przewodniczący
app.post('/api/ogloszenia/:id/accept', authAndBlockCheck, (req, res) => {
  const { id } = req.params;
  const currentUser = req.user; // Z middleware authAndBlockCheck
  
  // Sprawdź uprawnienia do moderacji
  if (currentUser.role !== 'admin' && currentUser.role !== 'przewodniczacy' && currentUser.role !== 'przewodniczący') {
    return res.status(403).json({ message: 'Brak uprawnień do akceptacji ogłoszeń.' });
  }
  
  db.run('UPDATE ogloszenia SET pending = 0 WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy akceptacji ogłoszenia.' });
    if (this.changes === 0) return res.status(404).json({ message: 'Nie znaleziono ogłoszenia.' });
    res.json({ message: 'Ogłoszenie zaakceptowane.' });
  });
});

// Odrzucenie ogłoszenia (usuwa ogłoszenie i wysyła maila) - tylko dla admin/przewodniczący
app.post('/api/ogloszenia/:id/reject', authAndBlockCheck, (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  const currentUser = req.user; // Z middleware authAndBlockCheck
  
  // Sprawdź uprawnienia do moderacji
  if (currentUser.role !== 'admin' && currentUser.role !== 'przewodniczacy' && currentUser.role !== 'przewodniczący') {
    return res.status(403).json({ message: 'Brak uprawnień do odrzucania ogłoszeń.' });
  }
  
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

// Middleware autoryzacji i sprawdzania blokady - obsługuje cookies
function authAndBlockCheck(req, res, next) {
  // Sprawdź token w cookie (priorytet) lub w header Authorization (fallback)
  let token = req.cookies.jwt_token;
  
  if (!token) {
    // Fallback - sprawdź header Authorization dla kompatybilności wstecznej
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }
  }
  
  if (!token) {
    return res.status(401).json({ message: 'Brak tokenu autoryzacji. Zaloguj się ponownie.' });
  }

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Nieprawidłowy token. Zaloguj się ponownie.' });
    
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
          message: 'Twoja blokada została zdjęta. Zaloguj się ponownie, aby korzystać z serwisu.'
        });
      }
      
      req.user = user; // przekazujemy dalej
      next();
    });
  });
}

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

// Dodawanie komentarza do ogłoszenia - wymaga autoryzacji
app.post('/api/ogloszenia/:id/comment', authAndBlockCheck, (req, res) => {
  const { id } = req.params;
  const { text } = req.body;
  const currentUser = req.user; // Z middleware authAndBlockCheck

  // Debug log
  console.log('Dodawanie komentarza:', { id, text, authorMail: currentUser.mail });

  if (!text || text.trim().length === 0) {
    return res.status(400).json({ message: 'Komentarz nie może być pusty.' });
  }

  const date = new Date().toISOString();
  const authorMail = currentUser.mail; // Użyj maila z tokena, nie z requesta

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

// Usuń komentarz do ogłoszenia - tylko admin lub właściciel komentarza
app.delete('/api/ogloszenia/comments/:id', authAndBlockCheck, (req, res) => {
  const { id } = req.params;
  const currentUser = req.user; // Z middleware authAndBlockCheck
  
  // Najpierw sprawdź kto jest właścicielem komentarza
  db.get('SELECT authorMail FROM ogloszenia_comments WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy sprawdzaniu komentarza.' });
    if (!row) return res.status(404).json({ message: 'Nie znaleziono komentarza.' });
    
    // Sprawdź uprawnienia: admin lub właściciel komentarza
    if (currentUser.role !== 'admin' && currentUser.mail !== row.authorMail) {
      return res.status(403).json({ message: 'Brak uprawnień do usunięcia tego komentarza.' });
    }
    
    // Usuń komentarz
    db.run('DELETE FROM ogloszenia_comments WHERE id = ?', [id], function(err2) {
      if (err2) return res.status(500).json({ message: 'Błąd serwera przy usuwaniu komentarza.' });
      if (this.changes === 0) return res.status(404).json({ message: 'Nie znaleziono komentarza.' });
      res.json({ message: 'Komentarz usunięty.' });
    });
  });
});

// Usuń komentarz do wiadomości spotted (admin lub właściciel)
app.delete('/api/spotet/comments/:id', authAndBlockCheck, (req, res) => {
  const { id } = req.params;
  const currentUser = req.user; // Z middleware authAndBlockCheck
  
  // Sprawdź czy komentarz istnieje i kto go napisał
  db.get('SELECT * FROM spotet_comments WHERE id = ?', [id], (err, comment) => {
    if (err) return res.status(500).json({ message: 'Błąd serwera przy sprawdzaniu komentarza.' });
    if (!comment) return res.status(404).json({ message: 'Nie znaleziono komentarza.' });
    
    // Tylko admin lub właściciel komentarza może go usunąć
    if (currentUser.role !== 'admin' && currentUser.mail !== comment.authorMail) {
      return res.status(403).json({ message: 'Brak uprawnień do usunięcia tego komentarza.' });
    }
    
    // Usuń komentarz
    db.run('DELETE FROM spotet_comments WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ message: 'Błąd serwera przy usuwaniu komentarza.' });
      res.json({ message: 'Komentarz usunięty.' });
    });
  });
});

// Funkcja do dodawania brakujących kolumn w istniejących tabelach
function updateExistingTables() {
  // Sprawdź czy tabela users istnieje przed próbą dodania kolumn
  db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
    if (err) {
      console.log('Błąd sprawdzania tabeli users:', err.message);
      return;
    }
    
    if (!row) {
      console.log('Tabela users nie istnieje jeszcze - pomijam aktualizację kolumn');
      return;
    }

    // Sprawdź jakie kolumny już istnieją
    db.all("PRAGMA table_info(users)", (err, columns) => {
      if (err) {
        console.log('Błąd sprawdzania kolumn tabeli users:', err.message);
        return;
      }

      const existingColumns = columns.map(col => col.name);
      
      // Dodaj kolumnę role jeśli nie istnieje
      if (!existingColumns.includes('role')) {
        db.run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`, (err) => {
          if (err) {
            console.log('Błąd dodawania kolumny role:', err.message);
          } else {
            console.log('✅ Dodano kolumnę role do tabeli users');
          }
        });
      }
      
      // Dodaj kolumnę blockedUntil jeśli nie istnieje
      if (!existingColumns.includes('blockedUntil')) {
        db.run(`ALTER TABLE users ADD COLUMN blockedUntil TEXT`, (err) => {
          if (err) {
            console.log('Błąd dodawania kolumny blockedUntil:', err.message);
          } else {
            console.log('✅ Dodano kolumnę blockedUntil do tabeli users');
          }
        });
      }
      
      // Dodaj kolumnę blockReason jeśli nie istnieje
      if (!existingColumns.includes('blockReason')) {
        db.run(`ALTER TABLE users ADD COLUMN blockReason TEXT`, (err) => {
          if (err) {
            console.log('Błąd dodawania kolumny blockReason:', err.message);
          } else {
            console.log('✅ Dodano kolumnę blockReason do tabeli users');
          }
        });
      }
    });
  });
}

// Wywołaj aktualizację tabel dla istniejących baz danych po krótkim opóźnieniu
setTimeout(() => {
  updateExistingTables();
}, 100);

// Endpoint do sprawdzania uprawnień użytkownika
app.get('/api/check-permissions', authAndBlockCheck, (req, res) => {
  const user = req.user;
  
  const permissions = {
    canAddBooks: true, // każdy zalogowany może dodawać książki
    canAddSpotted: true, // każdy zalogowany może dodawać spotted
    canAddAnnouncements: ['admin', 'nauczyciel', 'przewodniczący', 'przewodniczacy', 'uczen', 'user'].includes(user.role),
    canSeeAdminPanel: ['admin', 'przewodniczący', 'przewodniczacy'].includes(user.role),
    canAccessAdminPanel: ['admin', 'przewodniczący', 'przewodniczacy'].includes(user.role),
    canDeleteAnyOffer: ['admin', 'przewodniczący', 'przewodniczacy'].includes(user.role),
    canModerateContent: user.role === 'admin',
    canSeeAllEmails: user.role === 'admin',
    role: user.role,
    mail: user.mail,
    isAdmin: user.role === 'admin',
    isPrzewodniczacy: ['przewodniczący', 'przewodniczacy'].includes(user.role)
  };
  
  res.json(permissions);
});

// Endpoint do sprawdzania uprawnień do konkretnej akcji
app.post('/api/check-action-permission', authAndBlockCheck, (req, res) => {
  const user = req.user;
  const { action, resourceId, resourceType } = req.body;
  
  let hasPermission = false;
  
  switch (action) {
    case 'delete_book':
      // Admin może usuwać wszystkie, user tylko swoje
      if (user.role === 'admin') {
        hasPermission = true;
      } else if (resourceId) {
        // Sprawdź w bazie czy user jest właścicielem książki
        db.get('SELECT userMail FROM books WHERE id = ?', [resourceId], (err, book) => {
          if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
          hasPermission = book && book.userMail === user.mail;
          res.json({ hasPermission, reason: hasPermission ? 'owner' : 'not_owner' });
        });
        return; // exit early dla async sprawdzenia
      }
      break;
      
    case 'delete_spotted':
      // Admin może usuwać wszystkie, user tylko swoje
      if (user.role === 'admin') {
        hasPermission = true;
      } else if (resourceId) {
        db.get('SELECT authorMail FROM spotet WHERE id = ?', [resourceId], (err, spotted) => {
          if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
          hasPermission = spotted && spotted.authorMail === user.mail;
          res.json({ hasPermission, reason: hasPermission ? 'owner' : 'not_owner' });
        });
        return;
      }
      break;
      
    case 'delete_announcement':
      // Admin może usuwać wszystkie, przewodniczący tylko swoje
      if (user.role === 'admin') {
        hasPermission = true;
      } else if (['przewodniczący', 'przewodniczacy'].includes(user.role) && resourceId) {
        db.get('SELECT authorMail FROM ogloszenia WHERE id = ?', [resourceId], (err, announcement) => {
          if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
          hasPermission = announcement && announcement.authorMail === user.mail;
          res.json({ hasPermission, reason: hasPermission ? 'owner' : 'not_owner' });
        });
        return;
      }
      break;
      
    case 'edit_announcement':
      // Podobnie jak delete_announcement
      if (user.role === 'admin') {
        hasPermission = true;
      } else if (['przewodniczący', 'przewodniczacy'].includes(user.role) && resourceId) {
        db.get('SELECT authorMail FROM ogloszenia WHERE id = ?', [resourceId], (err, announcement) => {
          if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
          hasPermission = announcement && announcement.authorMail === user.mail;
          res.json({ hasPermission, reason: hasPermission ? 'owner' : 'not_owner' });
        });
        return;
      }
      break;
      
    case 'delete_comment':
      // Admin może usuwać wszystkie komentarze, user tylko swoje
      if (user.role === 'admin') {
        hasPermission = true;
      } else if (resourceId && resourceType) {
        const table = resourceType === 'spotted' ? 'spotet_comments' : 'ogloszenia_comments';
        db.get(`SELECT authorMail FROM ${table} WHERE id = ?`, [resourceId], (err, comment) => {
          if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
          hasPermission = comment && comment.authorMail === user.mail;
          res.json({ hasPermission, reason: hasPermission ? 'owner' : 'not_owner' });
        });
        return;
      }
      break;
      
    default:
      hasPermission = false;
  }
  
  res.json({ hasPermission, reason: hasPermission ? 'authorized' : 'unauthorized' });
});
