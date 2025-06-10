const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const morgan = require('morgan');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

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
app.post('/api/books', upload.single('photo'), (req, res) => {
  const { subject, title, publisher, phoneNumber, messengerLink, instagramLink, year, grade, price, stan, imie, klasa } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: 'Brak zdjęcia (photo)' });
  }

  const newOffer = {
    subject,
    title,
    publisher,
    phoneNumber,
    messengerLink,
    instagramLink,
    year,
    grade,
    price,
    imie,
    stan,
    klasa,
    photo: `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`,
    date: new Date().toISOString()
  };

  offers.push(newOffer);
  res.status(201).json(newOffer);
});

// Endpoint GET - zwracanie ofert
app.get('/api/books', (req, res) => {
  res.json(offers);
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
