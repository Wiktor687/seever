const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const sanitizeHtml = require('sanitize-html');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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
app.post('/api/books', upload.single('photo'), (req, res) => {
  const { subject, title, publisher, phoneNumber, messengerLink, instagramLink, year, grade, price, stan, imie, klasa } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: 'Brak zdjęcia (photo)' });
  }

  const newOffer = {
    id: Date.now().toString(), // unikalny identyfikator
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

// Usuń ofertę po id
app.delete('/api/books/:id', (req, res) => {
  const { id } = req.params;
  const index = offers.findIndex(o => o.id === id);
  if (index === -1) {
    return res.status(404).json({ error: 'Nie znaleziono oferty' });
  }
  // Usuń plik zdjęcia jeśli istnieje
  const photoPath = offers[index].photo?.replace(`${req.protocol}://${req.get('host')}`, '.');
  if (photoPath && fs.existsSync(photoPath)) {
    fs.unlinkSync(photoPath);
  }
  offers.splice(index, 1);
  res.sendStatus(204);
});

// Dodawanie oferty
app.post('/api/books', (req, res) => {
    const { title, deleteCode } = req.body;
    if (!deleteCode || deleteCode.length < 4) return res.status(400).json({ message: 'Brak kodu do usuwania' });
    const id = Date.now().toString();
    books.push({ id, title, deleteCode });
    res.json({ id });
});

// Usuwanie oferty
app.delete('/api/books/:id', (req, res) => {
    const { id } = req.params;
    const { deleteCode } = req.body;
    const idx = books.findIndex(b => b.id === id);
    if (idx === -1) return res.status(404).json({ message: 'Nie znaleziono oferty' });
    if (books[idx].deleteCode !== deleteCode) return res.status(403).json({ message: 'Nieprawidłowy kod' });
    books.splice(idx, 1);
    res.json({ message: 'Oferta usunięta' });
});

// Uruchom serwer na wszystkich interfejsach
const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Serwer działa na http://0.0.0.0:${PORT} (lub przez domenę jeśli dostępna)`);
});
