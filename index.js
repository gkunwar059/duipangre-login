const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const mongoose = require('mongoose');

const app = express();
app.use(bodyParser.json({ limit: '10mb' }));
app.use(cors());

const users = [];
//mongodb conncetion 
// Database connection
mongoose.connect('mongodb+srv://auth:MYyyZ40YR2zMY2cn@cluster0.lzxg3eo.mongodb.net/hello', { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
})
.then(() => console.log('Connected to MongoDB...'))
.catch(error => console.log(error));


// Set up multer storage for user photo uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, new Date().toISOString() + file.originalname);
  }
});

// Filter function to only allow certain image types
const validMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];

const fileFilter = (req, file, cb) => {
  if (validMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and GIF allowed.'), false);
  }
};

// Set up multer middleware for user photo uploads
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 1024 * 1024 * 5
  },
  fileFilter: fileFilter
});

app.post('/register', upload.single('photo'), async (req, res) => {
  const {username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password,10);
  // check email is already exist 
  const userExists = users.some((user) => user.email === email );
  if (userExists) {
    return res.status(409).json({ message: 'Email or username already exists' });
  }


  // Check if file was uploaded
  let photoPath = '';
  if (req.file) {
    photoPath = req.file.path;
  }

  users.push({
    username,
    email:email,
    password: hashedPassword,
    photo: photoPath
  });

  res.json({ message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ email:email}, 'secret-key');
  res.json({user, token});
});

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  jwt.verify(token, 'secret-key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    req.user = decoded;
    next();
  });
}

app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected route', user: req.user });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
