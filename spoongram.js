// SpoonGram - Mini Instagram pour cuillères géolocalisées
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const flash = require('connect-flash');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB
mongoose.connect(process.env.MONGODB_URI)
mongoose.connection.on('connected', () => console.log('Connected to MongoDB'));

// User Schema/Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '/images/default-avatar.jpg' },
  createdAt: { type: Date, default: Date.now }
});
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
const User = mongoose.model('User', userSchema);

// Post Schema/Model
const Post = mongoose.model('Post', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
 images: [{ type: String, required: true }],
  caption: { type: String, default: '' },
  location: {
    name: { type: String },
    coordinates: {
      lat: { type: Number },
      lng: { type: Number }
    }
  },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
}));

// Passport config
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) return done(null, false, { message: 'Utilisateur inconnu.' });
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return done(null, false, { message: 'Mot de passe incorrect.' });
      return done(null, user);
    } catch (err) { return done(err); }
  }
));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try { done(null, await User.findById(id)); }
  catch (err) { done(err); }
});

// Multer (photos)
const { storage } = require('./config/cloudinary'); // adapte le chemin si besoin
const upload = multer({ storage });

// Route pour mettre à jour l'avatar
app.post('/profile/avatar', upload.single('avatar'), async (req, res) => {
  if (!req.isAuthenticated()) {
    req.flash('error', 'Veuillez vous connecter');
    return res.redirect('/login');
  }
  if (!req.file) {
    req.flash('error', 'Veuillez sélectionner une image');
    return res.redirect('/profile');
  }
  // Met à jour l'avatar de l'utilisateur connecté
  req.user.avatar = req.file.path; // URL Cloudinary
  await req.user.save();
  req.flash('success', 'Avatar mis à jour !');
  res.redirect('/profile');
});

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/spoongram' }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});

// EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
const uploadRoutes = require('./public/upload');
app.use('/', uploadRoutes);
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) fs.mkdirSync(viewsDir);

// ROUTES

// Accueil
app.get('/', async (req, res) => {
  const posts = await Post.find().populate('userId').sort({ createdAt: -1 });
  res.render('index', { posts });
});

// Login/Register/Logout
app.get('/login', (req, res) => res.render('login'));
app.post('/login', passport.authenticate('local', {
  successRedirect: '/', failureRedirect: '/login', failureFlash: true
}));
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (await User.findOne({ username })) {
      req.flash('error', 'Ce nom d\'utilisateur est déjà pris');
      return res.redirect('/register');
    }
    const user = new User({ username, password });
    await user.save();
    req.login(user, (err) => {
      if (err) return next(err);
      req.flash('success', 'Inscription réussie !');
      res.redirect('/');
    });
  } catch (e) {
    req.flash('error', 'Erreur lors de l\'inscription');
    res.redirect('/register');
  }
});
app.get('/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) return next(err);
    req.flash('success', 'Vous avez été déconnecté');
    res.redirect('/');
  });
});

// Nouveau post
app.post('/post', upload.array('images', 10), async (req, res) => {
  if (!req.isAuthenticated()) {
    req.flash('error', 'Veuillez vous connecter');
    return res.redirect('/login');
  }
  if (!req.files || req.files.length === 0) {
    req.flash('error', 'Veuillez sélectionner au moins une image');
    return res.redirect('/');
  }
const images = req.files.map(file => file.path);
  const newPost = new Post({
    userId: req.user._id,
    images: images,
    caption: req.body.caption,
    location: {
      name: req.body.locationName,
      coordinates: {
        lat: req.body.lat ? parseFloat(req.body.lat) : undefined,
        lng: req.body.lng ? parseFloat(req.body.lng) : undefined
      }
    }
  });
  await newPost.save();
  req.flash('success', 'Photo publiée avec succès !');
  res.redirect('/');
});

// Affichage d'un post
app.get('/post/:id', async (req, res) => {
  const post = await Post.findById(req.params.id).populate('userId').populate('comments.userId');
  if (!post) {
    req.flash('error', 'Post non trouvé');
    return res.redirect('/');
  }
  res.render('post', { post });
});

// Edition d'un post (formulaire)
app.get('/post/:id/edit', async (req, res) => {
  const post = await Post.findById(req.params.id).populate('userId');
  if (!post) {
    req.flash('error', 'Post non trouvé');
    return res.redirect('/');
  }
  if (!req.user || !post.userId.equals(req.user._id)) {
    req.flash('error', "Vous n'avez pas le droit de modifier ce post.");
    return res.redirect('/');
  }
  res.render('edit', { post });
});

// Edition d'un post (soumission)
app.post('/post/:id/edit', upload.array('images', 10), async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) {
    req.flash('error', 'Post non trouvé');
    return res.redirect('/');
  }
  if (!req.user || !post.userId.equals(req.user._id)) {
    req.flash('error', "Vous n'avez pas le droit de modifier ce post.");
    return res.redirect('/');
  }

  post.caption = req.body.caption;
  post.location.name = req.body.locationName;

  // Si de nouvelles images sont uploadées, on remplace les anciennes
  if (req.files && req.files.length > 0) {
    post.images = req.files.map(file => '/uploads/' + file.filename);
  }
  // Sinon, on garde les images actuelles

  await post.save();
  req.flash('success', 'Post modifié !');
  res.redirect(`/post/${post._id}`);
});

// Suppression d'un post
app.post('/post/:id/delete', async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) {
    req.flash('error', 'Post non trouvé');
    return res.redirect('/');
  }
  if (!req.user || !post.userId.equals(req.user._id)) {
    req.flash('error', "Vous n'avez pas le droit de supprimer ce post.");
    return res.redirect('/');
  }
  await Post.deleteOne({ _id: req.params.id });
  req.flash('success', 'Post supprimé !');
  res.redirect('/');
});

// Like
app.post('/like/:id', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non authentifié' });
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  const userId = req.user._id;
  const likeIndex = post.likes.findIndex(like => like.equals(userId));
  if (likeIndex === -1) post.likes.push(userId);
  else post.likes.splice(likeIndex, 1);
  await post.save();
  res.json({ likes: post.likes.length, liked: likeIndex === -1 });
});

// Commentaire
app.post('/comment/:id', async (req, res) => {
  if (!req.isAuthenticated()) {
    req.flash('error', 'Veuillez vous connecter');
    return res.redirect('/login');
  }
  const post = await Post.findById(req.params.id);
  if (!post) {
    req.flash('error', 'Post non trouvé');
    return res.redirect('/');
  }
  post.comments.push({
    userId: req.user._id,
    text: req.body.comment
  });
  await post.save();
  req.flash('success', 'Commentaire ajouté');
  res.redirect(`/post/${post._id}`);
});

// Carte des cuillères (amélioration possible)
app.get('/map', async (req, res) => {
  const posts = await Post.find({ 'location.name': { $exists: true, $ne: "" } }).populate('userId');
  res.render('map', {
    posts: JSON.stringify(posts),
    mapboxToken: process.env.MAPBOX_TOKEN || 'your-mapbox-token'
  });
});

// Profil utilisateur
app.get('/profile', async (req, res) => {
  if (!req.isAuthenticated()) {
    req.flash('error', 'Veuillez vous connecter');
    return res.redirect('/login');
  }
  const posts = await Post.find({ userId: req.user._id }).sort({ createdAt: -1 });
  res.render('profile', { user: req.user, posts });
});

// Génération des templates de base si absents (pour première utilisation)
const ejsTemplates = {
  // (voir plus bas pour chaque fichier EJS)
};

// Création auto des fichiers EJS si absents
Object.entries(ejsTemplates).forEach(([filename, content]) => {
  const filePath = path.join(viewsDir, filename);
  if (!fs.existsSync(filePath)) fs.writeFileSync(filePath, content.trim());
});
['public','public/uploads','public/images','views'].forEach(dir => {
  if (!fs.existsSync(path.join(__dirname, dir))) fs.mkdirSync(path.join(__dirname, dir), { recursive: true });
});
// Configuration du projet (remplace le pseudo-JSON)
const projectConfig = {
  name: "spoongram",
  version: "1.0.0",
  main: "app.js",
  scripts: {
    start: "node app.js",
    dev: "nodemon app.js"  // Ajout utile pour le développement
  },
  dependencies: {
    express: "^4.18.0",
    ejs: "^3.1.8",
    mongoose: "^6.0.0",    // Ajout des dépendances déjà utilisées
    bcryptjs: "^2.4.3",
    multer: "^1.4.4",
    "connect-flash": "^0.1.1",
    passport: "^0.6.0",
    "passport-local": "^1.0.0",
    dotenv: "^16.0.0",
    "express-session": "^1.17.2",
    "connect-mongo": "^4.6.0"
  }
};

// Fonction utilitaire pour afficher la config (optionnel)
function logProjectConfig() {
  console.log(`Configuration du projet ${projectConfig.name} v${projectConfig.version}`);
  console.log(`Dépendances principales: ${Object.keys(projectConfig.dependencies).join(', ')}`);
}


const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
