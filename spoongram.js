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
mongoose.connect(process.env.MONGODB_URI);
mongoose.connection.on('connected', () => console.log('Connected to MongoDB'));

// User Schema/Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '/images/default-avatar.jpg' },
  createdAt: { type: Date, default: Date.now },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  banned: { type: Boolean, default: false }
});
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
const User = mongoose.model('User', userSchema);

// Création du compte admin à l'initialisation (Pavel / 123456789)
(async () => {
  const admin = await User.findOne({ username: "Pavel" });
  if (!admin) {
    const password = await bcrypt.hash('123456789', 12);
    await User.create({
      username: "Pavel",
      password,
      role: "admin",
      banned: false
    });
    console.log("Compte admin Pavel créé !");
  }
})();


// Comment Schema (threaded)
const commentSchema = new mongoose.Schema({
  _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  parentId: { type: mongoose.Schema.Types.ObjectId, default: null }
});

// Post Schema/Model
const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  images: [{ type: String, required: true }],
  videos: [{ type: String }], // <--- ajoute cette ligne
  caption: { type: String, default: '' },
  location: {
    name: { type: String },
    coordinates: {
      lat: { type: Number },
      lng: { type: Number }
    }
  },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [commentSchema],
  views: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

// Album Schema/Model
const albumSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String },
  posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
  createdAt: { type: Date, default: Date.now }
});
const Album = mongoose.model('Album', albumSchema);

// Passport config
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) return done(null, false, { message: 'Utilisateur inconnu.' });
      if (user.banned) return done(null, false, { message: 'Compte banni.' });
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
const { storage } = require('./config/cloudinary');
const upload = multer({ storage });

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
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) fs.mkdirSync(viewsDir);

// Fonction utilitaire pour transformer hashtags et mentions en liens cliquables
function formatCaption(text) {
  if (!text) return '';
  // Hashtags
  text = text.replace(/#([a-zA-Z0-9_]+)/g, '<a href="/hashtag/$1" class="hashtag">#$1</a>');
  // Mentions
  text = text.replace(/@([a-zA-Z0-9_]+)/g, '<a href="/user/by-username/$1" class="mention">@$1</a>');
  return text;
}
app.locals.formatCaption = formatCaption;

// Middleware admin/modérateur
function isAdmin(req, res, next) {
  if (req.user && (req.user.role === "admin" || req.user.role === "moderator")) return next();
  req.flash('error', "Accès réservé aux administrateurs/modérateurs");
  res.redirect('/');
}

// ROUTES

// Gestion comptes - voir tous les users (admin/modo)
app.get('/admin/users', isAdmin, async (req, res) => {
  const users = await User.find();
  res.render('admin_users', { users, currentUser: req.user });
});

// Ban/unban
app.post('/admin/ban/:id', isAdmin, async (req, res) => {
  if (req.user._id.toString() === req.params.id) {
    req.flash('error', "Vous ne pouvez pas bannir votre propre compte !");
    return res.redirect('/admin/users');
  }
  const user = await User.findById(req.params.id);
  if (user) {
    user.banned = true;
    await user.save();
    req.flash('success', "Utilisateur banni !");
  }
  res.redirect('/admin/users');
});
app.post('/admin/unban/:id', isAdmin, async (req, res) => {
  const user = await User.findById(req.params.id);
  if (user) {
    user.banned = false;
    await user.save();
    req.flash('success', "Utilisateur débanni !");
  }
  res.redirect('/admin/users');
});

// Route pour mettre à jour l'avatar (doit être APRES les middlewares)
app.post('/profile/avatar', upload.single('avatar'), async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      req.flash('error', 'Veuillez vous connecter');
      return res.redirect('/login');
    }
    if (!req.file) {
      req.flash('error', 'Veuillez sélectionner une image');
      return res.redirect('/profile');
    }
    req.user.avatar = req.file.path;
    await req.user.save();
    req.flash('success', 'Avatar mis à jour !');
    res.redirect('/profile');
  } catch (e) {
    console.error(e);
    res.status(500).send(e.message);
  }
});

// Accueil
app.get('/', async (req, res) => {
  const posts = await Post.find().populate('userId').sort({ createdAt: -1 });
  res.render('index', { posts });
});

// Flux personnalisé : posts des gens suivis
app.get('/feed', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  const user = await User.findById(req.user._id);
  const posts = await Post.find({ userId: { $in: user.following } }).populate('userId').sort({ createdAt: -1 });
  res.render('feed', { posts });
});

// Voir le profil d'un autre utilisateur
app.get('/user/:id', async (req, res) => {
  const user = await User.findById(req.params.id).populate('followers').populate('following');
  if (!user) return res.redirect('/');
  const posts = await Post.find({ userId: user._id }).sort({ createdAt: -1 });
  res.render('user', { user, posts, currentUser: req.user });
});

// Suivre un utilisateur
app.post('/follow/:id', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  if (req.user._id.equals(req.params.id)) return res.redirect('/profile');
  const userToFollow = await User.findById(req.params.id);
  if (!userToFollow) return res.redirect('/');
  if (!userToFollow.followers.some(f => f.equals(req.user._id))) {
    userToFollow.followers.push(req.user._id);
    req.user.following.push(userToFollow._id);
    await userToFollow.save();
    await req.user.save();
  }
  res.redirect('/user/' + userToFollow._id);
});

// Se désabonner
app.post('/unfollow/:id', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  if (req.user._id.equals(req.params.id)) return res.redirect('/profile');
  const userToUnfollow = await User.findById(req.params.id);
  if (!userToUnfollow) return res.redirect('/');
  userToUnfollow.followers = userToUnfollow.followers.filter(f => !f.equals(req.user._id));
  req.user.following = req.user.following.filter(f => !f.equals(userToUnfollow._id));
  await userToUnfollow.save();
  await req.user.save();
  res.redirect('/user/' + userToUnfollow._id);
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
  const post = await Post.findById(req.params.id)
    .populate('userId')
    .populate('comments.userId');
  if (!post) {
    req.flash('error', 'Post non trouvé');
    return res.redirect('/');
  }
  // Incrémenter le compteur de vues
  post.views = (post.views || 0) + 1;
  await post.save();
  res.render('post', { post, currentUser: req.user, request: req });
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

// Commentaire enrichi (threadé)
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
  const parentId = req.body.parentId || null;
  post.comments.push({
    userId: req.user._id,
    text: req.body.comment,
    parentId: parentId
  });
  await post.save();
  req.flash('success', 'Commentaire ajouté');
  res.redirect(`/post/${post._id}`);
});

// Carte avec filtres
app.get('/map', async (req, res) => {
  let { user, lieu, minlikes } = req.query;
  let query = { 'location.name': { $exists: true, $ne: "" } };

  if (user) {
    const users = await User.find({ username: { $regex: user, $options: 'i' } });
    if (users.length > 0) query.userId = { $in: users.map(u => u._id) };
    else query.userId = null; // aucun résultat
  }
  if (lieu) {
    query['location.name'] = { $regex: lieu, $options: 'i' };
  }
  if (minlikes) {
    // Filtrage par nombre de likes (en JS après récupération)
    let posts = await Post.find(query).populate('userId');
    posts = posts.filter(p => (p.likes?.length || 0) >= parseInt(minlikes));
    return res.render('map', {
      posts: JSON.stringify(posts),
      mapboxToken: process.env.MAPBOX_TOKEN || 'your-mapbox-token'
    });
  }

  let posts = await Post.find(query).populate('userId');
  res.render('map', {
    posts: JSON.stringify(posts),
    mapboxToken: process.env.MAPBOX_TOKEN || 'your-mapbox-token'
  });
});

// Profil utilisateur (profil connecté)
app.get('/profile', async (req, res) => {
  if (!req.isAuthenticated()) {
    req.flash('error', 'Veuillez vous connecter');
    return res.redirect('/login');
  }
  const user = await User.findById(req.user._id).populate('followers').populate('following');
  const posts = await Post.find({ userId: req.user._id }).sort({ createdAt: -1 }).populate('comments.userId');

  // Statistiques pour courbe activité
  const now = new Date();
  let statsByMonth = {};
  let likesByMonth = {};
  posts.forEach(post => {
    const d = new Date(post.createdAt);
    const month = d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2, '0');
    statsByMonth[month] = (statsByMonth[month] || 0) + 1;
    likesByMonth[month] = (likesByMonth[month] || 0) + (post.likes ? post.likes.length : 0);
  });

  res.render('profile', { user, posts, statsByMonth, likesByMonth });
});

// Page d’un hashtag
app.get('/hashtag/:tag', async (req, res) => {
  const tag = req.params.tag;
  // On cherche les posts contenant ce hashtag
  const regex = new RegExp(`#${tag}(\\b|\\W)`, "i");
  const posts = await Post.find({ caption: { $regex: regex } }).populate('userId').sort({ createdAt: -1 });
  res.render('hashtag', { tag, posts });
});

// Accès au profil via @username
app.get('/user/by-username/:username', async (req, res) => {
  const user = await User.findOne({ username: req.params.username }).populate('followers').populate('following');
  if (!user) return res.redirect('/');
  const posts = await Post.find({ userId: user._id }).sort({ createdAt: -1 });
  res.render('user', { user, posts, currentUser: req.user });
});

// Génération des templates de base si absents (pour première utilisation)
const ejsTemplates = {
  // (voir plus bas pour chaque fichier EJS)
  // Ajoute ici le template admin_users.ejs si tu veux qu'il soit généré automatiquement
  "admin_users.ejs": `
<%- include('partials/header') %>
<h2>Gestion des utilisateurs</h2>
<table style="width:100%;border-collapse:collapse">
  <tr>
    <th>Nom</th>
    <th>Rôle</th>
    <th>Banni ?</th>
    <th>Actions</th>
  </tr>
  <% users.forEach(u => { %>
    <tr style="<%= u.banned ? 'background:#ffeaea;' : '' %>">
      <td><%= u.username %></td>
      <td><%= u.role %></td>
      <td><%= u.banned ? 'Oui' : 'Non' %></td>
      <td>
        <% if (!u.banned && u._id.toString() !== currentUser._id.toString()) { %>
          <form action="/admin/ban/<%= u._id %>" method="POST" style="display:inline;">
            <button type="submit" style="color:#c00;">Ban</button>
          </form>
        <% } %>
        <% if (u.banned) { %>
          <form action="/admin/unban/<%= u._id %>" method="POST" style="display:inline;">
            <button type="submit" style="color:#080;">Unban</button>
          </form>
        <% } %>
      </td>
    </tr>
  <% }) %>
</table>
<%- include('partials/footer') %>
`
};

Object.entries(ejsTemplates).forEach(([filename, content]) => {
  const filePath = path.join(viewsDir, filename);
  if (!fs.existsSync(filePath)) fs.writeFileSync(filePath, content.trim());
});
['public','public/uploads','public/images','views'].forEach(dir => {
  if (!fs.existsSync(path.join(__dirname, dir))) fs.mkdirSync(path.join(__dirname, dir), { recursive: true });
});

// Albums
app.post('/albums/new', async (req, res) => {
  if (!req.isAuthenticated()) {
    req.flash('error', 'Veuillez vous connecter');
    return res.redirect('/login');
  }
  const { title, description } = req.body;
  const album = new Album({ userId: req.user._id, title, description });
  await album.save();
  req.flash('success', 'Album créé !');
  res.redirect('/albums');
});

app.get('/albums', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  const albums = await Album.find({ userId: req.user._id }).sort({ createdAt: -1 });
  res.render('albums', { albums });
});

app.get('/album/:id', async (req, res) => {
  const album = await Album.findById(req.params.id).populate({
    path: 'posts',
    populate: { path: 'userId' }
  });
  if (!album) return res.redirect('/albums');
  if (!req.user || !album.userId.equals(req.user._id)) {
    req.flash('error', "Vous n'avez pas accès à cet album.");
    return res.redirect('/albums');
  }
  // Récupère les posts de l'utilisateur non déjà dans cet album pour l'ajout
  const userPosts = await Post.find({ userId: req.user._id, _id: { $nin: album.posts } });
  res.render('album', { album, userPosts });
});

app.post('/album/:id/add-post', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  const album = await Album.findById(req.params.id);
  if (!album || !album.userId.equals(req.user._id)) return res.redirect('/albums');
  const { postId } = req.body;
  if (!album.posts.includes(postId)) {
    album.posts.push(postId);
    await album.save();
  }
  res.redirect('/album/' + album._id);
});

app.post('/album/:id/remove-post', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  const album = await Album.findById(req.params.id);
  if (!album || !album.userId.equals(req.user._id)) return res.redirect('/albums');
  const { postId } = req.body;
  album.posts = album.posts.filter(p => p.toString() !== postId);
  await album.save();
  res.redirect('/album/' + album._id);
});
app.post('/album/:id/delete', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  const album = await Album.findById(req.params.id);
  if (!album || !album.userId.equals(req.user._id)) {
    req.flash('error', "Vous n'avez pas le droit de supprimer cet album.");
    return res.redirect('/albums');
  }
  await Album.deleteOne({ _id: req.params.id });
  req.flash('success', "Album supprimé !");
  res.redirect('/albums');
});
app.get('/album/:id/edit', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  const album = await Album.findById(req.params.id);
  if (!album || !album.userId.equals(req.user._id)) {
    req.flash('error', "Vous n'avez pas le droit de modifier cet album.");
    return res.redirect('/albums');
  }
  res.render('edit_album', { album });
});
app.post('/album/:id/edit', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  const album = await Album.findById(req.params.id);
  if (!album || !album.userId.equals(req.user._id)) {
    req.flash('error', "Vous n'avez pas le droit de modifier cet album.");
    return res.redirect('/albums');
  }
  album.title = req.body.title;
  album.description = req.body.description;
  await album.save();
  req.flash('success', "Album modifié !");
  res.redirect('/album/' + album._id);
});

// Recherche globale (barre de recherche)
app.get('/search', async (req, res) => {
  const q = req.query.q || "";
  let posts = [];
  const hashtagRegex = /#(\w+)/g;
  let hashtags = [];
  let query = {};

  // Recherche par hashtag
  if (q.match(hashtagRegex)) {
    hashtags = [...q.matchAll(hashtagRegex)].map(m => m[1].toLowerCase());
    query.caption = { $regex: hashtags.map(h => `#${h}`).join('|'), $options: 'i' };
  } else if (q.startsWith("@")) {
    // Recherche par nom d'utilisateur (ex: @toto)
    const username = q.replace(/^@/, '');
    const user = await User.findOne({ username: new RegExp("^" + username + "$", "i") });
    if (user) query.userId = user._id;
    else query = { _id: null }; // Aucun résultat si user inconnu
  } else if (q) {
    // Recherche générale : lieu, légende, pseudo
    query.$or = [
      { caption: { $regex: q, $options: 'i' } },
      { "location.name": { $regex: q, $options: 'i' } }
    ];
    // Ajout recherche par pseudo
    const users = await User.find({ username: { $regex: q, $options: 'i' } });
    if (users.length > 0) query.$or.push({ userId: { $in: users.map(u => u._id) } });
  }

  posts = await Post.find(query).populate('userId').sort({ createdAt: -1 });

  res.render('search', { posts, q });
});
const QRCode = require('qrcode');

// Route pour générer un QR code de la localisation d’un post
app.get('/post/:id/qrcode', async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || !post.location || !post.location.coordinates) return res.status(404).send('Post ou localisation introuvable');
  const loc = post.location;
  const mapUrl = `https://www.google.com/maps/search/?api=1&query=${loc.coordinates.lat},${loc.coordinates.lng}`;
  QRCode.toDataURL(mapUrl, { width: 300 }, (err, url) => {
    if (err) return res.status(500).send('Erreur QR code');
    res.type('html').send(`<img src="${url}" alt="QR code localisation"><br><a href="${mapUrl}" target="_blank">Voir sur Google Maps</a>`);
  });
});

function logProjectConfig() {
  // (optionnel, pour debug)
  const projectConfig = {
    name: "spoongram",
    version: "1.0.0",
    dependencies: {
      express: "^4.18.0",
      ejs: "^3.1.8",
      mongoose: "^6.0.0",
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
  console.log(`Configuration du projet ${projectConfig.name} v${projectConfig.version}`);
  console.log(`Dépendances principales: ${Object.keys(projectConfig.dependencies).join(', ')}`);
}

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
