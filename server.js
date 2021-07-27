const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const flash = require('express-flash');
const methodOverride = require('method-override');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

function initialize(passport, getUserByEmail, getUserById) {
    const authenticateUser = async (email, password, done) => {
        const user = getUserByEmail(email);
        if (!user) {
            return done(null, false, { message: 'No user with that email' })
        }

        try {
            const match = bcrypt.compare(password, user.password);
            if (match) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Password incorrect' });
            }
        } catch (error) {
            return done(error);
        }
    }
    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
    passport.serializeUser((user, done) => done(null, user.id));
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id))
    });
}

initialize(
    passport, 
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
)
// Mock database
const users = [];

const app = express();

// Middleware and app settings
app.set('view-engine', 'ejs');
app.set('trust proxy', 1); // trust first proxy
app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: "thisismysecrctekeyfhrgfgrfrty84fwir767",
    saveUninitialized: true,
    resave: false,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: 'Hung Thinh' })
});

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs', { message: 'Register page' })
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(req.body.password, saltRounds);
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: passwordHash,
        });
        return res.redirect('/login');
    } catch (error) {
        return res.redirect('/register');
    }
});

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs', { message: 'Login page' });
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

app.delete('/logout', (req, res) => {
    req.logOut();
    res.redirect('/login');
});

function checkAuthenticated(req, res, next) {
    // if user is authenticated, go to home page
    // else go back to login page
    if (req.isAuthenticated()) {
        return next();
    }
    return res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
    // if user is authencicated, go to home page
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    return next();
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[server:] Server is running on PORT ${PORT}`)
});

