//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const passport = require('passport');
const session = require('express-session');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();


// process env
// console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

// WAJIB PAKE BIAR BISA KELIAT LAGI LOGIN SESSION NYA
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    User.find({"secret": {$ne: null}}, (err, foundUsers) => {
        if(err) {
            console.log(err);
        } else {
            if(foundUsers) {
                res.render("secrets", { userWithSecrets: foundUsers });
            }
        }
    })
});

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            const registerUser = passport.authenticate("local")
            registerUser(req, res, () => {
                res.redirect("/secrets");
            });
        }
    })
});

app.post("/login", (req, res) => {
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            const loginUser = passport.authenticate("local");
            loginUser(req, res, () => {
                res.redirect("/secrets");
            })
        }
    })

});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.render("login");
    }
});

app.post("/submit", (req, res) => {
   const submittedSecret = req.body.secret;
   console.log(req.user.id);

   User.findById(req.user.id, (err, foundUser) => {
       if(err) {
           console.log(err);
       } else {
           if(foundUser) {
               foundUser.secret = submittedSecret;
               foundUser.save(() => {
                   res.redirect("/secrets");
               })
           }
       }
   });
});

app.listen(3000, () => {
    console.log("Server started at port 3000");
})


// NOTES
/*
    AUTHENTICATED COOKIES WILL DISAPPEAR WHEN
    WE RESTART THE SERVER ON NODEMON
*/