const LocalStrategy = require("passport-local").Strategy;
const User          = require("../models/user");
const bcrypt        = require("bcrypt");

module.exports = (passport) => {
  passport.use(new LocalStrategy((username, password, next) => {
    User.findOne({ username }, (err, user) => {
      if (err) { return next(err); }
      if (!user) { next(null, false, { message: "Incorrect username" }); }
      if (!bcrypt.compareSync(password, user.password)) { next(null, false, { message: "Incorrect password" });
    }

      return next(null, user);
    });
  }));

  passport.serializeUser((user, cb) => {
    cb(null, user.id);
  });

  passport.deserializeUser((id, cb) => {
    User.findOne({ _id: id }, (err, user) => {
      if (err) { return cb(err); }
      cb(null, user);
    });
  });

  passport.use('local-auth', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
  }, (email, password, next) => {
    User.findOne({ email: email })
      .then(user => {
        if (!user) {
          next(null, user, { password: 'Invalid username or password' });
        } else {
          user.checkPassword(password)
            .then(match => {
              if (match) {
                next(null, user);
              } else {
                next(null, null, { password: 'Invalid username or password' });
              }
            })
            .catch(error => next(error));
        }
      })
      .catch(error => next(error));
  }));
};
