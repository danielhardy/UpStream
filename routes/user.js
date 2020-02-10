var async = require("async");
var nodemailer = require("nodemailer");
var sg = require("nodemailer-sendgrid-transport");
var crypto = require("crypto");
var User = require("../models/users_model.js");
var nodemailer_config = require("../config/nodemailer_config.js");

var nodemailerTransport = nodemailer.createTransport(
  sg({
    auth: {
      api_key: nodemailer_config.key
    }
  })
);

module.exports = function(app, passport) {
  // normal routes ===============================================================

  // PROFILE SECTION =========================
  app.get("/profile", isLoggedIn, function(req, res) {
    //Fetch the count of subscirptions
    Subscription.count({ user: req.user._id }, function(err, count) {
      if (err) throw err;

      res.render("users/profile", {
        user: req.user,
        count: count
      });
    });
  });

  // LOGOUT ==============================
  app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
  });

  // FORGOT
  app.get("/forgot", function(req, res) {
    res.render("users/forgot");
  });

  app.post("/forgot", function(req, res, next) {
    async.waterfall(
      [
        function(done) {
          console.log("creating token");
          crypto.randomBytes(20, function(err, buf) {
            var token = buf.toString("hex");
            done(err, token);
          });
        },
        function(token, done) {
          console.log("Looking up user.");
          User.findOne({ "local.email": req.body.email }, function(err, user) {
            if (err) throw err;
            if (!user) {
              req.flash(
                "error_messages",
                "No account with that email address exists."
              );
              return res.redirect("/forgot");
            }

            user.resetPasswordToken = token;
            user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

            user.save(function(err) {
              console.log("Finished reseting");
              done(err, token, user);
            });
          });
        },
        function(token, user, done) {
          console.log("Preparing to send email to " + user.local.email);

          var mailOptions = {
            to: user.local.email,
            from: app.locals.productName + " <hello@" + app.locals.domain + ">",
            subject: app.locals.productName + " Password Reset",
            text:
              "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
              "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
              "http://" +
              req.headers.host +
              "/reset/" +
              token +
              "\n\n" +
              "If you did not request this, please ignore this email and your password will remain unchanged.\n"
          };
          nodemailerTransport.sendMail(mailOptions, function(err, info) {
            if (err) {
              console.log(err + " - " + info);
            } else {
              console.log("Sent Email: " + info);
              req.flash(
                "success_messages",
                "An e-mail has been sent to " +
                  user.local.email +
                  " with further instructions."
              );
              done(err, "done");
            }
          });
        }
      ],
      function(err) {
        if (err) return next(err);
        res.redirect("/forgot");
      }
    );
  });

  app.get("/reset/:token", function(req, res) {
    User.findOne(
      {
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
      },
      function(err, user) {
        if (!user) {
          req.flash(
            "error_messages",
            "Password reset token is invalid or has expired."
          );
          return res.redirect("/login");
        }
        res.render("users/reset", {
          user: req.user
        });
      }
    );
  });
  app.post("/reset/:token", function(req, res) {
    async.waterfall(
      [
        function(done) {
          User.findOne(
            {
              resetPasswordToken: req.params.token,
              resetPasswordExpires: { $gt: Date.now() }
            },
            function(err, user) {
              if (!user) {
                req.flash(
                  "error",
                  "Password reset token is invalid or has expired."
                );
                return res.redirect("back");
              }

              user.local.password = user.generateHash(req.body.password);
              user.resetPasswordToken = undefined;
              user.resetPasswordExpires = undefined;

              user.save(function(err) {
                req.logIn(user, function(err) {
                  done(err, user);
                });
              });
            }
          );
        },
        function(user, done) {
          var mailOptions = {
            to: user.local.email,
            from: app.locals.productName + " <hello@" + app.locals.domain + ">",
            subject: "Your password has been changed",
            text:
              "Hello,\n\n" +
              "This is a confirmation that the password for your account " +
              user.local.email +
              " has just been changed.\n"
          };
          nodemailerTransport.sendMail(mailOptions, function(err) {
            req.flash(
              "success_messages",
              "Success! Your password has been changed."
            );
            done(err);
          });
        }
      ],
      function(err) {
        if (err) throw err;
        res.redirect("/login");
      }
    );
  });

  // =============================================================================
  // CHANGE PASSWORD USING RESET =================================================
  // =============================================================================
  app.get("/users/changepassword", function(req, res, next) {
    async.waterfall(
      [
        function(done) {
          console.log("creating token");
          crypto.randomBytes(20, function(err, buf) {
            var token = buf.toString("hex");
            done(err, token);
          });
        },
        function(token, done) {
          console.log("Looking up user.");
          console.log("Session: " + req.user);
          User.findOne({ "local.email": req.user.local.email }, function(
            err,
            user
          ) {
            if (err) throw err;
            if (!user) {
              req.flash(
                "error_messages",
                "No account with that email address exists."
              );
              return res.redirect("/login");
            }

            user.resetPasswordToken = token;
            user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

            user.save(function(err) {
              console.log("Finished reseting");
              done(err, token, user);
            });
          });
        },
        function(token, user, done) {
          //Redirect to reset page;
          var redirectLocation =
            "http://" + req.headers.host + "/reset/" + token;
          return res.redirect(redirectLocation);
          done("done");
        }
      ],
      function(err) {
        if (err) return next(err);
        res.redirect("/login");
      }
    );
  });
  // =============================================================================
  // AUTHENTICATE (FIRST LOGIN) ==================================================
  // =============================================================================

  // locally --------------------------------
  // LOGIN ===============================
  // show the login form
  app.get("/login", function(req, res) {
    res.render("users/login");
  });

  // process the login form
  app.post(
    "/login",
    passport.authenticate("local-login", {
      successRedirect: "/subscriptions", // redirect to the secure subscriptions section
      failureRedirect: "/login", // redirect back to the signup page if there is an error
      failureFlash: true // allow flash messages
    })
  );

  // SIGNUP =================================
  // show the signup form
  app.get("/signup", function(req, res) {
    res.render("users/signup");
  });

  // process the signup form
  app.post(
    "/signup",
    passport.authenticate("local-signup", {
      successRedirect: "/subscriptions", // redirect to the secure subscriptions section
      failureRedirect: "/signup", // redirect back to the signup page if there is an error
      failureFlash: true // allow flash messages
    })
  );

  // facebook -------------------------------

  // send to facebook to do the authentication
  app.get(
    "/auth/facebook",
    passport.authenticate("facebook", { scope: "email" })
  );

  // handle the callback after facebook has authenticated the user
  app.get(
    "/auth/facebook/callback",
    passport.authenticate("facebook", {
      successRedirect: "/profile",
      failureRedirect: "/"
    })
  );

  // twitter --------------------------------

  // send to twitter to do the authentication
  app.get(
    "/auth/twitter",
    passport.authenticate("twitter", { scope: "email" })
  );

  // handle the callback after twitter has authenticated the user
  app.get(
    "/auth/twitter/callback",
    passport.authenticate("twitter", {
      successRedirect: "/profile",
      failureRedirect: "/"
    })
  );

  // google ---------------------------------

  // send to google to do the authentication
  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
  );

  // the callback after google has authenticated the user
  app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
      successRedirect: "/profile",
      failureRedirect: "/"
    })
  );

  // =============================================================================
  // AUTHORIZE (ALREADY LOGGED IN / CONNECTING OTHER SOCIAL ACCOUNT) =============
  // =============================================================================

  // locally --------------------------------
  app.get("/connect/local", function(req, res) {
    res.render("connect-local.ejs");
  });
  app.post(
    "/connect/local",
    passport.authenticate("local-signup", {
      successRedirect: "/profile", // redirect to the secure profile section
      failureRedirect: "/connect/local", // redirect back to the signup page if there is an error
      failureFlash: true // allow flash messages
    })
  );

  // facebook -------------------------------

  // send to facebook to do the authentication
  app.get(
    "/connect/facebook",
    passport.authorize("facebook", { scope: "email" })
  );

  // handle the callback after facebook has authorized the user
  app.get(
    "/connect/facebook/callback",
    passport.authorize("facebook", {
      successRedirect: "/profile",
      failureRedirect: "/"
    })
  );

  // twitter --------------------------------

  // send to twitter to do the authentication
  app.get(
    "/connect/twitter",
    passport.authorize("twitter", { scope: "email" })
  );

  // handle the callback after twitter has authorized the user
  app.get(
    "/connect/twitter/callback",
    passport.authorize("twitter", {
      successRedirect: "/profile",
      failureRedirect: "/"
    })
  );

  // google ---------------------------------

  // send to google to do the authentication
  app.get(
    "/connect/google",
    passport.authorize("google", { scope: ["profile", "email"] })
  );

  // the callback after google has authorized the user
  app.get(
    "/connect/google/callback",
    passport.authorize("google", {
      successRedirect: "/profile",
      failureRedirect: "/"
    })
  );

  // =============================================================================
  // UNLINK ACCOUNTS =============================================================
  // =============================================================================
  // used to unlink accounts. for social accounts, just remove the token
  // for local account, remove email and password
  // user account will stay active in case they want to reconnect in the future

  // local -----------------------------------
  app.get("/unlink/local", isLoggedIn, function(req, res) {
    var user = req.user;
    user.local.email = undefined;
    user.local.password = undefined;
    user.save(function(err) {
      res.redirect("/profile");
    });
  });

  // facebook -------------------------------
  app.get("/unlink/facebook", isLoggedIn, function(req, res) {
    var user = req.user;
    user.facebook.token = undefined;
    user.save(function(err) {
      res.redirect("/profile");
    });
  });

  // twitter --------------------------------
  app.get("/unlink/twitter", isLoggedIn, function(req, res) {
    var user = req.user;
    user.twitter.token = undefined;
    user.save(function(err) {
      res.redirect("/profile");
    });
  });

  // google ---------------------------------
  app.get("/unlink/google", isLoggedIn, function(req, res) {
    var user = req.user;
    user.google.token = undefined;
    user.save(function(err) {
      res.redirect("/profile");
    });
  });
};

// route middleware to ensure user is logged in
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
}
