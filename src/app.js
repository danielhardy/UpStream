var express = require("express"),
  bodyParser = require("body-parser"),
  mongoose = require("mongoose"),
  flash = require("connect-flash"),
  passport = require("passport"),
  morgan = require("morgan"),
  cookieParser = require("cookie-parser"),
  session = require("express-session"),
  mongoStore = require("connect-mongo")(session);

var app = express();
const port = 8080;

// Configure Passport;
require("../config/passport_config.js")(passport);

// Configure Jade
app.set("view engine", "pug");
app.set("views", __dirname + "../views");
app.use(express.static(__dirname + "/public"));

// set up our express application
app.use(morgan("dev")); // log every request to the console
app.use(cookieParser()); // read cookies (needed for auth)
app.use(bodyParser.json()); // get information from html forms
app.use(bodyParser.urlencoded({ extended: true }));

// required for passport
//app.use(session({ secret: 'FoSheezyWizzlePizzle' })); // session secret
app.use(
  session({
    secret: "FoSheezyWizzlePizzle",
    maxAge: Date(Date.now() + 42300),
    store: new mongoStore({ mongooseConnection: mongoose.connection }, function(
      err
    ) {
      console.log(err || "connect-mongodb setup ok");
    })
  })
);

app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

app.get("/", function(req, res) {
  res.render("index", { title: "Hey there!", message: "Hello there!" });
});

/*
 *Import additional routes
 */

require("../routes/user.js")(app, passport, isLoggedIn);

/*
 * Middle ware to manage logged in state;
 */
// Route middleware to ensure user is logged in
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();

  req.flash("error_messages", "You must be logged in to view that content.");
  res.redirect("/login");
}

app.listen(port, () => console.log(`App listening on port ${port}!`));
