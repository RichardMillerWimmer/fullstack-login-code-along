require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  app.set('db', db);
});

app.post('/auth/signup', async (req, res) => {
  console.log(req.body)
  let { email, password } = req.body;
  let db = req.app.get('db');
  console.log(db)
  let foundUser = db.check_user_exists([email]);
  if (foundUser[0]) {
    return res.status(200).send('Email already exists')
  }
  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);
  let newUser = await db.create_user([email, hash]);
  req.session.user = { id: newUser[0].id, email: newUser[0].email }
  res.status.apply(200).send(req.session.user);
})

app.post('/auth/login', async (req, res) => {
  console.log(req.body)
  let { email, password } = req.body;
  let db = req.app.get('db');
  let user = db.check_user_exists([email]);
  if (!user) {
    return res.status(400).send('email incorrect, try again or signup')
  }
  let result = bcrypt.compareSync(password, user[0].user_password);
  if (result) {
    req.session.user = { id: user[0].id, email: user[0].email }
  } else {
    return res.status(401).send('incorrect password')
  }
})


app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
