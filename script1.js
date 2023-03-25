const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// connect to database
mongoose.connect('mongodb://localhost/auth_challenge', { useNewUrlParser: true });

// create user schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});

// create user model
const User = mongoose.model('User', userSchema);

// use middleware to parse JSON body
app.use(bodyParser.json());

// signup endpoint
app.post('/api/signup', async (req, res) => {
  try {
    // check if user already exists
    const user = await User.findOne({ email: req.body.email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // create new user
    const newUser = new User({
      name: req.body.name,
      email: req.body.email,
      password: await bcrypt.hash(req.body.password, 10)
    });
    await newUser.save();

    // generate JWT
    const token = jwt.sign({ email: newUser.email }, 'secret');

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// login endpoint
app.post('/api/login', async (req, res) => {
  try {
    // find user by email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    // check password
    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    // generate JWT
    const token = jwt.sign({ email: user.email }, 'secret');

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// check-auth endpoint
app.get('/api/check-auth', (req, res) => {
  try {
    // get token from headers
    const token = req.headers.authorization.split(' ')[1];

    // verify token
    const decodedToken = jwt.verify(token, 'secret');

    res.sendStatus(200);
  } catch (err) {
    res.sendStatus(401);
  }
});

// start server
app.listen(3000, () => {
  console.log('Server started');
});
