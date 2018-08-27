const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { secretOrKey } = require("../../config/keys");

//Load model
const User = require("../../models/User");

// @route   GET api/users/test
// @desc    Test users route
// @access  Public
router.get("/test", (req, res) => res.json({ msg: "User Works!" }));

let getAvatar = email => {
  const avatar = gravatar.url(email, {
    s: "200", // Size
    r: "pg", // Rating
    d: "mm" // Default
  });
  return avatar;
};

let getUser = async email => {
  const user = await User.findOne({ email });
  return user;
};

// let saveUser = async user => {
//   const result = await user.save();
//   return result;
// };

let encryptPassword = (user, res) => {
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) throw err;
      user.password = hash;
      user
        .save()
        .then(user => res.json(user))
        .catch(err => console.log(err));
    });
  });
};

let register = async (req, res) => {
  const { name, email, password } = req.body;
  const user = await getUser(email);
  if (user) {
    return res.status(400).json({ email: "Email already exists" });
  }
  const avatar = getAvatar(email);
  const newUser = new User({
    name,
    email,
    avatar,
    password
  });
  encryptPassword(newUser, res);
};

let doesPasswordMatch = async (password, userPassword) => {
  let isMatch = await bcrypt.compare(password, userPassword);
  return isMatch;
};

let login = async (req, res) => {
  const { email, password } = req.body;
  const user = await getUser(email);
  if (!user) {
    return res.status(404).json({ email: "User not found" });
  }
  //Check password
  let isMatch = await doesPasswordMatch(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ password: "Password incorrect" });
  }
  //Create JWT payload
  const { id, name, avatar } = user;
  const payload = { id, name, avatar };
  jwt.sign(payload, secretOrKey, { expiresIn: 1200 }, (err, token) => {
    return res.json({
      success: true,
      token: `Bearer ${token}`
    });
  });
};

// @route   POST api/users/register
// @desc    Register user
// @access  Public
router.post("/register", (req, res) => {
  register(req, res);
});

// @route   POST api/users/login
// @desc    Login user / Return JWT
// @access  Public
router.post("/login", (req, res) => {
  login(req, res);
});

module.exports = router;
