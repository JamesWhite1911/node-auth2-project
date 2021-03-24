//express
const router = require('express').Router();

//db access
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { findBy, add } = require('../users/users-model')

//token stuff
const { JWT_SECRET } = require('../secrets');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')


// /api/auth/register
router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    //credentials
    const { username, password, role_name } = req.body
    const user = await findBy({ username })

    // save the user to the database
    if (user) {
      return res.status(409).json({ message: "User by that name already exists" })
    }
    const newUser = await add({ username, password: bcrypt.hash(password, 8), role_name })
    res.status(201).json(newUser)

  } catch (err) {
    next(err)
  }
});

// /api/auth/login
router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    //credentials
    const { username, password } = req.body

    //valid user
    const user = await findBy({ username })
    if (!user) {
      return res.status(401).json({ message: "Cannot find a user by that username" })
    }

    //validate passwsord
    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) {
      return res.status(401).json({ message: "Password incorrect" })
    }

    //token
    const token = buildToken(user)
    res.cookie('token', token)

    res.json({ message: `${user.username} is back!`, token: token })

  } catch (err) {
    next(err)
  }
});

//build token
function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const config = {
    expiresIn: '1d',
  }
  return jwt.sign(
    payload, JWT_SECRET, config
  )
}

module.exports = router;
