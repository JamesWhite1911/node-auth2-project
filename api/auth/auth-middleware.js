const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets");
const { findBy } = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization

  if (!token) {
    res.status(401).json({ message: "Token required" })
  } else {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        res.status(401).json({ message: "Token invalid" })
      } else {
        req.decodedJwt = decoded
        next()
      }
    })
  }
}

const only = role_name => (req, res, next) => {
  if (req.decodedJwt.role_name !== role_name) {
    res.status(403).json({ message: "This is not for you" })
  } else {
    next()
  }
}

const checkUsernameExists = async (req, res, next) => {
  const user = await findBy(req.body.username)

  if (!user || user.length === 0) {
    res.status(401).json({ message: "Invalid credentials" })
  } else {
    next()
  }
}

const validateRoleName = (req, res, next) => {
  let roleName = req.body.role_name.trim()

  if (!roleName || roleName.length === 0) {
    req.role_name = 'student'
    next()
  } else if (roleName === 'admin') {
    res.status(422).json({ message: "Role name can not be admin" })
  } else if (roleName.length > 32) {
    res.status(422).json({ message: "Role name can not be longer than 32 chars" })
  } else {
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
