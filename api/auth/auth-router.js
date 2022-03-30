const router = require("express").Router();
const Users = require('../users/users-model');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, (req, res, next) => {

  const hash = bcrypt.hashSync(req.body.password, 8);
  req.body.password = hash;
  console.log('hash: ', hash);
  Users.add(req.body)
  .then(resp => {
    Users.findBy({ username: req.body.username })
    .then(resp => {
      const returnUser = {
        user_id: resp[0].user_id,
        username: resp[0].username,
        role_name: resp[0].role_name
      }
      res.status(201).json(returnUser);
    })
    .catch(error => {
      next(error);
    })
  })
  .catch(error => {
    next(error);
  })
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  if( bcrypt.compareSync(req.body.password, req.user.password)){
    const token = buildToken(req.user)
    res.json({
      message: `${req.user.username} is back!`,
      token
    })
  }else{
    next({status: 401, message: 'Invalid credentials'})
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function buildToken(user){
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username
  }
  const options = {
    expiresIn: '1d'
  }

  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
