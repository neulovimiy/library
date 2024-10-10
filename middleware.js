const jwt = require('jsonwebtoken');
const secretKey = process.env.SECRET_KEY;

function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.redirect('/login');
    }
    req.user = user;
    next();
  });
}

function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Доступ запрещен');
  }
  next();
}

module.exports = { authenticateToken, authorizeAdmin };
