const jwt = require('jsonwebtoken');
const secretKey = process.env.SECRET_KEY;

function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    console.log("Токен отсутствует");
    return res.redirect('/login');
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      console.log("Ошибка проверки токена:", err.message);
      return res.redirect('/login');
    }
    req.user = user;
    console.log("Пользователь успешно аутентифицирован:", req.user);
    next();
  });
}

function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    console.log("Доступ запрещен: пользователь не является администратором");
    return res.status(403).send('Доступ запрещен');
  }
  next();
}

function authorizeLibrarianOrAdmin(req, res, next) {
  if (req.user.role === 'librarian' || req.user.role === 'admin') {
    console.log("Доступ разрешен для роли:", req.user.role);
    return next();
  }
  console.log("Доступ запрещен: роль пользователя не соответствует требуемым правам");
  return res.status(403).send('Доступ запрещен');
}

module.exports = { authenticateToken, authorizeAdmin, authorizeLibrarianOrAdmin };
