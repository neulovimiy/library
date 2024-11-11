const jwt = require('jsonwebtoken');
const secretKey = process.env.SECRET_KEY;

function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    console.log("Токен отсутствует");
    return res.redirect('/login');
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.log("Ошибка проверки токена:", err.message);
      return res.redirect('/login');
    }
    req.user = { userId: decoded.userId, role: decoded.role };
    console.log("Пользователь успешно аутентифицирован:", req.user);
    next();
  });
}

function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    console.log("Доступ запрещен: пользователь не является администратором");
    return res.status(403).json({ message: 'Доступ запрещен' });
  }
  next();
}

function authorizeLibrarianOrAdmin(req, res, next) {
  if (['librarian', 'admin','boss'].includes(req.user.role)) {
    console.log("Доступ разрешен для роли:", req.user.role);
    return next();
  }
  console.log("Доступ запрещен: роль пользователя не соответствует требуемым правам");
  return res.status(403).json({ message: 'Доступ запрещен' });
}

module.exports = { authenticateToken, authorizeAdmin, authorizeLibrarianOrAdmin };
