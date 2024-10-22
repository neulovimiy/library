const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const secretKey = process.env.SECRET_KEY;
const logger = require('./logger'); 
module.exports = (app, connection) => {

  // Регистрация пользователя
  app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    logger.info('Данные для регистрации:', req.body);  // Логирование входящих данных

    // Проверка на пустые значения
    if (!name || !email || !password) {
      return res.status(400).send('Все поля обязательны для заполнения');
    }

    try {
      // Хэширование пароля
      const hashedPassword = await bcrypt.hash(password, 10);

      // Добавление нового пользователя в таблицу users
      const query = 'INSERT INTO users (name, email, role) VALUES (?, ?, ?)';
      connection.query(query, [name, email, 'user'], (err, result) => {
        if (err) {
          logger.error('Ошибка при добавлении пользователя в таблицу users:', err);
          return res.status(500).send('Ошибка при регистрации пользователя');
        }

        const userId = result.insertId;

        // Сохранение хэшированного пароля в таблицу user_credentials
        const credentialsQuery = 'INSERT INTO user_credentials (user_id, hashed_password) VALUES (?, ?)';
        connection.query(credentialsQuery, [userId, hashedPassword], (err, result) => {
          if (err) {
            logger.error('Ошибка при добавлении пароля в таблицу user_credentials:', err);
            return res.status(500).send('Ошибка при сохранении пароля');
          }

          logger.info('Пользователь успешно зарегистрирован');
          res.redirect('/');  // После успешной регистрации перенаправляем на страницу логина
        });
      });
    } catch (error) {
      logger.error('Ошибка при регистрации:', error);
      res.status(500).send('Ошибка при регистрации');
    }
  });

  // Логин пользователя
  app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send('Email и пароль обязательны для входа');
    }

    // Поиск пользователя по email
    const query = 'SELECT user_id, role FROM users WHERE email = ?';
    connection.query(query, [email], async (err, results) => {
      if (err) {
        logger.error('Ошибка при поиске пользователя:', err);
        return res.status(500).send('Ошибка при аутентификации');
      }

      if (results.length === 0) {
        return res.status(400).send('Пользователь не найден');
      }

      const user = results[0];
      const userId = user.user_id;

      // Поиск пароля пользователя
      const credentialsQuery = 'SELECT hashed_password FROM user_credentials WHERE user_id = ?';
      connection.query(credentialsQuery, [userId], async (err, results) => {
        if (err) {
          logger.error('Ошибка при поиске пароля:', err);
          return res.status(500).send('Ошибка при аутентификации');
        }

        if (results.length === 0) {
          return res.status(400).send('Ошибка аутентификации');
        }

        const hashedPassword = results[0].hashed_password;

        // Сравнение введенного пароля с хэшированным паролем
        const passwordMatch = await bcrypt.compare(password, hashedPassword);
        if (!passwordMatch) {
          return res.status(400).send('Неверный пароль');
        }

        // Создаем JWT токен
        const token = jwt.sign({ userId, role: user.role }, secretKey, { expiresIn: '1h' });

        // Сохраняем токен в cookies
        res.cookie('token', token, { httpOnly: true });

        // Перенаправляем на страницу с книгами после успешного входа
        res.redirect('/books');
      });
    });
  });
};
