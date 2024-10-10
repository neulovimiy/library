// Подключаем библиотеки
require('dotenv').config();  // Загружаем переменные окружения из .env файла
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');  // Для работы с путями файлов
const { authenticateToken, authorizeAdmin } = require('./middleware'); // Импортируем миддлвары для авторизации

const app = express();
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// Подключаем модуль для авторизации (регистрация и логин)
const authRoutes = require('./auth');

// Настроим парсинг данных формы
app.use(bodyParser.urlencoded({ extended: true }));  // Для обработки данных форм
app.use(bodyParser.json());  // Для обработки JSON данных

// Устанавливаем EJS как шаблонизатор
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));  // Указываем папку для шаблонов

// Настройка соединения с базой данных
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'library'
});

// Проверка соединения с базой данных
connection.connect((err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных: ' + err.stack);
    return;
  }
  console.log('Подключение к базе данных успешно установлено');
});

// Используем маршруты для аутентификации
authRoutes(app, connection);

// Главная страница (страница входа)
app.get('/', (req, res) => {
  res.render('login'); // Рендерим страницу login.ejs
});

// Страница регистрации
app.get('/register', (req, res) => {
  res.render('register'); // Рендерим страницу register.ejs
});

// Регистрация пользователя
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Логируем данные, чтобы убедиться, что они приходят корректно
  console.log('Регистрация данные: ', req.body); // Логируем входящие данные

  // Проверка на пустые значения
  if (!name || !email || !password) {
    return res.status(400).send('Все поля обязательны для заполнения');
  }

  try {
    // Хэшируем пароль
    const hashedPassword = await bcrypt.hash(password, 10);

    // Вставляем нового пользователя в таблицу users
    const query = 'INSERT INTO users (name, email, role) VALUES (?, ?, ?)';
    connection.query(query, [name, email, 'user'], (err, result) => {
      if (err) {
        console.error('Ошибка при добавлении пользователя в таблицу users: ', err);
        return res.status(500).send('Ошибка при регистрации пользователя');
      }

      const userId = result.insertId;

      // Вставляем хешированный пароль в таблицу user_credentials
      const credentialsQuery = 'INSERT INTO user_credentials (user_id, hashed_password) VALUES (?, ?)';
      connection.query(credentialsQuery, [userId, hashedPassword], (err, result) => {
        if (err) {
          console.error('Ошибка при добавлении пароля в таблицу user_credentials: ', err);
          return res.status(500).send('Ошибка при сохранении пароля');
        }

        console.log('Пользователь успешно зарегистрирован');
        res.redirect('/');  // После регистрации перенаправляем на страницу логина
      });
    });
  } catch (error) {
    console.error('Ошибка при регистрации: ', error);
    res.status(500).send('Ошибка при регистрации');
  }
});
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email и пароль обязательны для входа');
  }

  const query = 'SELECT user_id, role FROM users WHERE email = ?';
  connection.query(query, [email], async (err, results) => {
    if (err) {
      console.error('Ошибка при поиске пользователя: ', err);
      return res.status(500).send('Ошибка при аутентификации');
    }

    if (results.length === 0) {
      return res.status(400).send('Пользователь не найден');
    }

    const user = results[0];
    const userId = user.user_id;

    const credentialsQuery = 'SELECT hashed_password FROM user_credentials WHERE user_id = ?';
    connection.query(credentialsQuery, [userId], async (err, results) => {
      if (err) {
        console.error('Ошибка при поиске пароля: ', err);
        return res.status(500).send('Ошибка при аутентификации');
      }

      if (results.length === 0) {
        return res.status(400).send('Ошибка аутентификации');
      }

      const hashedPassword = results[0].hashed_password;

      // Сравниваем пароли
      const passwordMatch = await bcrypt.compare(password, hashedPassword);
      if (!passwordMatch) {
        return res.status(400).send('Неверный пароль');
      }

      // Создаем JWT токен
      const token = jwt.sign({ userId, role: user.role }, process.env.SECRET_KEY, { expiresIn: '1h' });

      // Сохраняем токен в cookies
      res.cookie('token', token, { httpOnly: true });

      // Перенаправляем на страницу с книгами после успешного входа
      res.redirect('/books');
    });
  });
});


// Маршрут для получения всех пользователей (только для админов)
app.get('/users', authenticateToken, authorizeAdmin, (req, res) => {
  connection.query('SELECT * FROM users', (err, results) => {
    if (err) throw err;

    // Форматируем дату перед отправкой
    results.forEach(user => {
      user.registration_date = new Date(user.registration_date).toLocaleString();
    });

    res.json(results);
  });
});

app.get('/books', authenticateToken, (req, res) => {
  connection.query('SELECT * FROM Books', (err, results) => {
    if (err) throw err;

    // Рендерим страницу с книгами
    res.render('books', { books: results });
  });
});


// Маршрут для получения всех выданных книг (только для админов)
app.get('/loans', authenticateToken, authorizeAdmin, (req, res) => {
  const query = `
    SELECT 
      Loans.loan_id, 
      Books.title AS book_title, 
      Users.name AS user_name, 
      Loans.issue_date, 
      Loans.return_date 
    FROM Loans
    JOIN Books ON Loans.book_id = Books.book_id
    JOIN Users ON Loans.user_id = Users.user_id
  `;

  connection.query(query, (err, results) => {
    if (err) throw err;

    // Форматируем даты перед отправкой
    results.forEach(loans => {
      loans.issue_date = new Date(loans.issue_date).toLocaleString();
    });

    res.json(results);  // Отправляем результат как JSON
  });
});

// Запуск сервера на порту 3000
app.listen(3000, () => {
  console.log('Сервер запущен на http://localhost:3000');
});
