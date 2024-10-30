// Подключаем библиотеки
require('dotenv').config();  // Загружаем переменные окружения из .env файла
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');  // Для работы с путями файлов
const { authenticateToken, authorizeAdmin, authorizeLibrarianOrAdmin } = require('./middleware');
const logger = require('./logger'); // Подключаем логгер
const app = express();
const cookieParser = require('cookie-parser');

app.use(cookieParser());
// Подключаем модуль для авторизации (регистрация и логин)
const authRoutes = require('./auth');
app.use(express.static('public'));
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
    logger.error('Ошибка подключения к базе данных: ' + err.stack);
    return;
  }
  logger.info('Подключение к базе данных успешно установлено');
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
  logger.info('Регистрация данные: ', req.body); // Логируем входящие данные

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
        logger.error('Ошибка при добавлении пользователя в таблицу users: ', err);
        return res.status(500).send('Ошибка при регистрации пользователя');
      }

      const userId = result.insertId;

      // Вставляем хешированный пароль в таблицу user_credentials
      const credentialsQuery = 'INSERT INTO user_credentials (user_id, hashed_password) VALUES (?, ?)';
      connection.query(credentialsQuery, [userId, hashedPassword], (err, result) => {
        if (err) {
          logger.error('Ошибка при добавлении пароля в таблицу user_credentials: ', err);
          return res.status(500).send('Ошибка при сохранении пароля');
        }

        logger.info('Пользователь успешно зарегистрирован');
        res.redirect('/');  // После регистрации перенаправляем на страницу логина
      });
    });
  } catch (error) {
    logger.error('Ошибка при регистрации: ', error);
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
      logger.error('Ошибка при поиске пользователя: ', err);
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
        logger.error('Ошибка при поиске пароля: ', err);
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

// Маршрут для отображения страницы добавления книги (доступно только администратору)
app.get('/books/add', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Доступ запрещен');
  }
  res.render('add-book'); // Создаем новый шаблон add-book.ejs
});

// Маршрут для обработки добавления новой книги
app.post('/books/add', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Доступ запрещен');
  }

  const { title, author, genre, published_year, available_count } = req.body;
  // Проверяем, чтобы год не превышал 2024
  if (parseInt(published_year, 10) > 2024) {
    return res.status(400).send('Год публикации не может быть больше 2024');
  }
  const query = `
    INSERT INTO Books (title, author, genre, published_year, availability_status, available_count)
    VALUES (?, ?, ?, ?, 'available', ?)
  `;

  connection.query(query, [title, author, genre, published_year, available_count], (err) => {
    if (err) {
      logger.error('Ошибка при добавлении книги:', err);
      return res.status(500).send('Ошибка сервера');
    }

    // После успешного добавления перенаправляем обратно на страницу списка книг
    res.redirect('/books');
  });
});

// Маршрут для взятия книги
app.post('/books/take/:id', authenticateToken, (req, res) => {
  const bookId = req.params.id;
  const userId = req.user.userId;  // Получаем ID пользователя из токена

  // Проверка доступности книги
  const checkBookQuery = `
    SELECT available_count 
    FROM Books 
    WHERE book_id = ? 
    FOR UPDATE
  `;
  
  connection.beginTransaction((err) => {
    if (err) throw err; // Начинаем транзакцию

    // Сначала проверим доступность книги
    connection.query(checkBookQuery, [bookId], (err, results) => {
      if (err) {
        return connection.rollback(() => {
          logger.error('Ошибка при проверке книги:', err);
          res.status(500).send('Ошибка сервера');
        });
      }

      if (results.length > 0 && results[0].available_count > 0) {
        const availableCount = results[0].available_count - 1;

        // Обновляем количество доступных книг
        const updateBookQuery = `
          UPDATE Books
          SET available_count = ?, availability_status = ?
          WHERE book_id = ?
        `;
        const newStatus = availableCount > 0 ? 'available' : 'unavailable';

        connection.query(updateBookQuery, [availableCount, newStatus, bookId], (err) => {
          if (err) {
            return connection.rollback(() => {
              logger.error('Ошибка при обновлении книги:', err);
              res.status(500).send('Ошибка сервера');
            });
          }

          // Вставляем новую запись в таблицу Loans
          const insertLoanQuery = `
            INSERT INTO loans (book_id, user_id, issue_date) 
            VALUES (?, ?, NOW())
          `;
          
          connection.query(insertLoanQuery, [bookId, userId], (err, results) => {
            if (err) {
              return connection.rollback(() => {
                logger.error('Ошибка при вставке записи в loans:', err);
                res.status(500).send('Ошибка сервера');
              });
            }

            // Фиксируем изменения (commit)
            connection.commit((err) => {
              if (err) {
                return connection.rollback(() => {
                  logger.error('Ошибка при коммите транзакции:', err);
                  res.status(500).send('Ошибка сервера');
                });
              }
              logger.info('Запись добавлена в Loans:', results);
              res.redirect('/books');
             
            });
          });
        });
      } else {
        connection.rollback(() => {
          res.status(400).send('Книга больше недоступна');
        });
      }
    });
  });
});

// Маршрут для возврата книги
app.post('/books/return/:id', authenticateToken, (req, res) => {
  const bookId = req.params.id;
  const userId = req.user.userId; // Получаем ID пользователя из токена

  // Проверяем, брал ли пользователь эту книгу и не вернул ли её уже
  const query = `
    SELECT * FROM loans
    WHERE book_id = ? AND user_id = ? AND return_date IS NULL
  `;
  connection.query(query, [bookId, userId], (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      // Обновляем запись в Loans с датой возврата
      const updateLoanQuery = `
        UPDATE Loans
        SET return_date = NOW()
        WHERE loan_id = ?
      `;
      connection.query(updateLoanQuery, [results[0].loan_id], (err) => {
        if (err) throw err;

        // Увеличиваем количество доступных книг и обновляем статус
        const updateBookQuery = `
          UPDATE Books
          SET available_count = available_count + 1,
              availability_status = IF(available_count + 1 > 0, 'available', 'unavailable')
          WHERE book_id = ?
        `;
        connection.query(updateBookQuery, [bookId], (err) => {
          if (err) throw err;

          // Обновляем книги и возвращаем на страницу
          res.redirect('/books'); // Возвращаемся на страницу книг
        });
      });
    } else {
      res.status(400).send('Вы не брали эту книгу или уже вернули её');
    }
  });
});
app.get('/books', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const filterAvailable = req.query.filterAvailable === 'true';
  const filterBorrowed = req.query.filterBorrowed === 'true';
  const searchQuery = req.query.searchQuery;
  const itemsPerPage = 5;
  const currentPage = parseInt(req.query.page) || 1;
  const offset = (currentPage - 1) * itemsPerPage;

  // Запрос для подсчета общего количества книг с учетом фильтров и поиска
  let countQuery = `
    SELECT COUNT(*) as total
    FROM Books
    LEFT JOIN Loans ON Books.book_id = Loans.book_id AND Loans.user_id = ? AND Loans.return_date IS NULL
  `;
  let whereClauses = [];
  const queryParams = [userId];

  if (filterAvailable) {
    whereClauses.push("Books.availability_status = 'available'");
  }
  if (filterBorrowed) {
    whereClauses.push("Loans.loan_id IS NOT NULL");
  }
  if (searchQuery) {
    whereClauses.push(`
      (Books.title LIKE ? OR 
       Books.author LIKE ? OR 
       Books.genre LIKE ? OR 
       Books.published_year LIKE ?)
    `);
    queryParams.push(`%${searchQuery}%`, `%${searchQuery}%`, `%${searchQuery}%`, `%${searchQuery}%`);
  }

  if (whereClauses.length > 0) {
    countQuery += ' WHERE ' + whereClauses.join(' AND ');
  }

  connection.query(countQuery, queryParams, (err, countResults) => {
    if (err) throw err;

    const totalItems = countResults[0].total;
    const totalPages = Math.ceil(totalItems / itemsPerPage);

    // Основной запрос для получения книг с учетом фильтров, поиска и пагинации
    let query = `
      SELECT 
        Books.*, 
        Loans.loan_id, 
        Loans.return_date, 
        bookdetails.summary, 
        bookdetails.page_count
      FROM 
        Books
      LEFT JOIN 
        Loans ON Books.book_id = Loans.book_id AND Loans.user_id = ? AND Loans.return_date IS NULL
      LEFT JOIN 
        bookdetails ON Books.book_id = bookdetails.book_id
    `;

    if (whereClauses.length > 0) {
      query += ' WHERE ' + whereClauses.join(' AND ');
    }

    query += ' LIMIT ? OFFSET ?';
    const queryParamsWithPagination = [...queryParams, itemsPerPage, offset];

    connection.query(query, queryParamsWithPagination, (err, results) => {
      if (err) throw err;

      res.render('books', {
        books: results,
        user: req.user,
        filterAvailable,
        filterBorrowed,
        searchQuery,
        currentPage,
        totalPages,
      });
    });
  });
});

app.get('/my-history', authenticateToken, (req, res) => {
  const userId = req.user.userId;

  // Запрос для получения всех записей из таблицы loans для текущего пользователя
  const query = `
    SELECT 
      loans.*, 
      Books.title, 
      Books.author, 
      Books.genre, 
      Books.published_year, 
      bookdetails.summary, 
      bookdetails.page_count 
    FROM 
      Loans 
    JOIN 
      Books ON Loans.book_id = Books.book_id 
    LEFT JOIN 
      bookdetails ON Books.book_id = bookdetails.book_id
    WHERE 
      Loans.user_id = ?
  `;

  connection.query(query, [userId], (err, results) => {
    if (err) throw err;

    // Рендерим шаблон с историей пользователя
    res.render('history', { loans: results, user: req.user });
  });
});

app.get('/users', authenticateToken, authorizeLibrarianOrAdmin, (req, res) => {
  const searchQuery = req.query.searchQuery || ''; // Получаем значение поиска

  // Создаем SQL-запрос с учетом поиска
  const sql = `SELECT * FROM users WHERE name LIKE ? OR email LIKE ? OR user_id LIKE ?`;
  const queryParams = [`%${searchQuery}%`, `%${searchQuery}%`, `%${searchQuery}%`];

  connection.query(sql, queryParams, (err, results) => {
    if (err) throw err;

    // Форматируем дату перед отправкой
    results.forEach(user => {
      user.registration_date = new Date(user.registration_date).toLocaleString();
    });

    // Отправляем данные на страницу вместе с ролью текущего пользователя
    res.render('users', { users: results, currentUserRole: req.user.role, searchQuery });
  });
});

// Маршрут для отображения страницы редактирования
app.get('/books/edit/:id', async (req, res) => {
  const bookId = req.params.id;
  try {
    // Запрос объединенных данных из Books и bookdetails
    const [rows] = await connection.promise().query(`
      SELECT Books.*, bookdetails.summary, bookdetails.page_count
      FROM Books
      LEFT JOIN bookdetails ON Books.book_id = bookdetails.book_id
      WHERE Books.book_id = ?
    `, [bookId]);

    res.render('editBook', { book: rows[0], user: req.user });
  } catch (error) {
    console.error(error);
    res.status(500).send('Ошибка при получении данных книги');
  }
});

// Маршрут для обновления данных книги
app.post('/books/edit/:id', async (req, res) => {
  const { title, author, genre, published_year, availability_status, available_count, summary, page_count } = req.body;
  const bookId = req.params.id;

  try {
    // Обновляем данные в таблице Books
    await connection.promise().query(
      'UPDATE Books SET title = ?, author = ?, genre = ?, published_year = ?, availability_status = ?, available_count = ? WHERE book_id = ?',
      [title, author, genre, published_year, availability_status, available_count, bookId]
    );

    // Обновляем данные в таблице bookdetails
    await connection.promise().query(
      'UPDATE bookdetails SET summary = ?, page_count = ? WHERE book_id = ?',
      [summary, page_count, bookId]
    );

    res.redirect('/books');
  } catch (error) {
    console.error(error);
    res.status(500).send('Ошибка при обновлении данных книги');
  }
});


app.post('/users/:id/delete', (req, res) => {
  const userId = req.params.id;

  // Сначала удаляем все займы пользователя
  connection.query('DELETE FROM loans WHERE user_id = ?', [userId], (err) => {
    if (err) return res.status(500).send('Ошибка при удалении займов.');

    // Теперь удаляем пользователя
    connection.query('DELETE FROM users WHERE user_id = ?', [userId], (err) => {
      if (err) return res.status(500).send('Ошибка при удалении пользователя.');
      
      res.redirect('/users');
    });
  });
});

app.get('/loans', authenticateToken, authorizeLibrarianOrAdmin, (req, res) => {
  const page = parseInt(req.query.page) || 1; 
  const limit = 25; 
  const offset = (page - 1) * limit; 
  const searchQuery = req.query.searchQuery || ''; 

  logger.info('Search Query:', searchQuery); // Логирование

  const countQuery = `
    SELECT COUNT(*) AS total 
    FROM Loans 
    JOIN Books ON Loans.book_id = Books.book_id
    JOIN Users ON Loans.user_id = Users.user_id
    WHERE Books.title LIKE ? OR Users.name LIKE ?`;

  const countParams = [`%${searchQuery}%`, `%${searchQuery}%`];

  connection.query(countQuery, countParams, (err, countResult) => {
    if (err) throw err;

    const totalLoans = countResult[0].total;  
    const totalPages = Math.ceil(totalLoans / limit);  

    const loansQuery = `
      SELECT 
        Loans.loan_id, 
        Books.title AS book_title, 
        Users.name AS user_name, 
        Loans.issue_date, 
        Loans.return_date 
      FROM Loans
      JOIN Books ON Loans.book_id = Books.book_id
      JOIN Users ON Loans.user_id = Users.user_id
      WHERE Books.title LIKE ? OR Users.name LIKE ?
      ORDER BY Loans.loan_id ASC  
      LIMIT ? OFFSET ?`;

    const loansParams = [`%${searchQuery}%`, `%${searchQuery}%`, limit, offset];

    logger.info('Loans Query:', loansQuery, loansParams); // Логирование

    connection.query(loansQuery, loansParams, (err, results) => {
      if (err) throw err;

      logger.info('Results:', results); // Логирование

      results.forEach(loan => {
        loan.issue_date = new Date(loan.issue_date).toLocaleString();
        loan.return_date = loan.return_date ? new Date(loan.return_date).toLocaleString() : 'Не возвращена';
      });

      res.render('loans', {
        loans: results,
        currentPage: page,
        totalPages: totalPages,
        searchQuery  
      });
    });
  });
});

// Запуск сервера на порту 3000
app.listen(3000, () => {
  logger.info('Сервер запущен на http://localhost:3000');
});
