const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf, errors } = format;

// Формат логов
const logFormat = printf(({ level, message, timestamp, stack }) => {
  return `${timestamp} ${level}: ${stack || message}`;
});

// Создание логгера
const logger = createLogger({
  level: 'info', // Можно задать уровни логирования (info, warn, error и т.д.)
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }), // Логирование с отслеживанием ошибок
    logFormat
  ),
  transports: [
    new transports.File({ filename: 'logs/error.log', level: 'error' }), // Логи ошибок
    new transports.File({ filename: 'logs/combined.log' }) // Общие логи
  ]
});

// В режиме разработки можно выводить логи и в консоль
if (process.env.NODE_ENV !== 'production') {
  logger.add(new transports.Console({
    format: format.simple()
  }));
}

module.exports = logger;
