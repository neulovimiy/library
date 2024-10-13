  // Функция для сортировки таблицы
  function sortTable(n, type) {
    var table, rows, switching, i, x, y, shouldSwitch, dir, switchCount = 0;
    table = document.getElementById("booksTable");
    switching = true;
    dir = "asc"; // Устанавливаем направление сортировки по умолчанию

    while (switching) {
      switching = false;
      rows = table.rows;

      // Проходим по всем строкам таблицы, кроме первой (заголовки)
      for (i = 1; i < (rows.length - 1); i++) {
        shouldSwitch = false;

        // Получаем два элемента для сравнения
        x = rows[i].getElementsByTagName("TD")[n];
        y = rows[i + 1].getElementsByTagName("TD")[n];

        // Проверяем направление сортировки
        if (dir == "asc") {
          if (type === 'number') {
            if (parseInt(x.innerHTML) > parseInt(y.innerHTML)) {
              shouldSwitch = true;
              break;
            }
          } else {
            if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
              shouldSwitch = true;
              break;
            }
          }
        } else if (dir == "desc") {
          if (type === 'number') {
            if (parseInt(x.innerHTML) < parseInt(y.innerHTML)) {
              shouldSwitch = true;
              break;
            }
          } else {
            if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
              shouldSwitch = true;
              break;
            }
          }
        }
      }

      // Если было найдено, что нужно переключать строки, делаем это
      if (shouldSwitch) {
        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
        switching = true;
        switchCount++;
      } else {
        // Если не было переключений, меняем направление сортировки
        if (switchCount == 0 && dir == "asc") {
          dir = "desc";
          switching = true;
        }
      }
    }
  }

  // Функция для фильтрации таблицы по значению в поисковой строке
  function filterTable() {
    var input, filter, table, tr, td, i, j, txtValue, availableOnly, status;
    input = document.getElementById("searchInput");
    filter = input.value.toLowerCase();
    table = document.getElementById("booksTable");
    tr = table.getElementsByTagName("tr");
    availableOnly = document.getElementById("availableOnly").checked;

    // Проходим по всем строкам таблицы (кроме заголовков)
    for (i = 1; i < tr.length; i++) {
      tr[i].style.display = "none"; // Скрываем все строки по умолчанию
      var matchFound = false;

      // Проверяем все столбцы (кроме последнего столбца с кнопками)
      for (j = 0; j < tr[i].cells.length - 1; j++) {
        td = tr[i].getElementsByTagName("td")[j];
        if (td) {
          txtValue = td.textContent || td.innerText;
          if (txtValue.toLowerCase().indexOf(filter) > -1) {
            matchFound = true;
          }
        }
      }

      // Проверка статуса доступности книги
      status = tr[i].getElementsByTagName("td")[5].textContent || tr[i].getElementsByTagName("td")[5].innerText;
      if (availableOnly && status !== 'available') {
        matchFound = false;
      }

      if (matchFound) {
        tr[i].style.display = ""; // Показываем строку, если найдена совпадающая ячейка
      }
    }
  }
  