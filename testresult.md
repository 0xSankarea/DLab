# Test result

|Сценарий |Порядок действий  |Ожидаемый результат  | Фактический результат| Оценка|
|--|--| --|--|--|
| Импорт файла с конфигурацией |  Старт программы, проверка загруженных в программу данный| Система получит API ключи и сможет выполнять подключения к вашим системам  |Приложение не выполняет подключений, если ваш файл конфигурации не заполнен|Прошел|
| Проверка новых нотификаций|Проверка выполнения подключения к VT HUNT, просмотр информации о нотификации| Выполнение HTTP запроса, выгрузка последних 20 нотификаций.|Информация о нотификациях была получена|Прошел|
| Получение новых файлов по данным нотификации| Проверка выполнения подключение к VT HUNT, проверка HASH сумм файлов |Составление запроса исходня из данных полученных в нотификации, загрузка данных через HTTP, удаление нотификации  |Файл получен|Прошел|
| Эмуляция файлов в Cuckoo Sandbox| Проверка выполнения подключения к серверу Cuckoo, просмотр созданных задач | Выполнение HTTP запроса, отправка файла на эмуляцию с заданными параметрами|Файл был проэмулирован|Прошел|
| Репорт в базу Elasticsearch| Проверка подключенности reporting модулей в Cuckoo, просмотр репорта | Репорт был экспортирован из Cuckoo в Elasticsearch|Запись в базе была создана|Прошел|
| Все ошибки должны сопровождаться поясняющими сообщениями |  Указать неверные данные или другими способами нарушить корректное выполнение|Система отобразит ошибку |Ошибка отображена|Прошел|
| Графики в WEBUI должны быть осмысленными| Просмотр графиков, сравнение графиков на сторонних ресурсах|Графики постронные по полученным репортам|Графики построенны, однако их небольшое количество и низкая вариантивность не позволяет производить точные оценки |Не прошел|
| Дизайн должен быть единообразным| Оценка дизайна, использование WEB UI | Общий дизайн не должен быть перегруженным и вызывать сложности при работе|Дизайн удобен, цветовая схема корректная|Прошел|
| Тестирование производительности| Использование программы, оценка протребления ресурсов | Необходимая производительность не должна превышать мощности стандартого персонального компьютера |Производительность неудовлетворительная для запуска на персональных системах|Не прошел|
| Тестирование структуры WEBUI| Использование всех вкладок WEB UI | Структура WEB UI должна способствовать быстрому получению информации|Наблюдается ожидаемые результат|Прошел|

---
#### Замечания:
* Установка и настройка необходимых сервисов занимает большое количество времени. Необходимо подготовить для устоновки уже готовый образ или использовать другие способы автоматизации данного процесса.
* Предоставленный Research View для Кибаны недостаточно удобен, необходимо разработать большее количество шаблонов.
* Для самого скрипта так же не описаны зависимости, что может вызвать затруднения при запуске скрипта.
* Необходимо подготовить и вносить в репозиторий набор стандартных правил для VT HUNT в качестве примеров.
* Сам скрипт предоставляет удобную систему парсинга, однако не предоставляет необходимого инструментария для работы с правилами для VT HUNT.
* Для использования нужен платный аккаунт VirusTotal, что не было указано. 