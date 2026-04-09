## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/empproject.php` contains a SQL Injection vulnerability (and also reflects `id` into HTML without escaping)

Impact of the vulnerability
Because the `id` parameter is concatenated into an SQL query without parameterization, an attacker may be able to:

- Manipulate database queries to access unauthorized data (depending on DB permissions)
- Bypass intended filtering and potentially enumerate records
- Trigger database errors that may leak information (in some configurations)

### Payload:

101'and'h'='m

```
101'and'h'='m
```

### POC:

The vulnerable endpoint is `GET /empproject.php?id=...`. The `id` parameter is directly inserted into an SQL statement:

$id = (isset($_GET['id']) ? $_GET['id'] : '');

require_once ('process/dbh.php');

$sql = "SELECT * FROM `project` where eid = '$id'";

$result = mysqli_query($conn, $sql);

- Baseline request:

GET /empproject.php?id=101 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

- Injection test request (use any quote-containing test string in `id` to check for query breakage / abnormal behavior):

GET /empproject.php?id=<URL_ENCODED_SQLI_TEST_STRING> HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
Compared with the baseline, the test request may produce SQL errors, different content, or other abnormal behavior, indicating the `id` value is affecting the backend SQL execution. (In your response, you can also see the unescaped `id` being reflected into navigation links, which is a separate output-encoding issue.)

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409154257525](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409154257525.png)