## ONLINE_FOOD_ORDER_SYSTEM - Error-Based SQL Injection in delete_food_items1.php

### Vulnerability Description

An error-based SQL injection vulnerability exists in the `delete_food_items1.php` file of the ONLINE_FOOD_ORDER_SYSTEM. The `checkbox` POST parameter is directly concatenated into an SQL UPDATE statement without any sanitization, and database errors are output via `mysqli_error()`, allowing attackers to extract sensitive data through error-based injection.

### Impact

An attacker can leverage this vulnerability to extract database information (database name, table names, column names, user credentials, etc.) and potentially modify or delete arbitrary data in the database.

### Code Analysis

**delete_food_items1.php:**

```php
$cheks = implode("','", $_POST['checkbox']);           // No sanitization
$sql = "UPDATE FOOD SET `options` = 'DISABLE' WHERE F_ID in ('$cheks')";
$result = mysqli_query($conn,$sql) or die(mysqli_error($conn));  // Error output
```

### Payload

```
checkbox[]=80'and/**/extractvalue(1,concat(char(126),md5(1779411101)))and'
```

### Source Download

https://code-projects.org/online-food-order-system-in-php-with-source-code/



![image-20260626221239333](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260626221239333.png)
