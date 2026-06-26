## ONLINE_FOOD_ORDER_SYSTEM - Stored XSS Vulnerability in edit_food_items.php

### Vulnerability Description

A stored Cross-Site Scripting (XSS) vulnerability exists in the `edit_food_items.php` file of the ONLINE_FOOD_ORDER_SYSTEM. The `dname` parameter is directly inserted into the database without any sanitization, and subsequently output to the HTML page without escaping, allowing arbitrary JavaScript execution.

### Impact

An attacker can inject malicious JavaScript code via the `dname` parameter, which gets stored in the database and executed in the browser of any user viewing the affected pages. This can lead to cookie theft and session hijacking.

### Code Analysis

**edit_food_items.php (Lines 130-148):**

```php
if (isset($_GET['submit'])) {
    $name = $_GET['dname'];           // No sanitization
    $price = $_GET['dprice'];
    $description = $_GET['ddescription'];

    // Directly concatenated into SQL UPDATE
    $query = mysqli_query($conn, "UPDATE food set
    name='$name', price='$price',
    description='$description' where F_ID='$F_ID'");
}

// Output from database directly into HTML without htmlspecialchars()
$query = mysqli_query($conn, "SELECT * FROM food f WHERE ...");
while ($row = mysqli_fetch_array($query)) {
    echo "<b><a href='edit_food_items.php?update= {$row['F_ID']}'>"
        . "{$row['name']}"            // Malicious code rendered directly
        . "</a></b>";
}
```

### Payload

```
<sCrIpT>alert(9999)</ScRiPt>
```

### Source Download

https://code-projects.org/online-food-order-system-in-php-with-source-code/



![image-20260626220735926](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260626220735926.png)
