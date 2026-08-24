## ASSESSMENT MANAGEMENT IN PHP WITH SOURCE CODE admin/edit-user.php Stored XSS Vulnerability

### I. Vulnerability Impact

An attacker who can submit the user-editing form can inject arbitrary HTML/JavaScript into the `name` (or `surname`, `email`, `username`) field, which is stored in the database without any HTML encoding. The stored script is then rendered raw when any user opens the edit page for that account, resulting in persistent (stored) cross-site scripting and arbitrary script execution in the victim's browser, enabling session hijacking or phishing.

### II. Source Code Analysis

The vulnerability resides in `admin/edit-user.php`. On form submission the user input is only passed through `mysqli_real_escape_string()`, which escapes SQL special characters but leaves HTML characters untouched, and is then written to the `users` table:

```php
$name1 = mysqli_real_escape_string($conn, $_REQUEST['name']);
$sname1 = mysqli_real_escape_string($conn, $_REQUEST['sname']);
$email1 = mysqli_real_escape_string($conn, $_REQUEST['email']);
$username1 = mysqli_real_escape_string($conn, $_REQUEST['username']);
$password1 = mysqli_real_escape_string($conn, $_REQUEST['password']);

$query = "UPDATE users SET name='$name1', surname='$sname1', email='$email1', username='$username1', password='$password1', rank='$level' WHERE username='$user'";
```

When the page is rendered, the stored values are printed directly into the `value` attributes without `htmlspecialchars()` or `strip_tags()`:

```php
<input class="form-control" type="text" name="name" value="<?php if (isset($_GET['id'])) { print $name; }?>">
<input class="form-control" type="text" name="username" value="<?php if (isset($_GET['id'])) { print $user; }?>">
```

Because the stored value is printed raw inside an HTML attribute, a stored `"><script>` sequence closes the `value` attribute and the injected tag is executed by the browser. Note that the `name`/`surname`/`email`/`password` fields print stored database values without encoding (stored XSS). Additionally, when the `id` lookup returns no row, `$user` keeps the SQL-escaped `id` value and is printed into the `username` field, so the same `id` parameter is also a reflected XSS sink.

### III. Payload

The core stored payload written into the `name` field is:

```
"><sCrIpT>alert(999)</ScRiPt>
```

### IV. Source Download

https://code-projects.org/assessment-management-in-php-with-source-code/



![image-20260824095132412](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260824095132412.png)

