

## EMPLOYEE_MANAGEMENT_SYSTEM  file `370project/edit.php` has a Reflected XSS vulnerability

Impact of the vulnerability
An attacker can craft a malicious link to trick an administrator into clicking it, causing arbitrary JavaScript to execute in the administrator’s browser. This may lead to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (performing sensitive actions with admin privileges)
- Page defacement / phishing (fake login prompts, tampering with displayed data)

#### Payload:

"><ScRiPt>alert(1)</ScRiPt>

```
"><ScRiPt>alert(1)</ScRiPt>
```



#### sources download：

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409103252951](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409103252951.png)