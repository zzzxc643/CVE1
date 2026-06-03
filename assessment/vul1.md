#   Assessment Management System login.php SQL Injection Vulnerability

  A SQL injection vulnerability exists in the login.php file of the Assessment Management System. The application
  directly concatenates user-controlled input from the userid and password parameters into an SQL query without proper
  sanitization or parameterized statements. As a result, an attacker can inject arbitrary SQL syntax into the
  authentication query.

##  

##  Impact of the Vulnerability

  This vulnerability may allow an attacker to manipulate backend SQL queries, bypass authentication, extract database
  content, and trigger database error-based responses. In some cases, it may lead to disclosure of sensitive information
  such as usernames, password data, or other application records stored in the database.

##  

##  Payload

```
admin'and/**/extractvalue(1,concat(char(126),md5(1049915738)))and'
```

admin'and/**/extractvalue(1,concat(char(126),md5(1049915738)))and'



##   Proof of Concept

  When the above payload is sent to login.php, the server responds with a database error message containing the injected
  MD5 marker:

  XPATH syntax error: '~0cbac61d643315e758343ede0c3360d'

  This demonstrates that user input is embedded into the SQL statement and executed by the database engine, confirming
  the presence of an error-based SQL injection vulnerability.

##  

##  Source Download

```
 [Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)
```

[Assessment Management In PHP With Source Code - Source Code & Projects](https://code-projects.org/assessment-management-in-php-with-source-code/)



![image-20260603093017948](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260603093017948.png)