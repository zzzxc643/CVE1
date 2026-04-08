

The [aprocess.php](vscode-file://vscode-app/d:/VS/Microsoft VS Code/e7fb5e96c0/resources/app/out/vs/code/electron-browser/workbench/workbench.html) file in the EMPLOYEE_MANAGEMENT_SYSTEM_ contains a SQL injection vulnerability. The `pwd` parameter is directly concatenated into the SQL query without any escaping or parameterization.

Vulnerability Impact:

- Attackers can bypass login authentication by crafting malicious `pwd` values.
- Arbitrary SQL statements can be executed, allowing reading, modifying, or deleting database data.
- This may lead to sensitive information disclosure, account theft, and further exploitation of the entire system.



![image-20260408204751994](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260408204751994.png)



Payload: pwd=admin' AND IF(1=1, SLEEP(2), 0) -- 

```
pwd=admin' AND IF(1=1, SLEEP(2), 0) -- 
```

Source Download：

[Employee Management System in PHP With Source Code - Source Code & Projects](https://code-projects.org/employee-management-system-in-php-with-source-code/)

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```

