# Web-AppSec-Interview-Questions
The following web application security questions and answers (mostly focused on web app hacking) are part of  my Experience.

---

<details>
<summary><b>1. What is the difference between Web Cache Deception and Web Cache Poisoning?</b></summary>

**Web Cache Deception** involves finding a dynamic page that can be accessed via a URL a web cache will automatically cache (e.g., if `/transactions` can be accessed at `/transactions.jpg`). If an attacker can trick a victim into visiting the cacheable URL, they can then load the same URL and retrieve the victim's information from the cache.

**Web Cache Poisoning** involves finding an input that results in some exploitable change in the response but doesn't form part of the cache key for the request. When an attacker sends their payload, the exploited response will be cached and then delivered to anyone who accesses the page.
</details>

---

<details>
<summary><b>2. What two criteria must be met to exploit Session Fixation?</b></summary>

Session Fixation is not the same as Session Hijacking but rather a type of Session Hijacking attack. The two criteria are:

- Attacker must be able to forcibly set a (syntactically valid but otherwise inactive) session token in the victim's browser (e.g., using XSS / CRLF injection)
- Once the victim authenticates, the application uses the session token already present and does not set a new one
</details>

---

<details>
<summary><b>3. What are the differences between Base64 and Base64URL encoding?</b></summary>

In Base64URL encoding:
- A `-` is used instead of a `+`
- A `_` is used instead of a `/`
- Padding with `=` is optional and usually omitted

This provides more compatibility when the value needs to be used in a URL.

**Note:** Padding is actually not required at all for decoding, even in regular Base64, because we can figure out how many bytes are left to decode based on the number of remaining Base64 characters:
- 2 characters = 1 more byte
- 3 characters = 2 more bytes
</details>

---

<details>
<summary><b>4. Name 5 (or more) types of Cross-Site Scripting.</b></summary>

The 5 main types are:
- Reflected XSS
- Stored XSS
- DOM-based XSS
- CSTI (Client-Side Template Injection)
- Server-Side XSS

Other types suggested include:
- Self XSS
- XST (Cross-Site Tracing)
- Universal XSS
- Blind XSS
- Mutation XSS
</details>

---

<details>
<summary><b>5. How does Boolean Error Inferential (Blind) SQL Injection work?</b></summary>

This is a variant where injecting "AND 1=1" and "AND 1=2" (for example) will return the same response! The trick is to purposefully cause a database error when a condition we want to test is true, and hope that error propagates back to the response somehow (e.g., a 500 Internal Server error).

Many ways to do this, but most use a CASE expression and some divide by zero if the condition is true. For example: `AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)`
</details>

---

<details>
<summary><b>6. What is the Same-Origin Policy (SOP) and how does it work?</b></summary>

The Same-Origin Policy is a security mechanism browsers use to prevent a variety of cross-origin attacks. The basic principle is that client-side app code can only read data from a specific URL if the URL has the same origin as the current app. Two URLs have the same origin if they share the same protocol, host, and port.

Note that reading and embedding data from URLs are treated differently, allowing applications to embed things like scripts, videos, images, etc. without actually being able to access the raw bytes of each.
</details>

---

<details>
<summary><b>7. How does the TE.TE variant of HTTP Request Smuggling work?</b></summary>

The TE.TE variant has two or more servers which always use the Transfer-Encoding header over the Content-Length header if both are present, which usually makes Request Smuggling impossible. However, by manipulating the Transfer-Encoding header, it is possible to cause one of the servers to not recognize it. This server will use the Content-Length header instead, allowing the Request Smuggling attack to work.

There are countless ways to manipulate the Transfer-Encoding header. Common ones are including whitespace before the colon, capitalization, or modifying the value "chunked" in the header itself.
</details>

---

<details>
<summary><b>8. What is DOM Clobbering and how can it be used to bypass (some) HTML sanitizers, resulting in XSS?</b></summary>

DOM Clobbering is a way to manipulate the DOM using only HTML elements (i.e., no JavaScript). By using the id or name attribute of some elements, it is possible to create global variables in the DOM. This can lead to XSS in some cases.

[DOM Clobbering Cheatsheet](https://example.com) (works best in Chrome)
</details>

---

<details>
<summary><b>9. Describe how HTTP Parameter Pollution could be used to bypass a Web Application Firewall.</b></summary>

Some servers will concatenate parameter values if two or more identical parameters exist in requests, though often with a separator (e.g., a comma). For certain payloads, WAF detection can sometimes be bypassed if the payload can be split across multiple parameters.
</details>

---

<details>
<summary><b>10. Describe IDOR and explain how mitigating it is different from other access control vulnerabilities.</b></summary>

Insecure Direct Object References occur when an application provides functionality to access a resource using some unique reference (e.g., an ID) but does not perform adequate access control checks to determine if the user should have access to the specific resource.

Generally, the user should be able to access the functionality, but not all resources via the functionality. Thus, mitigation involves an access check comparing the user to the specific resource being requested, as opposed to the functionality itself.
</details>

---

<details>
<summary><b>11. What are JWKs and JKUs and how does their usage differ in JWTs?</b></summary>

A JSON Web Key (JWK) is a JSON object representing a signing key in a JWT. A JSON Web Key Set URL (JKU) is a URL which points to the location of a set of JWKs. In a JWT, both JWKs and JKUs go in the header.

When using a JWK, the entire public key is embedded within the header, whereas a JKU can point to a set of multiple public keys. In both cases a key ID (kid) is used to select the key to be used.
</details>

---

<details>
<summary><b>12. In the context of web apps, what is Business Logic and how does testing for Business Logic vulnerabilities differ compared to (for example) XSS, SQLi, etc?</b></summary>

Business logic is code which mimics real-world business operations / decisions, rather than code which handles how a user interacts with the application. Testing for business logic vulnerabilities usually involves identifying and challenging assumptions the developer has made about how someone uses the application, rather than technical oversights involving how data is processed.

It is impossible to identify business logic flaws using current scanners, since they require an understanding of the purpose of the application and are highly contextual.
</details>

---

<details>
<summary><b>13. Describe 3 payloads you could use to identify a server-side template engine by causing an error message.</b></summary>

- **Invalid syntax**: `${{<%[%'"}}%\`
- **Divide by zero**: `${1/0}`
- **Invalid variable names**: `${tib3rius}`
</details>

---

<details>
<summary><b>14. What is the purpose of the Sec-WebSocket-Key header?</b></summary>

The "key" has nothing to do with security / encryption. Since WebSockets are created using an initial HTTP request, the Sec-WebSocket-Key header is used by the client to make sure the server supports WebSockets. If the client doesn't receive a correctly hashed version of the key from the server, it doesn't continue with the WebSocket setup.
</details>

---

<details>
<summary><b>15. What does the "unsafe-inline" value allow for if used in a script-src directive of a CSP?</b></summary>

"unsafe-inline" will allow all inline scripts (e.g., `<script>...</script>` and "onevent" attributes) to be executed, but will not allow the loading of scripts from other files, nor will it allow the use of `eval()` and other methods which allow the execution of JavaScript from strings.
</details>

---

<details>
<summary><b>16. Give an example of stateless authentication, and describe an inherent weakness of this authentication mechanism.</b></summary>

Authentication using a JWT is an example of stateless authentication. An inherent weakness of stateless authentication is the inability to forcibly expire user sessions, since all session information is stored on the client-side.
</details>

---

<details>
<summary><b>17. Describe 3 ways to mitigate Cross-Site Request Forgery.</b></summary>

- Setting the SameSite cookie attribute to Lax or Strict on session cookies can prevent this cookie being added to cross-site requests, making forged requests unauthenticated. There are some exceptions if Lax is used.
- Requiring Anti-CSRF Tokens to be submitted with vulnerable requests will prevent CSRF provided the tokens are unique, unpredictable, and are not (only) submitted in cookies.
- Another option is to check the Referer header of a request to ensure it matches a trusted origin.
</details>

---

<details>
<summary><b>18. What are XML parameter entities and what limitations do they have in XXE Injection?</b></summary>

XML parameter entities are referenced using a `%` instead of `&`, but can only be referenced within a DTD, not the main XML document. This limitation means that parameter entities are often only useful with out-of-band XXE techniques.
</details>

---

<details>
<summary><b>19. What recommendations would you give a customer for fixing DOM based XSS?</b></summary>

If possible, avoid passing untrusted inputs to potentially dangerous JavaScript functions. Checks should be implemented to ensure that values only include expected characters (as opposed to trying to detect bad characters). Encoding inputs is also a possibility.
</details>

---

<details>
<summary><b>20. What conditions must be met to prevent a browser from sending a CORS Preflight request?</b></summary>

- Only GET, HEAD, or POST methods are allowed
- Only the following headers can be manually set: Accept, Accept-Language, Content-Language, Content-Type, Range
- If Content-Type is set, it must use one of the following: application/x-www-form-urlencoded, multipart/form-data, text/plain
- If XMLHttpRequest was used, no event listener must be registered on the XMLHttpRequest.upload property
- No ReadableStream object was used
</details>

---

<details>
<summary><b>21. Describe 3 ways an Insecure Deserialization vulnerability could be exploited.</b></summary>

- Modifying the value of an object attribute
- Modifying the type of an object attribute
- Using a Magic Method to make calls to other functions/methods (potentially leading to RCE)
</details>

---

<details>
<summary><b>22. List the checks an application might perform to ensure files cannot contain malicious content, and can only be uploaded to specific directories.</b></summary>

- Only allowing files with certain extensions and mime-types to be uploaded
- Performing file analysis (to confirm the file type) and AV scans
- Performing path canonicalization before checking the end location of the file matches an allowed directory
</details>

---

<details>
<summary><b>23. How does Mass Assignment work and what are some potential outcomes of exploiting such a vulnerability?</b></summary>

Mass Assignment occurs when functionality allowing users to create or update "objects" does not restrict which attributes a user can specify. This is more common in modern MVC-type frameworks.

This can lead to attackers being able to "upgrade" their role (e.g., to admin), add money to an account balance, assign potentially negative resources to other users, or perform a log forging attack by modifying date values, as well as countless other attacks.
</details>

---

<details>
<summary><b>24. What is GraphQL batching and how can it be used to bypass rate limiting?</b></summary>

GraphQL batching allows a user to send multiple queries or mutations to a GraphQL endpoint in a single request, either using arrays or aliases. Each query / mutation is then executed and a collection of results is returned in the response.

This can bypass rate limiting since instead of sending 1000 requests to the endpoint (for example), one request can be sent containing 1000 queries / mutations.
</details>

---

<details>
<summary><b>25. What is type juggling, and why does the JSON format help exploit these vulnerabilities?</b></summary>

Type juggling is a feature of certain programming languages where variables will be converted to a different type (e.g., string, integer, boolean) in certain operations, rather than throwing an exception. For example, when concatenating a string with an integer, the integer will be converted to a string.

This can however lead to vulnerabilities when preserving the type is important. The JSON format helps exploit these vulnerabilities as it supports a wide range of data types natively (numbers, strings, booleans, arrays, objects, and nulls), whereas regular URL/Body parameters often only support strings and arrays.
</details>

---

