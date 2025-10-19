# 
Web-AppSec-Interview-Questions  [![Awesome](https://cdn.jsdelivr.net/gh/sindresorhus/awesome@d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome#readme) 
This collection features challenging web application security questions originally shared through my social media channels. These questions are designed to test your knowledge of web application hacking concepts at an advanced level.

<details>
<summary><b>1. What is the difference between Web Cache Deception and Web Cache Poisoning?</b></summary>

**Web Cache Deception** involves finding a dynamic page that can be accessed via a URL a web cache will automatically cache (e.g., if `/transactions` can be accessed at `/transactions.jpg`). If an attacker can trick a victim into visiting the cacheable URL, they can then load the same URL and retrieve the victim's information from the cache.

**Web Cache Poisoning** involves finding an input that results in some exploitable change in the response but doesn't form part of the cache key for the request. When an attacker sends their payload, the exploited response will be cached and then delivered to anyone who accesses the page.
</details>

<details>
<summary><b>2. What two criteria must be met to exploit Session Fixation?</b></summary>

Session Fixation is not the same as Session Hijacking but rather a type of Session Hijacking attack. The two criteria are:

- Attacker must be able to forcibly set a (syntactically valid but otherwise inactive) session token in the victim's browser (e.g., using XSS / CRLF injection)
- Once the victim authenticates, the application uses the session token already present and does not set a new one
</details>

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

<details>
<summary><b>5. How does Boolean Error Inferential (Blind) SQL Injection work?</b></summary>

This is a variant where injecting "AND 1=1" and "AND 1=2" (for example) will return the same response! The trick is to purposefully cause a database error when a condition we want to test is true, and hope that error propagates back to the response somehow (e.g., a 500 Internal Server error).

Many ways to do this, but most use a CASE expression and some divide by zero if the condition is true. For example: `AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)`
</details>

<details>
<summary><b>6. What is the Same-Origin Policy (SOP) and how does it work?</b></summary>

The Same-Origin Policy is a security mechanism browsers use to prevent a variety of cross-origin attacks. The basic principle is that client-side app code can only read data from a specific URL if the URL has the same origin as the current app. Two URLs have the same origin if they share the same protocol, host, and port.

Note that reading and embedding data from URLs are treated differently, allowing applications to embed things like scripts, videos, images, etc. without actually being able to access the raw bytes of each.
</details>

<details>
<summary><b>7. How does the TE.TE variant of HTTP Request Smuggling work?</b></summary>

The TE.TE variant has two or more servers which always use the Transfer-Encoding header over the Content-Length header if both are present, which usually makes Request Smuggling impossible. However, by manipulating the Transfer-Encoding header, it is possible to cause one of the servers to not recognize it. This server will use the Content-Length header instead, allowing the Request Smuggling attack to work.

There are countless ways to manipulate the Transfer-Encoding header. Common ones are including whitespace before the colon, capitalization, or modifying the value "chunked" in the header itself.
</details>

<details>
<summary><b>8. What is DOM Clobbering and how can it be used to bypass (some) HTML sanitizers, resulting in XSS?</b></summary>

DOM Clobbering is a way to manipulate the DOM using only HTML elements (i.e., no JavaScript). By using the id or name attribute of some elements, it is possible to create global variables in the DOM. This can lead to XSS in some cases.

[DOM Clobbering Cheatsheet](https://example.com) (works best in Chrome)
</details>

<details>
<summary><b>9. Describe how HTTP Parameter Pollution could be used to bypass a Web Application Firewall.</b></summary>

Some servers will concatenate parameter values if two or more identical parameters exist in requests, though often with a separator (e.g., a comma). For certain payloads, WAF detection can sometimes be bypassed if the payload can be split across multiple parameters.
</details>

<details>
<summary><b>10. Describe IDOR and explain how mitigating it is different from other access control vulnerabilities.</b></summary>

Insecure Direct Object References occur when an application provides functionality to access a resource using some unique reference (e.g., an ID) but does not perform adequate access control checks to determine if the user should have access to the specific resource.

Generally, the user should be able to access the functionality, but not all resources via the functionality. Thus, mitigation involves an access check comparing the user to the specific resource being requested, as opposed to the functionality itself.
</details>

<details>
<summary><b>11. What are JWKs and JKUs and how does their usage differ in JWTs?</b></summary>

A JSON Web Key (JWK) is a JSON object representing a signing key in a JWT. A JSON Web Key Set URL (JKU) is a URL which points to the location of a set of JWKs. In a JWT, both JWKs and JKUs go in the header.

When using a JWK, the entire public key is embedded within the header, whereas a JKU can point to a set of multiple public keys. In both cases a key ID (kid) is used to select the key to be used.
</details>

<details>
<summary><b>12. In the context of web apps, what is Business Logic and how does testing for Business Logic vulnerabilities differ compared to (for example) XSS, SQLi, etc?</b></summary>

Business logic is code which mimics real-world business operations / decisions, rather than code which handles how a user interacts with the application. Testing for business logic vulnerabilities usually involves identifying and challenging assumptions the developer has made about how someone uses the application, rather than technical oversights involving how data is processed.

It is impossible to identify business logic flaws using current scanners, since they require an understanding of the purpose of the application and are highly contextual.
</details>

<details>
<summary><b>13. Describe 3 payloads you could use to identify a server-side template engine by causing an error message.</b></summary>

- **Invalid syntax**: `${{<%[%'"}}%\`
- **Divide by zero**: `${1/0}`
- **Invalid variable names**: `${tib3rius}`
</details>

<details>
<summary><b>14. What is the purpose of the Sec-WebSocket-Key header?</b></summary>

The "key" has nothing to do with security / encryption. Since WebSockets are created using an initial HTTP request, the Sec-WebSocket-Key header is used by the client to make sure the server supports WebSockets. If the client doesn't receive a correctly hashed version of the key from the server, it doesn't continue with the WebSocket setup.
</details>

<details>
<summary><b>15. What does the "unsafe-inline" value allow for if used in a script-src directive of a CSP?</b></summary>

"unsafe-inline" will allow all inline scripts (e.g., `<script>...</script>` and "onevent" attributes) to be executed, but will not allow the loading of scripts from other files, nor will it allow the use of `eval()` and other methods which allow the execution of JavaScript from strings.
</details>

<details>
<summary><b>16. Give an example of stateless authentication, and describe an inherent weakness of this authentication mechanism.</b></summary>

Authentication using a JWT is an example of stateless authentication. An inherent weakness of stateless authentication is the inability to forcibly expire user sessions, since all session information is stored on the client-side.
</details>

<details>
<summary><b>17. Describe 3 ways to mitigate Cross-Site Request Forgery.</b></summary>

- Setting the SameSite cookie attribute to Lax or Strict on session cookies can prevent this cookie being added to cross-site requests, making forged requests unauthenticated. There are some exceptions if Lax is used.
- Requiring Anti-CSRF Tokens to be submitted with vulnerable requests will prevent CSRF provided the tokens are unique, unpredictable, and are not (only) submitted in cookies.
- Another option is to check the Referer header of a request to ensure it matches a trusted origin.
</details>

<details>
<summary><b>18. What are XML parameter entities and what limitations do they have in XXE Injection?</b></summary>

XML parameter entities are referenced using a `%` instead of `&`, but can only be referenced within a DTD, not the main XML document. This limitation means that parameter entities are often only useful with out-of-band XXE techniques.
</details>

<details>
<summary><b>19. What recommendations would you give a customer for fixing DOM based XSS?</b></summary>

If possible, avoid passing untrusted inputs to potentially dangerous JavaScript functions. Checks should be implemented to ensure that values only include expected characters (as opposed to trying to detect bad characters). Encoding inputs is also a possibility.
</details>

<details>
<summary><b>20. What conditions must be met to prevent a browser from sending a CORS Preflight request?</b></summary>

- Only GET, HEAD, or POST methods are allowed
- Only the following headers can be manually set: Accept, Accept-Language, Content-Language, Content-Type, Range
- If Content-Type is set, it must use one of the following: application/x-www-form-urlencoded, multipart/form-data, text/plain
- If XMLHttpRequest was used, no event listener must be registered on the XMLHttpRequest.upload property
- No ReadableStream object was used
</details>

<details>
<summary><b>21. Describe 3 ways an Insecure Deserialization vulnerability could be exploited.</b></summary>

- Modifying the value of an object attribute
- Modifying the type of an object attribute
- Using a Magic Method to make calls to other functions/methods (potentially leading to RCE)
</details>

<details>
<summary><b>22. List the checks an application might perform to ensure files cannot contain malicious content, and can only be uploaded to specific directories.</b></summary>

- Only allowing files with certain extensions and mime-types to be uploaded
- Performing file analysis (to confirm the file type) and AV scans
- Performing path canonicalization before checking the end location of the file matches an allowed directory
</details>

<details>
<summary><b>23. How does Mass Assignment work and what are some potential outcomes of exploiting such a vulnerability?</b></summary>

Mass Assignment occurs when functionality allowing users to create or update "objects" does not restrict which attributes a user can specify. This is more common in modern MVC-type frameworks.

This can lead to attackers being able to "upgrade" their role (e.g., to admin), add money to an account balance, assign potentially negative resources to other users, or perform a log forging attack by modifying date values, as well as countless other attacks.
</details>

<details>
<summary><b>24. What is GraphQL batching and how can it be used to bypass rate limiting?</b></summary>

GraphQL batching allows a user to send multiple queries or mutations to a GraphQL endpoint in a single request, either using arrays or aliases. Each query / mutation is then executed and a collection of results is returned in the response.

This can bypass rate limiting since instead of sending 1000 requests to the endpoint (for example), one request can be sent containing 1000 queries / mutations.
</details>

<details>
<summary><b>25. What is type juggling, and why does the JSON format help exploit these vulnerabilities?</b></summary>

Type juggling is a feature of certain programming languages where variables will be converted to a different type (e.g., string, integer, boolean) in certain operations, rather than throwing an exception. For example, when concatenating a string with an integer, the integer will be converted to a string.

This can however lead to vulnerabilities when preserving the type is important. The JSON format helps exploit these vulnerabilities as it supports a wide range of data types natively (numbers, strings, booleans, arrays, objects, and nulls), whereas regular URL/Body parameters often only support strings and arrays.
</details>

<details>
<summary><b>26. Describe 3 techniques you might use to find sensitive data being exposed by an application.</b></summary>

There are of course far more than 3 techniques, and any of the following would count:
- Source code analysis
- Directory busting
- Causing errors / exceptions / stack traces by fuzzing
- Access control exploitation
- Google dorking
- Git repo history analysis
- Exploiting SQL injections
</details>
<details>
<summary><b>27. Describe the attributes of a request which make it effectively immune to CSRF (i.e. CSRF mitigation is not required).</b></summary>

Again there are a few possible answers here:
- If authentication uses an Authorization header and a non-trivial token (i.e. not Basic Auth), such as a JWT, or any kind of custom header with an unpredictable value
- If the server doesn't support CORS or has a locked down policy, and a non-standard HTTP method is used (e.g. PUT, DELETE), or the request body uses JSON/XML and requires an appropriate Content-Type
- If the request relies on a "secret" value which effectively becomes an anti-CSRF token. For example, login requests are immune to CSRF because if the attacker knows the victim's credentials, they don't even need to perform a CSRF attack*

*There are some rare edge cases where performing a CSRF attack against a login, despite knowing the victim's credentials, would be useful
</details>
<details>
<summary><b>28. What are 3 negative outcomes (i.e. bad for the tester) that could arise if "OR <true>" (or similar) is relied on for SQL injection testing?</b></summary>

I've ranted about this before.
- OR <true> can return all rows of a table, which could cause server issues if the table is large
- OR <true> can lead to false positives when testing for login bypasses, if the login expects only one row be returned for a valid login attempt
- OR <true> injected into an UPDATE or DELETE statement can be disastrous
</details>
<details>
<summary><b>29. Name 5 vulnerabilities which could potentially lead to OS command execution on a web app.</b></summary>

There are quite a few ways, though several are rare or require highly specific setups to work:
- OS Command Injection
- Insecure Deserialization
- Server-Side Template Injection
- File Upload Vulnerabilities
- File Inclusion Vulnerabilities
- Server-Side Prototype Pollution
- Code Injection
- SQL Injection
- XXE
</details>
<details>
<summary><b>30. What is prototype pollution, and what exploits could it lead to with both client / server-side variants?</b></summary>

Prototype Pollution is a JavaScript / NodeJS vulnerability that allows attackers to add properties to global object prototypes, which are then passed down to actual objects used in the application.

In client-side JS this can lead to DOM XSS. With server-side JS (e.g. NodeJS), it can lead to access control bypasses as well as potential RCEs.
</details>
<details>
<summary><b>31. Describe how you would test for Vertical Access Control vulnerabilities on an application with 20 roles and 300+ different "functional" requests.</b></summary>

While a manual effort is possible, the best way to do this is via some form of guided automation. In Burp Suite, the Auth Analyzer extension can be used to track multiple sessions (one for each role) and replay each request with updated session tokens, comparing the response to the original.

For the brave, the AuthMatrix extension allows for more complex automation, and can handle logging users in, tracking anti-CSRF tokens, etc. Access rules can be configured per request/role pair, and the entire setup can be saved and replayed at a later date to validate fixes.
</details>
<details>
<summary><b>32. Under what circumstances is a tab's Session Storage instance preserved?</b></summary>

A tab's Session Storage instance is preserved if the page is reloaded, or if the user browses to another origin in the tab and later returns. If the user closes the tab, the instance is still preserved, provided the browser has the ability to reopen tabs.

In some browsers, Session Storage for tabs is preserved if the browser instance crashes rather than exiting cleanly, allowing users to resume their browsing session.
</details>
<details>
<summary><b>33. Other than uploading XML via a form, how else might one find and exploit XXE?</b></summary>

Many file formats use XML as a base and may trigger XXE if parsed insecurely. Examples include SVG, Microsoft documents (e.g. docx, xlsx), and other markup languages like KML.

In addition, SOAP services use XML-formatted requests. In some cases, APIs which default to JSON-formatted inputs will also accept the same inputs as XML.
</details>
<details>
<summary><b>34. Name some common password reset flow vulnerabilities.</b></summary>

- Basing the password reset on a user identifier (e.g. username) rather than a secret token
- Using host header injection to modify password reset links in emails in order to steal the token
- Easily guessable password reset tokens (bonus if they don't expire quickly / once used)
- Using security questions instead of a secret token to authenticate the user
- Username enumeration based on password reset success messages
</details>
<details>
<summary><b>35. What is the difference between encoding, encryption, and hashing?</b></summary>

**Encoding** is the process of transferring data from one format to another while preserving the integrity of the data. If the encoding algorithm is known, anyone can decode the original data.

**Encryption** is the process of scrambling data so that it can only be read by someone with the correct decryption key. Even if the encoding algorithm is known, unauthorized users will not be able to decrypt the data.

**Hashing** is the process of converting data into a number (aka hash) of fixed size (e.g. 256 bits), such that the same data results in the same number. This can be used to verify a user knows the initial data without needing to know the data itself (e.g. a password for a login). The process is irreversible, and in good hashing algorithms, it should be difficult to find two sets of data which result in the same hash.
</details>
<details>
<summary><b>36. Name some ways an attacker might exploit an HTTP Request Smuggling vulnerability.</b></summary>

- Forcing a victim to trigger an XSS payload, including "unexploitable" payloads such as those contained within a UserAgent header
- Using some form of "save" functionality in the application to capture a victim's request, extracting their session token and hijacking their account
- Bypassing front-end access controls by smuggling a request to a disallowed area onto one of our own requests
</details>
<details>
<summary><b>37. What is Server-Side Request Forgery and how can it be detected & exploited?</b></summary>

Server-Side Request Forgery (SSRF) occurs when an attacker can cause a server at the back-end of the application to make a "request" to a target it would not normally request from.

It can be detected by looking for parameters which contain references to URLs, hostnames, or file paths, and attempting to manipulate these parameters to see if a request is made to a server we control, or to some backend service we can detect.

SSRF can often be exploited to retrieve files from within the environment, perform basic port scanning, leak information from request headers, execute code, and even deliver XSS payloads.
</details>
<details>
<summary><b>38. Name some ways TLS / SSL can be misconfigured.</b></summary>

- Outdated Protocols (e.g. SSLv3, TLSv1.0)
- Insecure Private Key Sizes
- Incomplete Certificate Chains
- Expired / Revoked Certificates
- Insecure Cipher Suites
- Lack of Forward Secrecy
- Insecure Key Exchange Algorithms
- Insecure Client-Initiated Renegotiation
</details>
<details>
<summary><b>39. Give some reasons why sending sensitive data in a URL query parameter is insecure.</b></summary>

- URLs are generally logged, by both the server and potentially proxy services in-between the user and application
- URLs are also saved to browser history, which may be preserved on shared public computers
- The data may be visible in screenshots and screen shares
- Users may think it is safe to copy URLs and share them
- If 3rd party resources are loaded by the client-side application, the data may get sent as part of the Referer header to the 3rd party
</details>
<details>
<summary><b>40. In what ways could an open redirect be exploited?</b></summary>

- A victim could be redirected to a malicious copy of the site and not notice, since the original URL was for the legitimate site
- If chained with an SSRF, it could be used to bypass URL validation and reach otherwise prohibited targets
- If chained with a misconfigured OAuth setup, it could be used to steal access tokens
- If the redirect uses the Location response header, we may be able to perform CRLF injection
</details>
<details>
<summary><b>41. Describe two output encoding techniques and the context in which they should be used to mitigate Cross-site Scripting.</b></summary>

- **Encoding for HTML contexts** involves converting the following characters into HTML entities: & < > " '
- **Encoding for HTML attribute contexts** is the same, provided all attribute values are quoted correctly. If not, all non-alphanumeric characters should be converted to HTML entities
- **Encoding for JavaScript contexts** involves converting all non-alphanumeric characters into the Unicode encoding format (e.g. \u0022)
</details>
<details>
<summary><b>42. Describe three "403 Forbidden" bypass techniques.</b></summary>

- Using different HTTP methods (e.g. POST instead of GET), or using "method override" headers / URL parameters (e.g. X-HTTP-Method) if a back-end server supports them
- Using "Client Origin" HTTP headers (e.g. X-Forwarded-For) to forge our source IP address, bypassing IP-based blocklists
- Manipulating the URL path using directory traversal, case modification, adding characters, or double-URL encoding
</details>
<details>
<summary><b>43. Describe some potential CAPTCHA weaknesses.</b></summary>

- Replay attacks - using a previously confirmed correct answer
- Improper input validation - removing or blanking CAPTCHA-related parameters
- Leaked answers - the correct answer appears somewhere in the source code (I once found a CAPTCHA which worked by using CSS to distort text)
- Low entropy - if the set of possible answers is too small, a brute-force attack may work
- Machine learning susceptible - with enough training data, a computer can solve the CAPTCHA
</details>
<details>
<summary><b>44. You find XSS in an application, however the customer informs you that users should be able to submit HTML code. What advice would you give them to remain secure?</b></summary>

The easiest solution is likely to use an HTML sanitizer like DOMPurify with an allowlist of "safe" elements and attributes.

Another option is to use a separate "sandbox" domain to host the HTML code, displaying it using an iframe. Any JavaScript code will run in the security context of the sandbox and will not be able to affect the main application.

As an additional measure, a well-configured Content Security Policy can be used to instruct the browser to only run trusted JavaScript code.
</details>
<details>
<summary><b>45. What are some questions you would ask a customer during a web app pentest scoping call?</b></summary>

Many questions would depend on a demo of the application, however here are a few general ones:
- How much functionality does the app contain (e.g. no. of "pages")?
- How complex is the functionality (e.g. any learning curves, lengthy processes, etc.)?
- How many different roles are there / should be tested?
- Which environment is being tested (e.g. dev, staging, prod)?
- Do our accounts have access to test/dummy data?
- Are there any access restrictions (e.g. VPN, IP block)?
- Are there any custom protocols being used (e.g. proprietary encoding/encryption)?
- Is there any rate limiting, WAF/IPS in place?
- Are there any out of scope areas, or vulnerabilities which should not be tested (e.g. Denial of Service)?
</details>
<details>
<summary><b>46. How would you recommend a customer fix an Insecure Deserialization vulnerability?</b></summary>

- If possible, don't pass serialized data via user inputs at all
- Use "safe" serialization methods (e.g. JSON, Protobuf)
- Digitally sign any serialized data, and verify the signature prior to deserializing it
- If applicable, perform type checks against deserialized data prior to using it
</details>
<details>
<summary><b>47. Name some user account enumeration techniques.</b></summary>

- Error/success messages on login / registration / forgot password pages
- Insecure Direct Object References
- Timing Attacks (e.g. login)
- Excessive data exposure on APIs (e.g. /v1/users)
</details>
<details>
<summary><b>48. Name some techniques to detect blind/inferential command injection vulnerabilities.</b></summary>

- Trying commands with noticeable time delays, like sleep on *nix, or ping on *nix/Windows
- Attempting to redirect the command output into a file in the webroot (if we know / can guess the directory)
- Trying commands which perform some detectable network interaction, like a DNS lookup (dig, host, nslookup) or HTTP request (curl, wget)
</details>
<details>
<summary><b>49. What are some types of race condition vulnerabilities in web applications?</b></summary>

- Limit overrun - performing more actions than allowed (e.g. redeeming gift cards, transferring money)
- State changes - bypassing a state change within normal application flow (e.g. a MFA step during login)
- Resource access - accessing a shared resource prior to / during the processing of the resource (e.g. uploading and accessing a malicious file prior to AV detection)
</details>
<details>
<summary><b>50. How does NoSQL Injection differ from SQL Injection?</b></summary>

Other than the obvious (NoSQL injection affects NoSQL databases, not SQL databases), NoSQL injection is often highly dependent on the database variant and application programming language. Unlike SQL, there is no single standardized query language.

NoSQL is also vulnerable to operator injection, which unlike regular syntax injection, can change the original nature of conditional checks in the query.

Some NoSQL databases support the execution of arbitrary JavaScript code.
</details>
<details>
<summary><b>51. Describe the syntax of an HTTP request.</b></summary>

You can go into a lot of detail here, but here's a basic answer that hits all the key points:

An HTTP request starts with a request line, which includes 3 parts separated by a single space: the request method / verb (e.g. GET), the request URI, and the HTTP version. The request line is terminated by a CRLF linebreak. After this, there are a series of headers which are optional apart from the Host header (in v1.1 and above). Each header is comprised of a name, colon, value, and finally a CRLF linebreak. After the final header, there is an empty line (i.e. a CRLF), and an optional body. If a body is included, its format and length is determined by information provided in the headers.
</details>
<details>
<summary><b>52. Name some potential attacks against JWTs.</b></summary>

- Lack of signature verification
- "none" algorithm support
- Accepting embedded / remote signing keys
- Brute-forcing weak keys
- Algorithm confusion
</details>
<details>
<summary><b>53. Describe the process of finding and exploiting a web cache poisoning issue.</b></summary>

- Identify unkeyed inputs (usually header / cookie values) using a tool like Param Miner
- Test identified inputs for client-side vulnerabilities (e.g. XSS, Open Redirect)
- Send the payload to the server multiple times until it is cached by the web cache
- Verify the exploit by sending the request without the unkeyed input to see if the payload gets returned
</details>
<details>
<summary><b>54. Describe the process of finding and exploiting a Server-Side Template Injection.</b></summary>

- Identify inputs which may end up in templates (either reflected or stored values)
- Use a polyglot payload like ${{<%[%'"}}%\ to try and generate template errors
- Use several different arithmetic payloads (e.g. ${7*7}, {{7*7}}, <%=7*7%>) to try and detect / verify the version of the templating engine
- Check for known exploits of the templating engine for reading/writing files or performing OS command execution
</details>
<details>
<summary><b>55. What is formula injection and how might it be exploited?</b></summary>

Formula injection, also known as "CSV Injection" occurs when an attacker can insert Excel-like formula (e.g. =1+1) into an application's CSV export functionality. Since most CSV files are opened in an Excel-like program, the formula will execute instead of displaying the raw data.

This can be exploited by including a malicious formula which executes OS commands, for example the following which opens notepad.exe:
`=cmd|'/C notepad'!A1`

Other exploits can include data exfiltration via clickable links or DNS lookups.

Formula injection is a relatively controversial vulnerability, since the actual exploitation takes place entirely on the victim's computer, and not within their browser (like XSS). In addition, multiple warning popups generally appear when a user opens a document containing executable payloads, and the user must "willingly" enable their functionality.

However, several instances of server-side formula injection exist, where these limitations may not apply. This includes both cloud-hosted spreadsheets (e.g. Google Sheets) and backend processes which use Excel to process documents.
</details>
<details>
<summary><b>56. What are some common OAuth 2.0 flaws & misconfigurations?</b></summary>

- Insecure implementation of the implicit grant type
- Cross-Site Request Forgery (insecure state parameter)
- Session hijacking via redirection (e.g. redirect_uri)
- Improper scope validation
</details>
<details>
<summary><b>57. Describe the CL.0 variant of HTTP Request Smuggling and how it differs from standard variants (e.g. CL.TE).</b></summary>

CL.0 request smuggling occurs when a back-end server will ignore the Content-Length header in certain instances, while the front-end server uses it. This allows a second request to be smuggled in the first's body.

This differs from standard variants since the Transfer-Encoding header is never used, hence the name CL.0 instead of CL.TE.
</details>
<details>
<summary><b>58. Name some potential ways to exploit HTML Injection.</b></summary>

Assuming we discount traditional XSS, which is often treated as a separate vulnerability, there are several:
- Social engineering via injected links / redirects
- Denial of service via broken layouts
- SSRF / LFI via PDF generation
- Potentially stealing passwords (https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp)
- Exfiltrating potentially sensitive data via dangling markup
- XSS via DOM Clobbering
</details>
<details>
<summary><b>59. Describe some methods for bypassing SSRF detection filters.</b></summary>

- Use different IP address representations (e.g. decimal, hex)
- Use DNS to resolve a domain to a target IP address
- Abuse open redirects and (double) URL encoding
- Abuse lax URL validation / parser confusion (e.g. using valid-host@attacker-host or attacker-host#valid-host, etc.)
</details>
<details>
<summary><b>60. Describe different ways a PHP include() could be exploited to gain code execution.</b></summary>

- Writing PHP code to a local file and including it via absolute paths, directory traversal, or the file:// scheme
- Hosting PHP code remotely and including it using http://, ftp://, etc. schemes
- Using php://input to read and execute raw PHP code from a POST request body
- Using PHP filter (php://filter) chains to create executable PHP code
- Using the data:// scheme to pass raw PHP code as plain text, or as a Base64 encoded string
</details>
<details>
<summary><b>61. Explain how CRLF Injection works and describe possible ways it could be exploited.</b></summary>

CRLF (Carriage Return, Line Feed) injection occurs when it is possible to inject those characters (\r\n) into a response header, allowing the attacker to create new lines.

CRLF Injection can be used to create Set-Cookie headers, causing cookies to be created in the victim's browser. This is one criterion for a Session Fixation attack.

If the attacker can inject multiple \r\n and affect the response body, they may be able to perform XSS, redirect the user off-site, or attempt a social engineering attack.
</details>

