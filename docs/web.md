# Web Exploitation Wiki

## Overview of Web Application Security
Web Application Security is a specialized area within Information Security that focuses on safeguarding websites, web applications, and web services. It leverages application security principles specifically for the web, ensuring the integrity, confidentiality, and availability of web applications.

## Understanding Security Threats
A security threat is a potential risk that could exploit vulnerabilities in a computer system, leading to unauthorized access or damage. These threats can be intentional, such as cyber-attacks, or accidental, such as system failures or natural disasters.

### Common Security Threats

- **Virus Threats**: Viruses are malicious software programs designed to infect legitimate software, corrupt data, and modify the way applications operate without the user's consent.

- **Hackers and Predators**: The human element behind threats, hackers use their technical expertise to bypass security measures and gain unauthorized access to computer systems.

- **Phishing**: A technique used to deceive users into providing sensitive information by masquerading as a trustworthy entity in digital communication.

### The OWASP Top 10 Vulnerabilities
The Open Web Application Security Project (OWASP) identifies the most critical web application security risks. Key vulnerabilities include Injection, Broken Authentication, Sensitive Data Exposure, XML External Entities (XXE), Broken Access Control, Security Misconfiguration, Cross-Site Scripting (XSS), Insecure Deserialization, Using Components with Known Vulnerabilities, and Insufficient Logging & Monitoring.

## Web Development and Security Tools

### Client-Side Technologies
- **HTML**: The standard markup language for creating web pages.
- **JavaScript**: A programming language that enables interactive web pages.
- **CSS**: A style sheet language used for describing the presentation of a document written in HTML or XML.
- **jQuery**: A fast, small, and feature-rich JavaScript library.

### Server-Side Languages
- **PHP**
- **JavaScript (Node.js)**
- **Ruby**
- **Python**

### Important Web Mechanisms
- **Cookies and Sessions**: Essential for managing user sessions and storing user preferences.
- **HTTP Headers and Requests**: Fundamental components of the HTTP protocol that facilitate client-server communication.
- **HTTP Methods**: GET, POST, PUT, DELETE, CONNECT, HEAD, OPTIONS, TRACE, PATCH, each serving a specific purpose in HTTP transactions.

### Developer Tools
Modern browsers include developer tools for debugging and testing web applications, offering features like JavaScript debugging, network analysis, and DOM manipulation.

## Vulnerabilities and Exploits


---

# Comprehensive Guide to In-Depth Web Exploitation Learning

This guide consolidates knowledge on various web exploitation techniques. Each section covers a specific vulnerability, including resources, types of solutions, and common attack methods.

---



For more advanced topics, practical exercises, and essential tools, the guide includes sections on:

- **Local File Inclusion (LFI) to RCE**
- **CSRF (Cross-Site Request Forgery)**
- **Directory Traversal**
- **WebSocket Security**
- **Session Hijacking**
- **Subdomain Takeover**
- **SSRF (Server-Side Request Forgery)**
- **Deserialization Vulnerabilities**
- **API Security**


This guide provides a structured approach to mastering web exploitation techniques. Engage in CTF

 challenges, contribute to open-source projects, and stay updated with the latest security trends and tools.

### Quick Links
- [HackTricks](https://book.hacktricks.xyz/)
- [OWASP](https://owasp.org/)
- [The Odin Project](https://www.theodinproject.com/)
- [JWT.io](https://jwt.io/)
- [TryHackMe](https://tryhackme.com/)
- [Hack The Box](https://www.hackthebox.eu/)
- [HackerOne](https://www.hackerone.com/)
- [Burp Suite](https://portswigger.net/burp)
- [Wireshark](https://www.wireshark.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

--- 


Here’s a detailed breakdown of each web exploitation challenge format including challenge type, resources, solution types, and potential attacks.

---

### 1. **Reverse Shell Exploitation**

- **Challenge Type**: Reverse Shell Access
- **Resources**:
  - [Pentestmonkey Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
  - [Netcat Guide for Reverse Shells](https://null-byte.wonderhowto.com/how-to/use-netcat-like-pro-hack-with-best-of-them-0160467/)
- **Types of Solutions**:
  - **Direct Shell Invocation**: Using `bash`, `nc`, or `Python` commands to redirect shell input/output to an attacker's server.
  - **Payload Embedding**: Injecting shell commands in vulnerable applications to initiate a reverse shell connection.
- **Attacks**:
  - **Command Injection**: Embedding reverse shell commands in web forms or URL parameters.
  - **File Upload**: Uploading scripts that execute reverse shells, allowing attackers to control the server remotely.

---

### 2. **Cross-Site Scripting (XSS)**

- **Challenge Type**: Client-Side Injection (DOM-based, Reflected, Stored)
- **Resources**:
  - [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
  - [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- **Types of Solutions**:
  - **Client-Side Filtering**: Using libraries like DOMPurify for sanitizing inputs.
  - **Server-Side Input Validation**: Stripping or encoding dangerous characters.
- **Attacks**:
  - **Session Hijacking**: Injecting scripts to steal cookies and impersonate users.
  - **Malware Distribution**: Redirecting users to download malicious files.
  - **Phishing**: Creating fake login forms within the website to capture user credentials.

---

### 3. **SQL Injection (SQLi)**

- **Challenge Type**: SQL Database Manipulation
- **Resources**:
  - [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
  - [HackTricks SQL Injection Techniques](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- **Types of Solutions**:
  - **Parameterized Queries**: Avoiding dynamic query concatenation and using prepared statements.
  - **Escaping Inputs**: Using functions like `mysqli_real_escape_string()` to sanitize inputs.
- **Attacks**:
  - **Database Dump**: Extracting data from the database by injecting `UNION SELECT` or `INFORMATION_SCHEMA` queries.
  - **Authentication Bypass**: Manipulating authentication queries to gain unauthorized access.
  - **Blind SQL Injection**: Extracting data by observing server responses without seeing the database output.

---

### 4. **File Upload Vulnerabilities**

- **Challenge Type**: Unrestricted File Upload
- **Resources**:
  - [OWASP Unrestricted File Upload Guide](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
  - [PortSwigger File Upload Labs](https://portswigger.net/web-security/file-upload)
- **Types of Solutions**:
  - **Content-Type Validation**: Checking for acceptable file types (e.g., `.jpg`, `.png`).
  - **Filename Restrictions**: Preventing executable file uploads with `.php`, `.js`, etc.
- **Attacks**:
  - **Web Shell Upload**: Uploading a PHP or ASP file to execute commands.
  - **Malware Distribution**: Hosting malicious files on the server for unsuspecting users to download.
  - **Remote Code Execution (RCE)**: Using uploaded files to run arbitrary code on the server.

---

### 5. **Server-Side Template Injection (SSTI)**

- **Challenge Type**: Template Engine Manipulation
- **Resources**:
  - [HackTricks SSTI Exploitation](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
  - [PortSwigger Template Injection Labs](https://portswigger.net/web-security/server-side-template-injection)
- **Types of Solutions**:
  - **Escape User Input**: Avoid embedding user-controlled variables in templates.
  - **Input Filtering**: Strip out special characters and dangerous input patterns.
- **Attacks**:
  - **Code Execution**: Injecting code that the template engine evaluates (e.g., `{{7*7}}`).
  - **File Access**: Using template syntax to read files (e.g., `{{ open('/etc/passwd').read() }}`).
  - **Data Leakage**: Accessing server-side data through template variables.

---

### 6. **Cross-Origin Resource Sharing (CORS) Misconfiguration**

- **Challenge Type**: CORS Policy Manipulation
- **Resources**:
  - [OWASP CORS Misconfiguration Guide](https://owasp.org/www-community/attacks/CORS_Misconfiguration)
  - [PortSwigger CORS Labs](https://portswigger.net/web-security/cors)
- **Types of Solutions**:
  - **Proper Policy Definition**: Setting allowed origins and headers correctly.
  - **Avoid Wildcards**: Restricting access to trusted origins only.
- **Attacks**:
  - **Data Theft**: Accessing sensitive data through unauthorized CORS requests.
  - **Session Hijacking**: Sending unauthorized requests from a malicious site.
  - **Credential Theft**: Leveraging CORS to trick users into exposing credentials.

---

### 7. **GraphQL Injection**

- **Challenge Type**: GraphQL Query Manipulation
- **Resources**:
  - [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
  - [PortSwigger GraphQL Security Labs](https://portswigger.net/web-security/graphql)
- **Types of Solutions**:
  - **Query Limitations**: Limit query depth and restrict nested queries.
  - **Access Control**: Ensure users can only query data they are authorized to see.
- **Attacks**:
  - **Data Enumeration**: Using queries like `__schema` to map database structures.
  - **Sensitive Data Exposure**: Accessing restricted data by exploiting weak authorization.
  - **Denial of Service (DoS)**: Crafting overly complex queries to overload the server.

---

### 8. **DNS Exfiltration**

- **Challenge Type**: Data Exfiltration through DNS Requests
- **Resources**:
  - [OWASP DNS Exfiltration Guide](https://owasp.org/www-community/attacks/DNS_Exfiltration)
  - [SANS DNS Data Exfiltration](https://www.sans.org/blog/dns-data-exfiltration-techniques/)
- **Types of Solutions**:
  - **Monitor DNS Traffic**: Use IDS/IPS to detect unusual patterns.
  - **Restrict DNS Resolution**: Limit outgoing DNS requests to trusted domains.
- **Attacks**:
  - **Data Leakage**: Encoding sensitive data in DNS queries to an attacker-controlled domain.
  - **C2 Communication**: Using DNS as a covert channel to control malware.
  - **Credential Theft**: Extracting passwords or tokens through DNS requests.

---

### 9. **Hashcat for Password Cracking**

- **Challenge Type**: Brute-Forcing Password Hashes
- **Resources**:
  - [Hashcat Documentation](https://hashcat.net/hashcat/)
  - [Cracking Passwords with Hashcat](https://www.4armed.com/blog/using-hashcat-crack-passwords/)
- **Types of Solutions**:
  - **Dictionary Attack**: Using known password lists (e.g., rockyou.txt).
  - **Hybrid Attack**: Combining dictionary words with appended characters.
- **Attacks**:
  - **Credential Recovery**: Recovering passwords from hashes to access accounts.
  - **Hash Cracking**: Decrypting sensitive information stored as hashes.
  - **Authentication Bypass**: Using cracked hashes to impersonate users.

---

### 10. **Command Injection (HTMX)**

- **Challenge Type**: HTMX Command Injection
- **Resources**:
  - [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
  - [PortSwigger Command Injection Labs](https://portswigger.net/web-security/os-command-injection)
- **Types of Solutions**:
  - **Sanitize Input**: Avoid executing user input directly as commands.
  - **Whitelist Commands**: Allow only safe commands or arguments.
- **Attacks**:
  - **Remote Code Execution (RCE)**: Gaining shell access to the server.
  - **Privilege Escalation**: Executing commands to gain higher access levels.
  - **Data Manipulation**: Modifying system files or configurations.

---

#### 11. **AWS IAM Metadata Enumeration**

- **Challenge Type**: AWS Metadata Information Leakage
- **Resources**:
  - [AWS Metadata Service Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
  - [SSRF and AWS Metadata](https://portswigger.net/web-security/ssrf/exploiting-ssrf-to-access-aws-instance-metadata)
- **Types of Solutions**:
  - **Metadata Filtering**: Ensure metadata endpoints are accessible only from secure sources.
  - **Restrict SSRF**: Use firewalls and IAM policies to prevent SSRF attacks on metadata.
- **Attacks**:
  - **Credential Exposure**: Retrieve IAM credentials via `http://169.254.169.254` endpoint.
  - **Privilege Escalation**: Use IAM tokens to access other AWS resources improperly.

---

#### 12. **AWS S3 Versioning Exploitation**

- **Challenge Type**: Access and Manipulation of S3 Object Versions
- **Resources**:
  - [AWS S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)
  - [S3 Security Best Practices](https://aws.amazon.com/s3/security/)
- **Types of Solutions**:
  - **Access Control Lists (ACLs)**: Ensure only authorized users can access versioned objects.
  - **Restrict Bucket Access**: Limit public access and enforce MFA for sensitive objects.
- **Attacks**:
  - **Data Tampering**: Access older or sensitive versions to compromise integrity.
  - **Unauthorized Access**: Exploit publicly available S3 buckets to retrieve data.

---

#### 13. **Brute-Forcing with Pwntools**

- **Challenge Type**: Password Guessing via Brute-Force
- **Resources**:
  - [Pwntools Documentation](https://docs.pwntools.com/en/stable/)
  - [Brute-Force Attack Techniques](https://owasp.org/www-community/attacks/Brute_force_attack)
- **Types of Solutions**:
  - **Rate Limiting**: Implement a delay or restrict repeated attempts.
  - **Captcha Verification**: Use captchas to prevent automated attempts.
- **Attacks**:
  - **Password Cracking**: Systematically try passwords until the correct one is found.
  - **Credential Stuffing**: Use common passwords or leaked passwords from other breaches.

---

#### 14. **Replay Attack with Multi-Processing**

- **Challenge Type**: Replay Attack Simulation
- **Resources**:
  - [OWASP Replay Attacks](https://owasp.org/www-community/attacks/Replay_Attack)
  - [Mitigating Replay Attacks](https://owasp.org/www-project-cheat-sheets/cheatsheets/Authentication_Cheat_Sheet.html#replay-protection)
- **Types of Solutions**:
  - **Nonce Usage**: Require unique nonces for each request to prevent reuse.
  - **Timestamp Verification**: Expire old requests by checking timestamps.
- **Attacks**:
  - **Session Reuse**: Capture and reuse valid sessions or tokens.
  - **Data Manipulation**: Repeat actions (like transfers) multiple times without detection.

---

#### 15. **Endianness Conversion**

- **Challenge Type**: File Manipulation and Byte Reordering
- **Resources**:
  - [Endianness Explained](https://en.wikipedia.org/wiki/Endianness)
  - [Data Manipulation with Python](https://docs.python.org/3/library/struct.html)
- **Types of Solutions**:
  - **Standardize Byte Order**: Ensure data is interpreted correctly by converting to a uniform endianness.
- **Attacks**:
  - **File Corruption**: Use endianness manipulation to corrupt data.
  - **Malicious Payload Injection**: Reorder bytes to execute unexpected commands on certain systems.

---

#### 16. **Hash Length Extension Attack**

- **Challenge Type**: Hash Manipulation and Extension
- **Resources**:
  - [Hash Length Extension Attacks](https://crypto.stackexchange.com/questions/16689/what-is-the-length-extension-attack)
  - [OWASP Hashing Guidelines](https://owasp.org/www-project-cheat-sheets/cheatsheets/Password_Storage_Cheat_Sheet.html)
- **Types of Solutions**:
  - **Use HMACs**: Ensure secure hash functions like HMAC to prevent hash manipulation.
- **Attacks**:
  - **Hash Forgery**: Append data to an existing hash and compute a valid signature.
  - **Data Tampering**: Modify messages without invalidating their hash.

---

#### 17. **Image Manipulation with PIL**

- **Challenge Type**: Image Generation and Coordinate Mapping
- **Resources**:
  - [Pillow (PIL) Documentation](https://pillow.readthedocs.io/en/stable/)
  - [Python Data Visualization with PIL](https://www.geeksforgeeks.org/python-pil-imagedraw-draw-point-using-xy/)
- **Types of Solutions**:
  - **Data Masking**: Hide coordinates or sensitive information before plotting.
  - **Coordinate Verification**: Ensure that image coordinates do not reveal sensitive locations.
- **Attacks**:
  - **Location Disclosure**: Extract sensitive location data from plotted coordinates.
  - **Data Exposure**: Generate images that reveal private data through visual cues.

---

#### 18. **PBKDF2 Key Derivation and Cracking**

- **Challenge Type**: Hash Cracking with PBKDF2
- **Resources**:
  - [PBKDF2 Key Derivation Function](https://en.wikipedia.org/wiki/PBKDF2)
  - [OWASP Password Storage](https://owasp.org/www-project-cheat-sheets/cheatsheets/Password_Storage_Cheat_Sheet.html)
- **Types of Solutions**:
  - **Increase Iterations**: Use a high iteration count to slow down cracking.
  - **Salt Uniquely**: Add unique salts for each password to make cracking harder.
- **Attacks**:
  - **Password Cracking**: Derive passwords from stored PBKDF2 hashes.
  - **Dictionary Attacks**: Use known password lists to crack hashes with common patterns.

---

#### 19. **Pickle Deserialization Exploitation**

- **Challenge Type**: Insecure Deserialization with Pickle
- **Resources**:
  - [Python Pickle Module Documentation](https://docs.python.org/3/library/pickle.html)
  - [Insecure Deserialization Attacks](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- **Types of Solutions**:
  - **Avoid Pickle**: Use safer serialization methods like JSON.
  - **Input Validation**: Validate and sanitize data before deserializing.
- **Attacks**:
  - **Remote Code Execution**: Execute arbitrary commands during deserialization.
  - **Data Leakage**: Access and exfiltrate sensitive data using malicious objects.

---

#### 20. **SQL Injection with Substring Bruteforce**

- **Challenge Type**: SQL Injection with LIKE Brute-Forcing
- **Resources**:
  - [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
  - [OWASP SQL Injection Prevention](https://owasp.org/www-project-cheat-sheets/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- **Types of Solutions**:
  - **Parameterized Queries**: Prevent SQL injection by avoiding direct string concatenation.
  - **Input Sanitization**: Escape dangerous characters and enforce strict input validation.
- **Attacks**:
  - **Credential Stealing**: Extract credentials by brute-forcing individual characters.
  - **Database Dumping**: Leak database contents by incrementally guessing values.

---

#### 21. **SQL Injection with Substring Brute-Force**

- **Challenge Type**: SQL Injection with Substring Brute-Forcing
- **Resources**:
  - [SQL Injection Guide - OWASP](https://owasp.org/www-community/attacks/SQL_Injection)
  - [SQL Injection Cheat Sheet - PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- **Types of Solutions**:
  - **Parameterization**: Use parameterized queries to avoid direct SQL query construction.
  - **Rate Limiting**: Limit repeated attempts to avoid brute-force attacks on individual characters.
- **Attacks**:
  - **Credential Extraction**: Retrieve sensitive information by brute-forcing characters of values like passwords.
  - **Database Dumping**: Slowly gather table data by iterating through substrings.

---

#### 22. **WebSocket Manipulation and Data Streaming**

- **Challenge Type**: WebSocket Data Manipulation
- **Resources**:
  - [WebSocket Documentation - MDN](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
  - [Real-Time WebSocket Exploits - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/websocket)
- **Types of Solutions**:
  - **Event Filtering**: Ensure only authorized data is processed by WebSocket listeners.
  - **Input Validation**: Prevent data tampering by sanitizing data before handling WebSocket events.
- **Attacks**:
  - **Data Manipulation**: Use WebSocket to modify and transmit crafted data.
  - **Information Disclosure**: Leak server or user information via crafted messages sent over WebSocket.

---

#### 23. **Character Brute-Forcing for Flag Extraction**

- **Challenge Type**: Character-by-Character Brute-Force for Secrets
- **Resources**:
  - [Brute-Force Techniques - OWASP](https://owasp.org/www-community/attacks/Brute_force_attack)
  - [Pentesting Firebase for Secrets](https://book.hacktricks.xyz/pentesting-web/firebase-database)
- **Types of Solutions**:
  - **Input Throttling**: Limit the rate of requests to prevent brute-force attempts.
  - **Access Restriction**: Ensure that sensitive endpoints aren’t accessible to unauthorized users.
- **Attacks**:
  - **Secret Discovery**: Reveal flags or sensitive strings by iteratively testing character combinations.
  - **Credential Exposure**: Expose user credentials by discovering password characters sequentially.

---

#### 24. **Converting curl to SQLMap Commands**

- **Challenge Type**: Automating SQL Injection Testing with SQLMap
- **Resources**:
  - [SQLMap Documentation](https://sqlmap.org/)
  - [Uncurl Documentation - Python](https://github.com/spulec/uncurl)
- **Types of Solutions**:
  - **Automated Scanning**: Utilize SQLMap to automate SQL injection testing.
  - **String Sanitization**: Validate and sanitize inputs before converting them into commands.
- **Attacks**:
  - **Database Compromise**: Leverage SQLMap to automatically probe for SQL injection points.
  - **Data Exfiltration**: Dump databases using SQLMap to uncover stored information.

---

#### 25. **Google Cloud Storage Blob Downloader**

- **Challenge Type**: Google Cloud Storage Enumeration and Download
- **Resources**:
  - [Google Cloud Storage Documentation](https://cloud.google.com/storage/docs)
  - [Google Cloud Security Best Practices](https://cloud.google.com/security)
- **Types of Solutions**:
  - **Access Control Enforcement**: Set IAM roles to control access to storage buckets.
  - **Audit Logging**: Enable logging to track access to storage resources.
- **Attacks**:
  - **Data Leakage**: Download sensitive files stored in public or misconfigured buckets.
  - **Privilege Escalation**: Access sensitive resources using compromised credentials.

---

#### 26. **Captcha OCR for Bypassing Verification**

- **Challenge Type**: Bypassing Captchas using OCR
- **Resources**:
  - [Tesseract OCR Documentation](https://tesseract-ocr.github.io/)
  - [Automated Captcha Solving - HackTricks](https://book.hacktricks.xyz/pentesting-web/automated-captcha-solving)
- **Types of Solutions**:
  - **Complex Captchas**: Use advanced captcha techniques that can’t be easily bypassed by OCR.
  - **Behavioral Analysis**: Detect bot-like behavior to block automated captcha solvers.
- **Attacks**:
  - **Captcha Bypass**: Use OCR to bypass captchas and automate requests.
  - **Account Takeover**: Gain unauthorized access to accounts by bypassing captchas.

---

#### 27. **Pwntools-Based Buffer Overflow Exploitation**

- **Challenge Type**: Exploiting Buffer Overflow for Control
- **Resources**:
  - [Pwntools Documentation](https://docs.pwntools.com/en/stable/)
  - [Buffer Overflow Guide - OWASP](https://owasp.org/www-community/attacks/Buffer_Overflow)
- **Types of Solutions**:
  - **Input Length Validation**: Ensure buffers are appropriately sized for user inputs.
  - **Stack Protection**: Enable stack canaries and ASLR to prevent overflow attacks.
- **Attacks**:
  - **Shellcode Injection**: Inject shellcode to execute arbitrary commands.
  - **Memory Manipulation**: Overwrite return addresses to control program flow.

---

#### 28. **Simple PIN Brute-Force for Bypassing Authentication**

- **Challenge Type**: PIN Brute-Forcing for Authentication Bypass
- **Resources**:
  - [Brute-Force PIN Recovery - OWASP](https://owasp.org/www-community/attacks/Brute_force_attack)
  - [CAPTCHA & PIN Security](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- **Types of Solutions**:
  - **Throttling**: Limit login attempts to prevent brute-force attacks.
  - **Strong PIN Requirements**: Use longer, alphanumeric PINs to increase difficulty.
- **Attacks**:
  - **Authentication Bypass**: Iterate through PINs to gain unauthorized access.
  - **Account Takeover**: Gain access to accounts with weak or default PINs.

---

#### 29. **Simple PIN Brute-Force Attack**

- **Challenge Type**: PIN Brute-Force Attack for Login
- **Resources**:
  - [Brute-Force Attack - OWASP](https://owasp.org/www-community/attacks/Brute_force_attack)
  - [Python Requests Library for Web Exploits](https://requests.readthedocs.io/en/master/)
- **Types of Solutions**:
  - **Throttling Mechanism**: Implement rate-limiting to prevent multiple requests.
  - **Multi-factor Authentication (MFA)**: Add MFA to increase the complexity of PIN access.
- **Attacks**:
  - **PIN Guessing**: Attempts to brute-force short PINs for unauthorized access.
  - **Credential Discovery**: Used for testing multiple combinations to gain entry into accounts with simple PINs【85†source】.

---

#### 30. **SQL Injection with URL Encoding**

- **Challenge Type**: SQL Injection through URL-encoded Payloads
- **Resources**:
  - [SQL Injection Attack - OWASP](https://owasp.org/www-community/attacks/SQL_Injection)
  - [URL Encoding in SQL Injections](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- **Types of Solutions**:
  - **Parameterized Queries**: Prevent SQL injections by avoiding direct query construction.
  - **Payload Filtering**: Validate and sanitize URL-encoded strings in user inputs.
- **Attacks**:
  - **Database Enumeration**: Retrieve data by injecting SQL commands through URL parameters.
  - **Authentication Bypass**: Bypass login mechanisms by submitting payloads that alter SQL logic【86†source】.

---

#### 31. **Prototype Pollution in SQL Injection**

- **Challenge Type**: Prototype Pollution in SQL Queries
- **Resources**:
  - [Prototype Pollution - HackTricks](https://book.hacktricks.xyz/pentesting-web/prototype-pollution)
  - [SQL Injection in Prototypes](https://portswigger.net/research/exploiting-prototype-pollution-in-javascript-applications)
- **Types of Solutions**:
  - **Input Validation**: Block keywords like `__proto__` to prevent prototype manipulation.
  - **Object Freezing**: Freeze objects to make them immutable against prototype changes.
- **Attacks**:
  - **Object Injection**: Modify prototypes to inject arbitrary properties.
  - **Privilege Escalation**: Use prototype pollution to influence SQL queries and gain unauthorized access【87†source】.

---

#### 32. **Rotational Cipher Key Brute-Force (TUCTF Challenge)**

- **Challenge Type**: Brute-Forcing Rotational Ciphers
- **Resources**:
  - [Pwntools for Exploitation](https://docs.pwntools.com/en/stable/)
  - [ROT Cipher Analysis](https://crypto.stackexchange.com/questions/26614/understanding-rot-13-cipher)
- **Types of Solutions**:
  - **Key Restriction**: Use strong cryptographic ciphers instead of rotational ciphers.
  - **Rate Limiting**: Restrict the number of decryption attempts to avoid brute-forcing.
- **Attacks**:
  - **Key Guessing**: Iteratively attempt multiple rotational keys to decrypt or access data.
  - **Data Manipulation**: Modify cipher keys to alter encrypted messages in transit【88†source】.

---

#### 33. **Unicode-Based Exploitation in Payloads**

- **Challenge Type**: Unicode Manipulation in Payloads
- **Resources**:
  - [Unicode Security Considerations - OWASP](https://owasp.org/www-community/controls/Unicode_Security_Considerations)
  - [Unicode Encoding & Exploits](https://en.wikipedia.org/wiki/Unicode_security)
- **Types of Solutions**:
  - **Character Encoding**: Ensure payloads are encoded in a single charset to avoid multi-language injections.
  - **Sanitization**: Validate inputs to prevent harmful characters in Unicode payloads.
- **Attacks**:
  - **Obfuscation**: Use Unicode to mask or encode payloads that bypass basic filters.
  - **Code Injection**: Exploit Unicode for command injection in different language encodings【89†source】.

---

#### 34. **Remote Charset Detection and Payload Transmission**

- **Challenge Type**: Charset Identification for Payload Injection
- **Resources**:
  - [Charset Security in Payloads](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)
  - [Remote Character Set Manipulation](https://portswigger.net/web-security/character-encoding)
- **Types of Solutions**:
  - **Strict Charset Definition**: Define and enforce character sets for inputs and outputs.
  - **Payload Encoding**: Encode payloads in standard charsets to avoid misinterpretation.
- **Attacks**:
  - **Remote Code Execution**: Exploit charsets to manipulate code execution on remote servers.
  - **Payload Obfuscation**: Use non-standard characters to hide payloads in transmission【90†source】.

---

#### 35. **Path Correction in Graph Networks (Fix Paths)**

- **Challenge Type**: Graph Traversal for Path Discovery
- **Resources**:
  - [Graph Theory and Pathfinding Algorithms](https://en.wikipedia.org/wiki/Pathfinding)
  - [Using Graphs in Exploits](https://medium.com/swlh/graph-theory-in-computer-science-98a8a9d3d0a3)
- **Types of Solutions**:
  - **Shortest Path Validation**: Use reliable pathfinding algorithms (e.g., Dijkstra’s) for accurate paths.
  - **Cycle Detection**: Detect and manage cycles to prevent endless traversals.
- **Attacks**:
  - **Traversal Manipulation**: Alter paths in a graph to reroute or redirect processes.
  - **Infinite Loops**: Create cyclical paths to exploit loop handling in algorithms【91†source】【92†source】.

---

## Conclusion
This wiki serves as a comprehensive guide to understanding and mitigating web application vulnerabilities. By adhering to security best practices and staying informed about potential threats, developers and security professionals can safeguard web applications against exploitation.
