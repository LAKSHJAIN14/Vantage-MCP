# Advanced SQL Injection (SQLi)

## Quote/String Escape Bypasses
When single quotes (`'`) are filtered or escaped (e.g., converted to `\'`), try:
1. **Backslash Injection**: Inputting `\` can break the escape sequence of the next quote. E.g., `user=\&pass= or 1=1 #` becomes `SELECT * FROM users WHERE user='\' AND pass=' or 1=1 #'`. The `{user}` absorbs the AND clause, letting `pass` become the injection vector!
2. **Hex Encoding**: If allowed, use `UNHEX('61646d696e')` or `0x61646d696e` instead of `'admin'`.
3. **CHAR() Function**: Use `CHAR(97, 100, 109, 105, 110)` to represent "admin" without quotes.

## Filter & WAF Bypasses
1. **Double-Keyword Bypass**: If `SELECT` is removed, try `SELSELECTECT` (when the filter runs only once non-recursively).
2. **XML Entity Encoding**: If the input passes through XML before hitting the DB, use `&#x27;` for single quote, or `&apos;`.
3. **Shift-JIS Encoding (Multi-byte)**: In MySQL with Shift-JIS or similar encodings, sending `%bf%27` can consume the backslash added by `addslashes()` (`%5c`), turning into `%bf%5c` (a valid multi-byte character) and leaving the quote `%27` unescaped!
4. **LIKE Character Brute-Force**: If `=` is blocked, use `LIKE`. Example: `password LIKE 'a%'`. Keep guessing until the response length changes.

## Structural Bypasses
1. **Column Truncation (MySQL Strict Mode Off)**: If a `username` column limits to 20 chars, signing up with `admin               x` (admin + 15 spaces + x) will truncate to `admin` in the DB. This can overwrite or clash with the real admin account.
2. **Second-Order SQLi**: Injecting a payload into a profile field (like username) that is safely inserted into the database but later unsafely queried without parameterization in a different endpoint.
3. **Information_Schema.ProcessList**: If standard schema tables are blocked or you need to see what queries other connections are running: `SELECT info FROM information_schema.processlist`.

## Extreme Vectors
1. **EXIF Metadata**: Inject SQL logic into the `Artist` or `Comment` tag of an image and upload it.
2. **QR Code Injection**: Encode an SQL payload into a QR code if the backend parses QR content blindly.
3. **SQLi to SSTI Chain**: If the DB result is reflected into a template engine, dump SSTI payloads from the DB (e.g., `{{7*7}}`) to escalate SQLi to RCE!
