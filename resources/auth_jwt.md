# Advanced Auth, Access Control, and JWT Attacks

## JWT (JSON Web Token) Bypasses
1. **Algorithm None**: Change the header `alg` to `none` (or `None`, `NONE`) and delete the signature portion. Example: `eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.`
2. **Algorithm Confusion (RS256 to HS256)**: Change the algorithm from RS256 (asymmetric) to HS256 (symmetric). Then, sign the token using the application's *Public Key* as the HMAC secret! If the backend blindly passes the public key into an HS256 verification function, the signature will match.
3. **Weak Secret Brute-Force**: If HS256 is used, extract the token and feed it into `hashcat` or `john` to crack the signing secret offline.
4. **JWK/JKU Header Injection**:
   - `jku`: Add a `jku` header pointing to your own JSON Web Key Set URI, forcing the server to fetch and trust your public key.
   - `jwk`: Embed your own raw JSON Web Key in the header, then sign the token with your private key.
5. **KID Path Traversal**: If the `kid` (Key ID) header represents a file path (e.g., `kid: "key1.pem"`), change it to `kid: "../../../dev/null"` and sign the token with an empty string, or point it to a known static file system path!
6. **JWE (Encrypted) Token Forgery**: If the server accidentally exposes its private key (or uses a default/predictable one), you can craft entirely encrypted payloads representing admin sessions.

## IDOR & Authorization Bypasses
1. **Route Bypass via Encoding**: For Express.js or Node endpoints, passing `%2F` instead of `/` may bypass middleware auth checks but still route to the same handler. (e.g., `/api%2fadmin/users`).
2. **Hidden/WIP Endpoints**: Look for `/api/v1/auth/beta/admin` or similar paths in JS source code. Developers often leave unauthenticated routes exposed before pushing them "live".
3. **HTTP TRACE / Verb Manipulation**: Send the request as `TRACE`, `PATCH`, or `PUT` instead of `GET`/`POST`. If the auth middleware only checks `if method == 'GET'`, you bypass it and access the endpoint!

## Cookie Manipulation
1. **Public Admin Seeding**: Find an endpoint that sets an admin cookie unconditionally (perhaps a debug or healthcheck route) and then navigate to the admin panel.
2. **Always-True Hash Checks**: Sometimes logic uses loose equality (`==` vs `===` in PHP/JS) to compare signatures. Try providing `true`, `0`, or `[]` (arrays) as the signature if JSON is accepted.
3. **Host Header Bypass**: Supplying a different `Host` header can cause the backend to generate completely different session cookies or trust configurations, giving you elevated access on the primary domain.

## Blind NoSQL Injection (MongoDB)
- If the application connects to MongoDB and takes `{"user": "admin", "pass": {"$gt": ""}}`, it bypasses the password check!
- **Binary Search Extraction**: If the endpoint responds with true/false (or timing differences), you can extract a token sequentially: `{"token": {"$regex": "^a.*"}}` -> true, `{"token": {"$regex": "^ab.*"}}` -> false.
