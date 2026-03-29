# Advanced Node.js Prototype Pollution & VM Escapes

## Prototype Pollution Basics
In JavaScript, an attacker who controls object properties (e.g., via JSON parsing, recursive merge functions, or query string parsers) can overwrite the global `Object.prototype`.
- **Injection Vector**: Sending `{"__proto__": {"admin": true}}` or `?constructor.prototype.admin=true`.
- **Result**: Every object in the Node application instantly inherits `admin = true` unless specifically overridden!

## Escalation Path 1: Gadgets (RCE, SQLi, Auth)
To turn Prototype Pollution into a critical exploit, you need a "Gadget" — existing application code that safely assumes a property is `undefined` but behaves dangerously if it is defined.
1. **Library Settings Injection**:
   - Polluting `env` variables used by native Node modules (e.g., `child_process.exec` takes an `env` object).
   - Polluting SQL/ORM query objects (e.g., forcing knex.js or Sequelize to interpret polluted properties as raw SQL logic).
2. **Lodash vs Pug Chain**:
   - If `lodash.merge()` is polluted, and later the app uses the `Pug` or `Handlebars` template engine to render something, you can pollute the template compiler options to execute arbitrary javascript during page render!

## Escalation Path 2: Sandbox & VM Escapes
If an application attempts to run untrusted code safely using `vm`, `vm2`, or libraries like `Happy-DOM`, you can often break out into the main Node process.

1. **CommonJS Escape**:
   - If the code exposes `this.constructor.constructor`, you can rebuild the `Function` object and execute arbitrary code outside the sandbox:
   - `this.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')()`
2. **ESM-Compatible Escapes (CVE-2025-xxxx)**:
   - In ECMAScript Modules, `process.mainModule` is often `undefined`.
   - Instead, find global objects or promises passed into the context and trace their prototype chains back to the host constructor.
3. **Happy-DOM / JSDOM Exploitation**:
   - If the app uses a virtual DOM to safely render user HTML, utilizing `document.write` or similar sinks inside the polluted sandbox might trigger host-level parsers or script executors that break the boundaries.

## Defense Evasion (Bypassing Filters)
- If `__proto__` is blocked or stripped:
  - Try using `constructor.prototype`.
  - Try nested obfuscation: `__pro__proto__to__` (if the blocklist only replaces it once).
  - Use circular references or nested array tricks if using libraries like `flatnest`.
