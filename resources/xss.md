# Advanced Cross-Site Scripting (XSS)

## Filter & WAF Bypasses
1. **Hex/Unicode Escapes**: Represent characters dynamically. E.g., `\u003cscript\u003e` or `\x3cscript\x3e`.
2. **HTML5 Obscure Tags**: WAFs often miss elements like `<details ontoggle=alert(1)>`, `<marquee onstart=alert(1)>`, `<svg/onload=alert(1)>`.
3. **JavaScript String Exploitation**: If input lands inside a string `var name = "INPUT"`, break out using `"; alert(1); //` or string interpolation `${alert(1)}`.
4. **JSFuck / JS-on-the-fly Decoding**: If `alert` or alphanumeric strings are banned, encode them entirely using `[ ] ( ) ! +` characters.

## DOM-Based Vectors
1. **DOMPurify Bypasses**: 
   - Check if the backend replaces specific substrings *after* DOMPurify sanitizes the input!
   - Look for Trusted Backend Routes: Is the sanitized content pushed into a dangerous sink down the line (`innerHTML`, `document.write`)?
2. **DOM Clobbering**:
   - Overwrite global variables using HTML `id` attributes. If JS does `window.config.url`, provide `<a id=config><a id=config name=url href="javascript:alert(1)"></a>`.
   - Very useful against complex SPAs that trust global `window.` properties.
3. **Hidden DOM Elements / React Interactions**:
   - If an element is hidden or managed by React, look for programmatic filling routes.
   - Example: Forcing a React-controlled hidden field to hold a script payload.

## High-Impact Client Exploits
1. **XS-Leak via Image Load Timing**:
   - Use `<img>` tags pointing to an endpoint that responds differently based on state (e.g., search results taking longer to load than 0 results).
   - Use JavaScript `performance.now()` applied to `onload` / `onerror` to oracle data cross-origin blindly!
2. **HTTP Request Smuggling / Cache Poisoning**:
   - Store an XSS payload in a cached error response by smuggling a crafted request through the proxy.
3. **JPEG+HTML Polyglots**:
   - Craft a file that acts as a valid image (for upload filters) but contains a valid HTML `<script>` block when opened directly.
4. **Content-Type via File Extension**:
   - Upload `script.js` or `index.html` masking as another MIME type. If the server forces `text/html` based on custom extension mappings, it executes.
