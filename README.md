### brickwall

brickwall is an open source, extremely easy-to-use, seamless bot protection system for personal sites and more. it is primarily made for sites who want bot protection (cloudflare turnstiles or recaptchas) but cant edit server side code.  

### features
here are all the features documented for brickwall:

- proof-of-work challenge (sha-256 hash with leading zeros, ~1–2 seconds)
- browser fingerprinting checks
- signed jwt token issuance
- client-side token caching via localstorage
- headless browser detection (blocks puppeteer, phantomjs, nightmare, etc.)
- automated solve rejection (solutions under 200ms are rejected)
- noscript fallback message
- automatic crawler bypass (googlebot, bingbot, etc.)
- tor exit node blocking
- vpn/datacenter ip flagging and optional blocking
- rate limiting (15 requests/min per ip, 60-second cooldown)
- configurable token ttl (1–720 hours, default 24h)
- per-site token scoping
- api key rotation (invalidates all existing visitor tokens)
- client-side expiry checking (no server call needed)
- allow/block crawlers toggle
- block tor toggle
- block vpn toggle
- active/inactive toggle (bypass all challenges)
- multiple sites per account (no limit during early access)
- independent settings and request logs per site
- request log (last 500 entries per site)
- stats: total, passed, blocked, and flagged counts
- all requests panel with live visibility
- full authentication api (register, login, logout, account deletion)
- sites management api (create, update, delete, rotate keys)
- challenge api (init, verify, server-side check endpoint)
- express middleware support for backend/server-side verification

### contributing

refer to CONTRIBUTING.md

### documentation

documentation is here: https://brickwall.onrender.com/docs.html
