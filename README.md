# 🚀 **Professional Manual Bug Hunting Framework**  
*From Recon to Critical Findings - A Systematic Approach*

## 🧠 **Phase 0 – The Hunter Mindset**

**Stop chasing low-hanging fruit.**  
Instead, ask yourself: **"How can I steal money, data, or control from this system?"**

> **❌ Common Mistake:** Reporting missing security headers, X-Frame-Options, or CSP issues without context.  
> **✅ Professional Approach:** Focus on business impact—authentication bypass, logic flaws, and authorization issues.

---

## 🔥 **Phase 1 – Reconnaissance (Mapping the Attack Surface)**

### **Goal:** Discover every endpoint, file, and hidden functionality.

#### **Step 1 – Collect URLs**
```bash
# Use these tools
gau domain.com
waybackurls domain.com
hakrawler -url domain.com -depth 3
```

**Manual Checks:**
- `robots.txt`, `sitemap.xml`
- View page source for embedded links
- Analyze all JavaScript files

#### **Step 2 – Discover Hidden Directories**
```bash
dirsearch -u https://target.com -e php,json,asp
ffuf -u https://target.com/FUZZ -w common.txt
```

**Common Critical Paths:**
- `/admin`, `/api`, `/dev`, `/test`
- `/backup`, `/uploads`, `/dashboard`
- `/internal`, `/staging`, `/console`

#### **Step 3 – JavaScript Analysis (Gold Mine)**
**Files to examine:** `main.js`, `config.js`, `bundle.js`, `app.js`

**Search for these keywords:**
- `api`, `endpoint`, `url`
- `token`, `key`, `secret`, `password`
- `admin`, `debug`, `staging`, `internal`
- `user`, `auth`, `login`

> **Example Finding:**  
> In `app.js` you discover:  
> `const API_URL = "https://internal-api.target.com/v1"`  
> This internal API wasn't listed anywhere else.

---

## 🔥 **Phase 2 – Understanding Application Flow**

**Manually walk through:**  
1. Registration → Email verification  
2. Login → Dashboard → Profile  
3. Password reset flow  
4. File upload functionality  
5. Checkout process  
6. Search functionality  
7. Admin features (if accessible)

**Create a visual flow diagram:**
```
User → Login → Dashboard → Create Order → Payment → Invoice → Account Settings
```

**Ask:** *"Where can I break this flow?"*

---

## 🔥 **Phase 3 – Authentication Testing (High-Value Zone)**

### **Check 1 – Login Brute Force**
```http
POST /login HTTP/1.1
username=admin&password=guess123
```
- Test 100+ attempts
- **If no rate limiting:** Report as Critical

### **Check 2 – OTP Bypass**
```http
POST /verify-otp HTTP/1.1
otp=000000
```
**Test:** 123456, 111111, reuse old OTP, skip OTP request entirely.

### **Check 3 – Password Reset Logic Flaws**
**Try these attacks:**
1. Change email parameter in reset request
2. Reuse reset tokens
3. Predictable token generation (time-based)
4. Response manipulation showing OTP in response

### **Check 4 – Session Issues**
**Examine cookies:**
- Missing `HttpOnly` flag
- Missing `SameSite` attribute
- No session rotation after login
- Weak session IDs

---

## 🔥 **Phase 4 – Authorization Testing (Where Pros Earn Money)**

### **IDOR (Insecure Direct Object Reference)**
**Test every ID parameter:**
```
/user/101 → /user/102
/order/500 → /order/501
/invoice/1000 → /invoice/1001
/report/2024 → /report/2025
```

**Example:**  
```http
GET /api/user/orders?user_id=123
```
Change to `user_id=124` → If you see another user's orders, you've found IDOR.

### **Role/Permission Bypass**
**As a regular user, try:**
- `/admin/`
- `/api/admin/users`
- `/dashboard?admin=true`
- `/settings?role=administrator`

### **Parameter Tampering**
**Add these parameters to requests:**
```http
POST /update_profile HTTP/1.1
user_id=attacker&is_admin=true&role=superadmin

POST /purchase HTTP/1.1
price=0.01&discount=99.99&coupon=free
```

---

## 🔥 **Phase 5 – Input-Based Attacks**

### **Test every input field with:**
```json
Payloads = [
  "' OR '1'='1",
  "<script>alert(1)</script>",
  "../../../etc/passwd",
  "{{7*7}}",
  "||ping -c 10 127.0.0.1||"
]
```

### **SQL Injection Examples:**
```sql
' OR 1=1--
' UNION SELECT username,password FROM users--
' AND sleep(5)--
```

### **XSS Examples:**
```html
"><script>alert(document.domain)</script>
javascript:alert(1)
<svg onload=alert(1)>
```

### **Local File Inclusion:**
```
?file=../../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=index.php
```

---

## 🔥 **Phase 6 – File Upload Vulnerabilities**

### **Test these file types:**
1. **PHP Shell:** `<?php system($_GET['cmd']); ?>`
2. **SVG with JavaScript:** `<svg onload=alert(1)>`
3. **HTML:** `<html><script>alert(1)</script></html>`
4. **.htaccess** to modify server behavior

### **Bypass Techniques:**
- Change extension: `shell.php` → `shell.php.jpg`
- Null byte: `shell.php%00.jpg`
- Case sensitivity: `shell.PHp`
- Double extension: `shell.jpg.php`

---

## 🔥 **Phase 7 – Business Logic Flaws (Scanner-Proof Bugs)**

### **Price Manipulation**
```http
POST /checkout HTTP/1.1
{
  "items": [{"id": 1, "price": -100}],
  "total": -100
}
```

### **Coupon/Discount Abuse**
1. Apply same coupon multiple times
2. Use coupon intended for other users
3. Negative discount values

### **Payment Flow Bypass**
1. Skip to success page: `/payment/success` without paying
2. Modify payment status parameter: `status=completed`
3. Replay successful payment requests

### **Inventory/Stock Issues**
1. Add negative quantity items to cart
2. Order more than available stock
3. Modify item prices in cart

> **If you can cause financial loss:** Report as Critical.

---

## 🔥 **Phase 8 – Quick Misconfiguration Checks**

### **5-Minute Sweep:**
- **Sensitive files:** `/.env`, `/.git/`, `/backup.zip`, `/database.sql`
- **CORS misconfiguration:** `Access-Control-Allow-Origin: *`
- **Directory listing:** `/uploads/` showing all files
- **Debug endpoints:** `/debug`, `/console`, `/phpinfo`
- **Default credentials:** admin/admin, root/root

> **Note:** Security headers are worth noting but rarely high-impact alone.

---

## 🎯 **Daily Hunting Checklist**

### **✅ Reconnaissance**
- [ ] Collect all URLs (gau, waybackurls)
- [ ] Analyze JavaScript files for secrets/endpoints
- [ ] Brute-force directories and files

### **✅ Authentication**
- [ ] Test login brute force (rate limiting)
- [ ] Test OTP bypass mechanisms
- [ ] Test password reset logic
- [ ] Check session management

### **✅ Authorization**
- [ ] Test IDOR on all numeric IDs
- [ ] Attempt privilege escalation
- [ ] Tamper with role/privilege parameters

### **✅ Input Validation**
- [ ] Test for XSS in all inputs
- [ ] Test for SQL injection
- [ ] Test for LFI/RFI
- [ ] Test for SSTI (Template Injection)

### **✅ File Upload**
- [ ] Test malicious file uploads
- [ ] Try extension bypass techniques

### **✅ Business Logic**
- [ ] Test price manipulation
- [ ] Test coupon/discount logic
- [ ] Attempt payment flow bypass
- [ ] Test inventory/stock manipulation

### **✅ Misconfigurations**
- [ ] Check for sensitive file exposure
- [ ] Test CORS configuration
- [ ] Check for directory listing

---

## 🔥 **Final Professional Advice**

### **The Hunter's Hierarchy:**
1. **Authentication Bypass** - Get in without credentials
2. **Business Logic Flaws** - Break the money flow
3. **Authorization Issues** - Access other users' data
4. **Data Exposure** - Access sensitive information

### **What Top Hunters Ignore:**
- Missing security headers (unless exploitable)
- Informational findings without impact
- Theoretical vulnerabilities without proof-of-concept

### **What Top Hunters Chase:**
- **Money flow disruption** - Can you get free products/services?
- **Data access** - Can you access other users' information?
- **Account takeover** - Can you compromise user accounts?
- **Admin access** - Can you reach administrative functions?

### **Your Advantage:**
With your security and red team background, you understand **systems**, not just vulnerabilities. You think like an attacker, not a scanner. This mindset is what separates $500 findings from $5,000 findings.

---

## 📝 **Example Report Structure**

```
Title: [Critical] IDOR in Order API Exposes All User Orders
Target: https://target.com
Endpoint: GET /api/orders/{order_id}
Impact: Any authenticated user can view all orders of all users
Steps to Reproduce:
1. Login as user A (victim@email.com)
2. Note your order ID: 1001
3. Change order_id to 1002
4. Observe user B's order details
Proof: [Screenshot/Video]
Recommended Fix: Implement proper authorization checks
```

---

**Remember:** Quality over quantity. One critical finding is worth 100 low-severity reports.  
**Stay patient, think systematically, and hunt what matters.**

*Happy Hunting! 🎯*
