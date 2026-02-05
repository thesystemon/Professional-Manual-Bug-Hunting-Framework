# 🔥 **THE ULTIMATE FLOW BREAKING METHODOLOGY**

## **🎯 PHASE 1: INITIAL RECON (First 30 Minutes)**

### **Step 1: Website Type Classification**
```
Type: [ ] E-commerce  [ ] SaaS  [ ] Social  [ ] Banking  [ ] Healthcare
     [ ] Education  [ ] Government  [ ] Booking  [ ] Forum  [ ] Other

Primary Business Goals:
1. Make money through: ________________
2. Protect data of: ___________________
3. Control access to: _________________
```

### **Step 2: Manual Exploration Worksheet**
```markdown
# Website: ________________
# Date: __________________
# Tester: ________________

## 1. Homepage Analysis:
- Main navigation: ______, ______, ______, ______
- Call-to-action buttons: ______, ______
- Visible forms: ______, ______
- Visible links to: Login, Register, Support, About

## 2. User Roles Discovered:
- [ ] Guest (unauthenticated)
- [ ] Registered User
- [ ] Premium User
- [ ] Admin/Moderator
- [ ] Vendor/Seller
- [ ] Support Staff

## 3. Key Functionalities Found:
- [ ] User registration
- [ ] Payment processing
- [ ] File uploads
- [ ] Messaging/chat
- [ ] Booking/reservation
- [ ] Reviews/ratings
- [ ] Search functionality
- [ ] Profile management
- [ ] Social features
```

---

## **📝 PHASE 2: FLOW MAPPING (The Core Process)**

### **Tool 1: The Flow Diagram Template (Use draw.io or paper)**
```
       ┌─────────────────┐
       │     ENTRY       │
       │   (Homepage)    │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │   Decision      │
       │  Point #1       │
       │  [Login/Register]│
       └────────┬────────┘
    ┌───────────┼───────────┐
    │           │           │
    ▼           ▼           ▼
┌────────┐ ┌────────┐ ┌────────┐
│  Flow  │ │  Flow  │ │  Flow  │
│   A    │ │   B    │ │   C    │
│        │ │        │ │        │
└────┬───┘ └────┬───┘ └────┬───┘
     │          │          │
     └──────────┼──────────┘
                │
                ▼
       ┌─────────────────┐
       │   VULNERABLE    │
       │   JUNCTION      │
       │   (Attack Point)│
       └─────────────────┘
```

### **Tool 2: Step-by-Step Flow Documentation Template**
```markdown
# FLOW: [Registration Process]

## Step 1: Initial Access
- URL: /register
- Method: GET
- Visible: Form with fields: email, password, confirm_password
- Hidden: CSRF token, session cookie

## Step 2: Form Submission
- URL: /api/register
- Method: POST
- Parameters:
  * email: user@example.com
  * password: ********
  * confirm_password: ********
  * csrf_token: abc123
  * accept_terms: true

## Step 3: Server Response
- Success: 302 Redirect to /verify-email
- Response Headers: Set-Cookie: session=xyz789
- Response Body: { "success": true, "user_id": 1001 }

## Step 4: Email Verification
- URL: /verify-email?token=TOKEN_HERE
- Method: GET
- Success: "Account activated, redirecting to dashboard"

## Step 5: Dashboard Access
- URL: /dashboard
- Method: GET
- Checks: Valid session required
- Content: User-specific data
```

### **Tool 3: Attack Surface Matrix (Create This For Each Flow)**
```markdown
## ATTACK MATRIX for Registration Flow:

### Authentication Bypass:
- [ ] Can I skip email verification?
- [ ] Can I reuse old verification links?
- [ ] Can I verify without token?

### User Enumeration:
- [ ] Different error for existing email?
- [ ] Timing difference in response?
- [ ] Can I check if email exists via forgot password?

### Parameter Tampering:
- [ ] Can I set "is_admin": true?
- [ ] Can I set "verified": true?
- [ ] Can I modify user_id in response?

### Business Logic:
- [ ] Can I register with same email twice?
- [ ] What happens with very long inputs?
- [ ] Can I register with SQL injection in email?

### Rate Limiting:
- [ ] Can I spam registration?
- [ ] Is there CAPTCHA? Can I bypass?
```

---

## **🔧 PHASE 3: THE DEEP FLOW ANALYSIS METHOD**

### **Method A: The "Follow the Data" Approach**
```
1. Identify where data ENTERS the system
   → Registration forms
   → File uploads
   → API endpoints
   → Import functions

2. Track where data is PROCESSED
   → Search functions
   → Sorting/filtering
   → Calculations (prices, totals)
   → Transformations

3. Identify where data is STORED
   → Databases (what tables?)
   → Files (where uploaded?)
   → Cache (redis/memcached)

4. Track where data is OUTPUT
   → User profiles
   → Reports/exports
   → APIs returning data
   → Error messages

5. Ask at each stage:
   ❓ Can I inject malicious data?
   ❓ Can I access others' data?
   ❓ Can I manipulate processing?
   ❓ Can I leak data through output?
```

### **Method B: The "Trust Boundary" Mapping**
```
┌─────────────────────────────────────────┐
│           UNTRUSTED ZONE                │
│  (User Input, External APIs, Files)     │
└──────────────────┬──────────────────────┘
                   │
                   ▼
          ┌─────────────────┐
          │  VALIDATION     │
          │  LAYER          │
          │  (Should exist) │
          └─────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│           TRUSTED ZONE                  │
│  (Business Logic, Database, Internal)   │
└─────────────────────────────────────────┘

QUESTION: What happens if I bypass the validation layer?
```

### **Method C: The "State Transition" Analysis**
```
For each user state change, ask:

1. Can I go BACKWARDS?
   Example: From "order delivered" → "order pending"

2. Can I SKIP states?
   Example: From "cart" → "delivered" (skip payment)

3. Can I be in MULTIPLE states?
   Example: Both "pending" and "completed" at same time

4. Can I MODIFY state variables?
   Example: Change "amount_paid" from 100 to 0
```

---

## **📊 PHASE 4: CREATING VISUAL BREAKDOWN**

### **Visual Tool 1: Swimlane Diagram (Different User Perspectives)**
```
         Guest        User        Admin        System
           │           │            │            │
           ├───────────┼────────────┼────────────┤
           │ Visit Site│            │            │
           │───────────│────────────│────────────│
           │           │ Login      │            │
           │───────────│────────────│────────────│
           │           │ View Dash  │            │
           │───────────│────────────│────────────│
           │           │            │ View All   │
           │           │            │ Users      │
           │───────────│────────────│────────────│
           │           │ Can I      │ ❌ Shouldn't│
           │           │ view all   │ see this   │
           │           │ users?     │            │
           └───────────┴────────────┴────────────┘
```

### **Visual Tool 2: Attack Tree for Each Flow**
```
GOAL: Steal Money from Shopping Cart
├── Method 1: Price Manipulation
│   ├── Tamper cart API request
│   ├── Negative pricing
│   └── Race condition on price update
├── Method 2: Coupon Abuse
│   ├── Stack multiple coupons
│   ├── Unlimited use of single coupon
│   └── Apply coupon to excluded items
└── Method 3: Payment Bypass
    ├── Skip to success URL
    ├── Fake payment callback
    └── Reuse payment ID
```

### **Visual Tool 3: Data Flow Diagram with Attack Points**
```
[User Browser] 
     │ POST /cart/add
     ▼
[Load Balancer] → [ ] Can I DDoS?
     │
     ▼
[Web Server] → [ ] LFI/RFI?
     │
     ▼
[Auth Check] → [ ] Can I bypass?
     │
     ▼
[Business Logic] → [ ] Price calculation flaw?
     │
     ▼
[Database] → [ ] SQL Injection?
     │
     ▼
[Response] → [ ] Sensitive data exposure?
```

---

## **🛠️ PHASE 5: PRACTICAL EXECUTION PLAN**

### **Step 1: Create Your Testing Matrix**
```markdown
| Flow Name       | Steps | Critical Data | Money Involved | Test Status |
|-----------------|-------|---------------|----------------|-------------|
| Registration    | 5     | Email, Phone  | No             | [ ]         |
| Login           | 3     | Credentials   | No             | [ ]         |
| Password Reset  | 4     | Email, Token  | No             | [ ]         |
| Add to Cart     | 2     | Product IDs   | Indirect       | [ ]         |
| Checkout        | 6     | Address, Card | YES            | [ ]         |
| Payment         | 3     | Card Details  | YES            | [ ]         |
| Order History   | 2     | All Orders    | Yes            | [ ]         |
| Profile Update  | 3     | Personal Data | No             | [ ]         |
| File Upload     | 3     | Files         | Maybe          | [ ]         |
```

### **Step 2: The "5 Whys" Analysis for Each Flow**
```
1. Why does this flow exist?
   → To allow users to purchase products

2. Why is it implemented this way?
   → Because they use Stripe for payments

3. Why is that vulnerable?
   → Because they trust client-side validation

4. Why hasn't it been fixed?
   → Because they think Stripe handles security

5. Why can I exploit this?
   → Because I can intercept and modify requests
```

### **Step 3: Burp Suite Mapping Method**
```
1. Turn on Burp Proxy
2. Clear history
3. Perform flow COMPLETELY once
4. Export all requests (Right-click → Save)
5. Create flow map from Burp history:

Request #1: GET /login
Request #2: POST /login (credentials)
Request #3: GET /dashboard
Request #4: POST /cart/add
... etc.

6. For EACH request, ask:
   - Can I skip this?
   - Can I reorder this?
   - Can I tamper parameters?
   - Can I access without auth?
```

---

## **🎯 PHASE 6: THE BREAKING CHECKLIST (Per Flow)**

### **Auth Flow Breaking Checklist:**
```markdown
# LOGIN FLOW BREAKING:

## 1. Brute Force:
- [ ] No rate limiting (spam 100 requests)
- [ ] Account lockout bypass (try wrong password 3x, then right)

## 2. Credential Stuffing:
- [ ] Default credentials (admin/admin)
- [ ] Common passwords (password123)

## 3. Response Manipulation:
- [ ] Change "success": false → true
- [ ] Add "is_admin": true to response

## 4. Session Issues:
- [ ] Session fixed before login
- [ ] Multiple concurrent sessions
- [ ] No logout → session persists forever

## 5. 2FA/MFA Bypass:
- [ ] Skip 2FA step entirely
- [ ] Use 000000 as OTP
- [ ] Reuse old OTP
```

### **Payment Flow Breaking Checklist:**
```markdown
# PAYMENT FLOW BREAKING:

## 1. Price Manipulation:
- [ ] Change amount in request
- [ ] Negative values
- [ ] Decimal points ($0.001)
- [ ] Very large numbers (overflow)

## 2. State Bypass:
- [ ] Direct access to /payment/success
- [ ] Mark payment as completed manually
- [ ] Reuse successful payment ID

## 3. Coupon/Discount:
- [ ] Apply multiple coupons
- [ ] Negative discount values
- [ ] Apply to excluded items
- [ ] Use expired coupons

## 4. Race Conditions:
- [ ] Parallel requests for same limited item
- [ ] Stock check vs reserve timing
- [ ] Double spend attacks
```

### **Data Access Flow Breaking Checklist:**
```markdown
# DATA ACCESS FLOW BREAKING:

## 1. IDOR Testing:
- [ ] Sequential IDs (1001 → 1002)
- [ ] UUIDs (predictable patterns)
- [ ] Encoded IDs (base64 decode)
- [ ] Hashed IDs (check if reversible)

## 2. Direct Object Reference:
- [ ] /files/user_1001.pdf → user_1002.pdf
- [ ] /api/user/1001/orders → 1002/orders
- [ ] /download?file=invoice_1001 → invoice_1002

## 3. Search Function Abuse:
- [ ] Wildcard searches: *
- [ ] SQL injection in search
- [ ] No result limits (return all data)

## 4. Export Functionality:
- [ ] Export all users data
- [ ] No pagination on export
- [ ] Export sensitive fields
```

---

## **📚 PHASE 7: DOCUMENTATION & NOTE-TAKING SYSTEM**

### **System 1: The "One Page Per Flow" Method**
```
PAGE 1: REGISTRATION FLOW
────────────────────────────
URLs:
1. GET /register
2. POST /api/register
3. GET /verify-email?token=
4. GET /dashboard

Parameters Found:
- email, password, confirm_password
- csrf_token, accept_terms
- user_id (in response)

Vulnerabilities Tested:
✅ Email enumeration via different error messages
✅ SQLi in email field: ' OR '1'='1
✅ Bypass email verification: /dashboard directly
✅ Rate limiting: Sent 50 requests, no block

Issues Found:
1. HIGH: Can register with SQL injection
2. MEDIUM: No rate limiting on registration
3. LOW: Email enumeration possible

Proof:
[Screenshot 1]: SQL injection working
[Screenshot 2]: 50 registration requests
```

### **System 2: The "Request-Response" Log Method**
```yaml
Flow: Login
Request #1:
  URL: /login
  Method: GET
  Notes: Login form loaded

Request #2:
  URL: /api/login
  Method: POST
  Parameters:
    email: test@test.com
    password: test123
  Response:
    success: false
    error: Invalid credentials
  Attack: Changed success to true
  Result: ❌ Server validation

Request #3:
  URL: /api/login
  Method: POST
  Parameters:
    email: admin'--
    password: anything
  Response:
    success: true
    user_id: 1
  Attack: SQL Injection
  Result: ✅ ADMIN ACCESS!
```

### **System 3: The "Mind Map" Method (Best for Visual Thinkers)**
```
               CENTRAL: Shopping Website
                     │
         ┌───────────┼───────────┐
         │           │           │
     Money Flow   Data Flow   Auth Flow
         │           │           │
    ┌────┴────┐ ┌────┴────┐ ┌────┴────┐
    │Payment  │ │User Data│ │Login    │
    │Bypass   │ │Access   │ │Bypass   │
    │         │ │         │ │         │
    ├─────────┤ ├─────────┤ ├─────────┤
    │• Price  │ │• IDOR   │ │• Brute  │
    │  manip  │ │• Search │ │  force  │
    │• Coupon │ │  inj.   │ │• 2FA    │
    │  abuse  │ │• Export │ │  bypass │
    │• Race   │ │  all    │ │• Session│
    │  cond.  │ │  data   │ │  fixation
    └─────────┘ └─────────┘ └─────────┘
```

---

## **🚀 PHASE 8: ADVANCED BREAKING TECHNIQUES**

### **Technique 1: The "Assumption Breaking" Method**
```
For each step, identify developer assumptions:

ASSUMPTION: "User will follow steps in order"
BREAK: Go directly to step 5

ASSUMPTION: "User won't modify hidden fields"
BREAK: Modify all hidden fields

ASSUMPTION: "User won't send malformed data"
BREAK: Send SQL, XSS, XXE payloads

ASSUMPTION: "Rate limiting will prevent abuse"
BREAK: Find rate limit bypass

ASSUMPTION: "Frontend validation is enough"
BREAK: Bypass with direct API calls
```

### **Technique 2: The "Parallel Universe" Method**
```
Test what happens when you:
1. Open two browsers, one as User A, one as User B
2. Perform same action in both simultaneously
3. Try to access User B's data from User A's session
4. Try to perform admin action as regular user
5. Mix and match sessions/tokens
```

### **Technique 3: The "Time Travel" Method**
```
1. Capture a valid request
2. Replay it after:
   - 1 minute
   - 1 hour
   - 1 day
   - After logout
   - After password change
3. See what still works
```

---

## **🎮 PRACTICAL EXERCISE: Let's Map a REAL Website**

### **Exercise: Map Twitter's Tweet Flow**
```
1. Visit twitter.com
2. Map the "Tweet" flow:

Step 1: Click "Tweet" button
Step 2: Compose tweet (280 chars max)
Step 3: Add media (optional)
Step 4: Choose audience (public/private)
Step 5: Click "Tweet" to post

3. Attack points at each step:
   Step 2: XSS in tweet? SQL in tweet?
   Step 3: Malicious file upload?
   Step 4: Can I tweet as someone else?
   Step 5: Can I tweet without permission?

4. Document findings
```

### **Exercise: Map GitHub's Repository Creation**
```
1. Visit github.com
2. Map "Create Repository" flow:

Step 1: Click "+" → New repository
Step 2: Enter repo name, description
Step 3: Choose public/private
Step 4: Initialize with README
Step 5: Create repository

3. Attack points:
   Step 2: Path traversal in repo name?
   Step 3: Create private repo without paying?
   Step 4: XSS in README?
   Step 5: Create repo in someone else's org?

4. Test each attack
```

---

## **💡 PRO TIPS FOR FLOW BREAKING:**

### **Tip 1: Always Ask These Questions:**
1. **What's the WORST thing that could happen here?**
2. **What would a malicious insider do?**
3. **How could this be abused at scale?**
4. **What happens if two people do this at once?**
5. **Can I automate this attack?**

### **Tip 2: The "3 Layers Deep" Rule**
```
Layer 1: Surface test (obvious attacks)
Layer 2: One step deeper (combine two issues)
Layer 3: Chain multiple issues together

Example:
Layer 1: Find IDOR (access other's data)
Layer 2: IDOR + No rate limit (steal ALL data)
Layer 3: IDOR + Export feature + XSS = Mass data theft
```

### **Tip 3: The "Business Impact" Focus**
```
Don't just find bugs. Find business impact.

Instead of: "Missing security header"
Say: "I can steal user sessions because of missing header"

Instead of: "Rate limit missing"
Say: "I can brute force all user passwords costing $X in support"
```

---

## **📦 YOUR TESTING KIT (What You Need):**

### **Software:**
- Burp Suite Professional
- Browser with DevTools
- Note-taking app (Notion, Obsidian, OneNote)
- Diagram tool (draw.io, Lucidchart, or pen & paper)
- Python for custom scripts

### **Templates to Create:**
1. Flow Mapping Template
2. Attack Matrix Template
3. Finding Documentation Template
4. Proof of Concept Template

### **Mindset:**
- Curiosity ("What happens if...")
- Persistence (Test everything)
- Creativity (Think outside normal flow)
- Business awareness (Impact matters)

---

## **🎯 FINAL WORKFLOW SUMMARY:**

```
DAY 1-2: Map ALL flows (create diagrams)
DAY 3-4: Test Auth & Payment flows (highest impact)
DAY 5-6: Test Data Access & Business Logic
DAY 7: Chain vulnerabilities together
DAY 8: Document & report

EACH DAY:
Morning: Test new flows
Afternoon: Deep dive on findings
Evening: Document & plan next day
```

---

**Remember:** Flow breaking is an art AND a science. The science is in systematic testing. The art is in creative thinking about how to break assumptions.

**Start with one flow.** Master it. Become the expert at breaking THAT flow. Then move to the next.

**Your goal:** Not just to find bugs, but to understand the system BETTER than the developers who built it.

**Now go break some flows! 🚀**

---

*Pro tip: Keep a "Hall of Fame" document where you record your most creative flow breaks. Review it regularly to spark new ideas.*
