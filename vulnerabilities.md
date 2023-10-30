# V1 [[CWE-89](https://cwe.mitre.org/data/definitions/89.html)] - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

> **The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.**

---

##### Login (V1.1)

> In the Login, if the username is ' the web app will malfunction (SQL Injection)

---

##### SignUp (V1.2)

> In the Sign Up, if the username, email or password is ' the web app will malfunction (SQL Injection)

---

##### Password Recovery (V1.3)

> In the Password Recovery, if the email is ' the web app will malfunction (SQL Injection)

---

##### Checkout (V1.4)

> In the Checkout, if the shipping address is ' the web app will malfunction (SQL Injection)

---

##### Edit Profile (V1.5)

> While editing the profile fields, if the username, email or password is ' the web app will malfunction (SQL Injection)

---

##### Add a Product Review (V1.6)

> While adding a product review, the text area input is vulnerable to XSS

---



# V2 [[CWE-79](https://cwe.mitre.org/data/definitions/79.html)] - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

> **The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.**

---

##### Add a Product Review (V2.1)

> While adding a product review, the text area input is vulnerable to XSS

---

##### Product Details (V2.2)

> When adding or editing a product, the inputs are vulnerable to XSS or SQL Injections

---



# V3 [[CWE-285](https://cwe.mitre.org/data/definitions/285.html)] - Improper Authorization

> **The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.**

---

##### Acessing Pages Without Auth (V3.1)

> The authentication can be skipped by putting the right URL, so any page can be easily accessed, including the user's profile page and all the account

---



# V4 [[CWE-256](https://cwe.mitre.org/data/definitions/256.html)] - Plaintext Storage of a Password

> **Storing a password in plaintext may result in a system compromise.**

---

##### Password not Encrypted (V4.1)

> The password is being stored in plaintext

---

# V5 [[CWE-756](https://cwe.mitre.org/data/definitions/756.html)] - Missing Custom Error Page

> **The product does not return custom error pages to the user, possibly exposing sensitive information.**

---

##### Missing Error Page (V5.1)

> The product does not return custom error pages to the user, possibly exposing sensitive information.

---



# V6 [[CWE-798](https://cwe.mitre.org/data/definitions/798.html)] - Use of Hard-coded Credentials

> The product contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.

---

##### Credentials in the Code (V6.1)

> The email and database credentials are hard-coded into the code files.

---



# V7 [[CWE-620](https://cwe.mitre.org/data/definitions/620.html)] - Unverified Password Change

> When setting a new password for a user, the product does not require knowledge of the original password, or using another form of authentication.

---

##### Previous Password Not Required (V7.1)

> In the account settings page, when changing the password, the original password isn't required

---
