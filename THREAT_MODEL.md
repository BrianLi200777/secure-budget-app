# Threat Model: Secure Budget App

> **How to use this outline:** Replace every _italic prompt_ with your own answer, and fill in the tables. Delete this note when you're done.

## 1. What the system is

_In 2–3 sentences: what does the app do, and who uses it?_

### Assets (what's worth protecting)

_List what an attacker would want. Think about what's stored in the database, what's in `.env`, and what Plaid gives the app. Rank them by how bad it would be if each one leaked._

| Asset | Where it lives | Why it matters |
|---|---|---|
| | | |

### Trust boundaries

_Where does data cross from something you don't control into something you do? Think about the browser, the Flask app, the database file, and Plaid. Which of these do you trust, and which do you not?_

### Data flow

_Walk through one full bank connection step by step, from clicking "Connect a bank" to transactions appearing. At each step, note what data moves and where. (The diagram in the README can help, but write it in your own words.)_

## 2. STRIDE analysis

For each category, list specific threats to **this** app. Rate likelihood and impact as Low, Medium, or High. Status is one of: **Mitigated**, **Partially mitigated**, or **Open**.

### S: Spoofing (pretending to be someone else)

_Guiding questions:_
- _How could an attacker log in as another user?_
- _What happens if someone tries thousands of passwords?_
- _What if an attacker gets hold of someone's session cookie? How might they get it?_
- _Could someone fake a request that looks like it came from Plaid, or from your own page?_

| Threat | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|
| | | | | |

### T: Tampering (changing data you shouldn't be able to)

_Guiding questions:_
- _What could a user send in a form that the app doesn't expect?_
- _Could someone change another user's budgets or transactions?_
- _What if someone edits the database file directly?_
- _Could a malicious website make your browser submit a form to this app?_

| Threat | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|
| | | | | |

### R: Repudiation (doing something and denying it later)

_Guiding questions:_
- _If someone said "I never connected that bank account," could you prove otherwise?_
- _What does the app record when someone logs in, fails to log in, or connects a bank?_
- _If there was a break-in, what evidence would you have? What would you want to add?_

| Threat | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|
| | | | | |

### I: Information disclosure (data leaking to the wrong person)

_Guiding questions:_
- _If an attacker copied the database file, what could they read and what couldn't they?_
- _Where is the encryption key stored compared to the encrypted data? Is that a problem?_
- _What could leak through error messages, logs, the browser cache, or URLs?_
- _Could one user ever see another user's transactions?_
- _What could happen if a secret ended up in the GitHub repo?_

| Threat | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|
| | | | | |

### D: Denial of service (making the app unusable)

_Guiding questions:_
- _Which pages are limited by the rate limiter, and which aren't?_
- _What's the slowest thing the app does? Could someone trigger it over and over?_
- _What happens to your app if Plaid is down or slow?_

| Threat | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|
| | | | | |

### E: Elevation of privilege (getting more access than you should)

_Guiding questions:_
- _Every query that reads user data: how does it make sure it only returns the logged-in user's rows?_
- _Is there any way to run code on the server?_
- _What would be different if this were running online instead of on your laptop?_

| Threat | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|
| | | | | |

## 3. Risks you're accepting (for now)

_Which "Open" or "Partially mitigated" threats are you choosing not to fix yet, and why? Being honest here is a strength, not a weakness._

## 4. What you'd do next

_If you had another month, what are the top 3 security improvements you'd make, in order? Why that order?_
