---
title: The 10-second check: who, what, where
date: 2026-10-13
summary: Three questions you can ask about any email before you click, reply or pay. They take ten seconds and catch most scams.
tags: basics, links
---

You don't need to be a computer expert to catch most phishing. Before you act on an email, ask three questions.

## 1. Who really sent it?

Look at the **email address**, not the name. Anyone can set their display name to "Kevin Smith" or "Microsoft Support". The part after the @ is what matters.

- `kevin@supplyco.com` and `kevin.supplyco@gmail.com` are not the same person.
- Watch for look-alikes: `supp1yco.com`, `supplyco-invoices.com`, `rn` pretending to be `m`.

## 2. What does it want?

Sign in, pay, send information, open a file? That's when you slow down. The bigger the ask, the more you should check, especially if it's **urgent** or **secret**.

## 3. Where does the link really go?

Hover over a link (don't click) and look at the address that pops up. Read the main part of the address from right to left, starting just before the first single `/`:

- `https://login.microsoftonline.com/...` goes to **microsoftonline.com**
- `https://microsoft.com.account-verify.top/...` goes to **account-verify.top**

> [!NOTE] Off the Hook does this for you
> Hover any link in an open email and the link card shows where it really goes, with every check listed. QR codes in pictures are read too.

```email
From: SupplyCo Accounts <accounts@supplyco-billing.com>
To: you@yourcompany.com
Subject: Updated remittance information
Verdict: phishing
Attachment: Remittance_Update.pdf

Hi,

Please note that ==our bank details have changed|Changed bank details are the #1 invoice scam==. All ==future payments should go to the account in the attached letter|A real vendor change gets confirmed by phone==, effective immediately.

==Please keep this between accounting for now|Secrecy keeps you from checking with anyone==.

Regards,
SupplyCo Accounts
```

```quiz
The email above is from `supplyco-billing.com`. You normally get email from `supplyco.com`. What's the safest next step?
- [ ] Reply and ask them to confirm the new account
- [ ] Open the PDF to see if it looks official
- [x] Call SupplyCo on the number you already have on file
Why: Replies go to the scammer, and a fake letter can look perfect. A phone number you already had is the one channel the scammer doesn't control.
```
