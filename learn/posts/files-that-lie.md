---
title: Files that aren't what they say
date: 2026-10-20
summary: invoice.pdf.exe, web-page "documents" that ask you to sign in, and Word files that tell you to click "Enable content".
tags: attachments
---

Downloading an attachment is usually harmless. **Opening** it is when a bad file does its damage. These are the tricks to know:

## The double name

`Invoice_2026.pdf.exe` is a **program**, not a PDF. Windows often hides the last part of the name, so you only see `Invoice_2026.pdf`. Anything ending in `.exe`, `.js`, `.vbs`, `.lnk`, `.bat`, `.scr` or `.iso` can run code.

## The web page pretending to be a document

A file ending in `.html`, `.htm` or `.svg` opens in your browser. Scammers use it to show a fake sign-in page **from your own computer**, so link filters never see it.

## "Enable content"

A Word or Excel file that says *"This document was created in a newer version. Click Enable Content to view"* is asking you to turn on **macros**, small programs inside the file. That's how it installs malware.

```email
From: Accounts Payable <ap@northgate-supply.com>
To: you@yourcompany.com
Subject: Remittance advice - payment sent
Verdict: phishing
Attachment: Remittance_Advice.pdf.html

Hello,

==Payment has been sent to your account.|Good news gets you to open things without thinking==

Please ==open the attached remittance advice|The file is a web page, not a PDF: it will ask you to sign in== and sign in with your email to view the details.
```

> [!TIP] Check before you open
> Off the Hook's **file checker** (toolbar → **Check a file**) looks inside a downloaded file without opening it, and tells you if it's disguised or dangerous.

```quiz
Which attachment is the safest to open?
- [ ] Payment_Details.pdf.html
- [ ] Drawings.zip with a password in the email
- [x] Shop_Schedule.pdf from a coworker you were expecting it from
Why: The first is a web page in disguise, and locked zip files hide their contents from scanners. An expected PDF from someone you know is the normal case.
```
