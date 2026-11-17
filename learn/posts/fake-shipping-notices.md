---
title: Fake shipping and freight notices
date: 2026-10-20
summary: "Delivery failed", "BOL attached", "update the delivery address". These land best on people who really are waiting on shipments.
tags: construction, attachments
---

If your work involves deliveries, a shipping email doesn't look strange at all, which is exactly why scammers use them. Common versions:

- **"Delivery failed, confirm your address"** with a link
- **"Bill of lading attached"** as an `.html` or `.zip` file
- **"Customs or freight charges due"** with a small payment

```email
From: Freight Dispatch <dispatch@ltl-freightnotice.com>
To: you@yourcompany.com
Subject: Shipment on hold - BOL #4471209
Verdict: phishing
Attachment: BOL_4471209.html

Your shipment is ==on hold due to an incomplete delivery address|A reason to make you act==.

Please ==open the attached bill of lading|A BOL as a web page file is a sign-in trap, not a document== and confirm your details to release the shipment.

==A redelivery fee of $2.99 applies.|Small fees are how they get card numbers==
```

## How to check

- **Track it yourself.** Use the tracking number on the carrier's own website, or call your dispatcher or the vendor.
- **An `.html` file is not a document.** Real BOLs and packing lists come as PDFs or through the carrier's portal. A web-page attachment that opens a sign-in screen is phishing.
- **Small fees are bait.** The $2.99 is to get your card number.

> [!NOTE] Off the Hook flags web-page attachments
> Attachments like `.html`, `.htm` and `.svg` get a warning, and the file checker can look inside them without opening them.

```quiz
You're expecting a steel delivery. An email says it's on hold and attaches "BOL.html". What's the safest move?
- [ ] Open it: you really are expecting a delivery
- [x] Call your dispatcher or check the carrier's site yourself
- [ ] Forward it to the shop to deal with
Why: Scammers count on the timing. A web-page "bill of lading" is a trap, so check the shipment through a source you already trust.
```
