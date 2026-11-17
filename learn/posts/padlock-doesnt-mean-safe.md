---
title: The padlock doesn't mean safe
date: 2026-10-20
summary: The padlock means the connection is private, not that the site is honest. Most phishing sites have one too.
tags: links, basics
---

For years people were told: "Look for the padlock." That advice has aged badly.

The padlock (or `https://`) means one thing: **the connection between you and the site is encrypted**, so nobody in between can read it. It says nothing about **who** you're connected to. Getting a padlock is free and takes minutes, so most phishing sites have one.

> [!WARNING] A private line to a scammer is still a scammer
> The padlock protects what you send. It doesn't check who receives it.

## What to check instead

1. **The domain.** Read the address bar: is it really `microsoft.com`, `yourbank.com`, `supplyco.com`?
2. **How you got there.** Did you type the address or use a bookmark? Or did you click a link in an email or text?
3. **What it asks for.** A sign-in page you reached from an email deserves extra suspicion.

```quiz
You click a link in an email and land on a sign-in page with a padlock and https:// in the address bar. Is it safe to sign in?
- [ ] Yes: the padlock means the site is verified
- [x] Not necessarily: check the domain, and sign in by going to the site yourself
- [ ] Yes, if the page looks exactly like Microsoft's
Why: Phishing sites get padlocks for free, and copying a page's look is easy. The address and how you got there matter far more.
```
