---
title: Look-alike letters
date: 2026-10-20
summary: "rn" looks like "m", a zero looks like an "o", and some foreign letters look identical to English ones. Zoom in on the address.
tags: links, basics
---

Scammers register addresses that look **almost** right, counting on you to read quickly. Some tricks:

| Looks like | Is really |
|:--|:--|
| `microsoft.com` | `rnicrosoft.com` (r + n, not m) |
| `paypal.com` | `paypa1.com` (the number 1) |
| `google.com` | `g00gle.com` (zeros) |
| `apple.com` | `аpple.com` (a Russian "а") |
| `supplyco.com` | `supplyco-inc.com` (extra words) |

The foreign-letter trick is the sneakiest: on screen, the Russian letter "а" and the English "a" are **pixel-for-pixel identical**.

```quiz
Which of these addresses really belongs to Microsoft?
- [ ] rnicrosoft.com
- [ ] microsoft.com-account-security.net
- [x] login.microsoftonline.com
Why: "rnicrosoft" uses r and n to fake an m. In the second one, the real domain is the last part, "com-account-security.net". microsoftonline.com is Microsoft's real sign-in domain.
```

## How to check

- **Zoom in** (Ctrl and +) on the sender's address or the link before acting on anything important.
- **Read the end of the domain**, the part just before the first single `/`. That's who you're really dealing with.
- **Type addresses yourself**, or use a bookmark, for sites where you sign in or pay.

> [!NOTE] Off the Hook checks the letters for you
> It flags look-alike letters, number swaps and foreign characters in sender addresses and links, including addresses that imitate your own company.

```quiz
You get an invoice from billing@supp1yco.com. Your vendor is supplyco.com. Is this the same company?
- [ ] Yes, it's the same name
- [x] No: the "l" is the number 1, so it's a different domain
- [ ] Only if the invoice looks familiar
Why: One character is enough to make a completely different address that anyone can register.
```
