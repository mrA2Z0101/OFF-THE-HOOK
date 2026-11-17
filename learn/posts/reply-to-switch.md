---
title: The Reply-To switch
date: 2026-10-20
summary: The From line looks right, but when you hit Reply, your answer goes somewhere else entirely.
tags: basics
---

Every email has a hidden setting called **Reply-To**. It tells your email program where to send your reply. Normally it's the same as the sender. Scammers change it.

So an email can show **From: Dana Lee <dana.lee@yourcompany.com>** while your reply quietly goes to `dana.lee.office@gmail.com`. The scammer never needed to hack Dana's account; they only needed you to answer.

```email
From: Dana Lee <dana.lee@yourcompany.com>
To: you@yourcompany.com
Subject: Quick question
Verdict: phishing

Hi, ==are you available? I need a quick favor with a vendor payment.|A vague opener to get you talking==

==Reply here when you get this.|Your reply goes to a different address than the one shown==

Dana
```

## How to catch it

- **Check the "To" line when you reply.** Before you send, look at the address your reply is actually going to. If it changed, stop.
- **Start a fresh email** to the person from your contacts instead of replying, for anything involving money or information.
- **Look for the warning.** Some email programs show "Reply-To" in the message details.

> [!NOTE] Off the Hook checks Reply-To
> It warns you when replies would go to a different domain or a free email account.

```quiz
You hit Reply to an email from your manager. The "To" line now shows a Gmail address. What happened?
- [ ] Your manager prefers Gmail for replies
- [x] The email's Reply-To was set to a different address, a classic scam trick
- [ ] Outlook made a mistake
Why: The From line can look perfect while replies go elsewhere. Start a new email to your manager's real address instead.
```
