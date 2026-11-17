# Off the Hook privacy policy

Last updated: November 17, 2026

Off the Hook is a browser extension that flags signs of phishing in the email you have open in Gmail or Outlook on the web. This page says what it reads, what it keeps, and what leaves your computer.

## The short version

- The developer of Off the Hook receives **nothing**. There is no account, no server, no analytics, no ads and no tracking.
- In the default rule-based mode, **your email never leaves your browser**. Every check runs inside the extension.
- AI mode is **off by default**. If you turn it on, a filtered copy of the email you open is sent to the AI provider **you** choose, and to nobody else.
- Everything Off the Hook keeps is stored on your computer, and one button deletes all of it.

## What Off the Hook reads

To check for phishing, the extension reads the following on `mail.google.com` and Outlook on the web (`outlook.live.com`, `outlook.office.com`, `outlook.office365.com`, `outlook.cloud.microsoft`), and nowhere else:

- **The email you have open:** sender name and address, reply-to, subject, body text, links, attachment file names, and pictures (to read QR codes).
- **Your inbox list:** the sender, subject and preview line of each row, to tag risky emails before you open them.
- **A raw message header,** only when you open Gmail's "Show original" or Outlook's "View message details" yourself.
- **The reply you are typing** to a sender it has flagged, to warn you before you send a phone number, password, card or bank details. What you type is checked as you type and is never stored.
- **Files you drop into the file checker.** They are read on your computer only: never uploaded, opened or run.

Off the Hook is read-only. It never sends, deletes, moves or edits email, and it never opens or fetches the links in an email.

## What is stored, and where

All of this is kept in the browser's extension storage on your computer. None of it is synced or sent to the developer.

| What | Why |
|:--|:--|
| Your settings (sensitivity, company domain, trusted senders, custom keywords, highlight choices) | To work the way you set it up |
| Your reports ("It's phishing" / "It's safe"): sender, subject, link sites, the phrases and notes you add, and the email text only if you turn that on | To learn from your decisions |
| Contact memory: who normally emails you, kept as salted SHA-256 fingerprints rather than names or addresses (only a name's usual domain is readable) | To notice a familiar name on a new address |
| The public scam-site lists | To check links and senders on your computer |
| Which Learn posts you have opened | To show the "New" tag |
| Each tab's verdict and score (not email text), until the browser closes | To show the verdict in the toolbar |
| AI provider settings and your API key, if you add one | To use AI mode |

**Settings → Privacy and data → Clear all Off the Hook data** deletes all of it and takes back any AI site permission you granted. Removing the extension deletes it too.

## What leaves your computer

**1. Scam-site list downloads.** Once a day the extension downloads public lists of known phishing and malware sites from `raw.githubusercontent.com` (Phishing.Database and the OpenPhish community feed), `urlhaus.abuse.ch` and `phishing.army`. These are ordinary file downloads: nothing about you or your email is sent with them, though those sites see your IP address, as any website does. Links and senders are compared against the lists on your computer. You can switch any list, or all of them, off in Settings.

**2. Email pictures, to read QR codes.** Gmail and Outlook serve the pictures inside emails from their own image servers (`googleusercontent.com`, `office.net`). To read a QR code, the extension fetches the picture again from **those servers only**. It never contacts the sender's servers.

**3. AI mode, only if you turn it on.** Turning it on shows a notice you must accept first. After that, for each email you open, the extension sends the sender name and address, reply-to, subject, body (the first 3,000 characters unless you allow more), link text and addresses, attachment file names and the rule findings to the provider you configured:

- **Ollama or another local model:** the request goes to your own computer and nothing leaves it.
- **An OpenAI-compatible API or Anthropic:** the request goes to that provider, using your own API key. That provider's privacy policy and retention rules apply.

With redaction on (the default), email addresses keep only their domain, numbers of six or more digits become `[number]`, and link query strings are removed before sending. Your API key is stored only on your computer, is never synced or logged, and is sent only to that provider in a request header.

Nothing else leaves your computer.

## What Off the Hook does not do

- It does not sell or share your data with anyone.
- It does not use your data for advertising, profiling, or deciding creditworthiness or lending.
- It does not let any person read your email. The developer has no access to anything the extension reads or stores.
- It does not load or run code from the internet. Downloaded lists and AI replies are treated as plain data.

## Chrome Web Store Limited Use

Off the Hook's use of information it reads from your webmail complies with the [Chrome Web Store User Data Policy](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq), including the Limited Use requirements. The information is used only to provide the extension's single purpose: detecting and explaining signs of phishing in the email you are reading.

## Children

Off the Hook is not directed at children and does not knowingly collect information from anyone.

## Changes

If this policy changes, the new version will be posted on this page with a new date.

## Contact

Questions or concerns: open an issue at <https://github.com/mrA2Z0101/OFF-THE-HOOK/issues>.
