# Chrome Web Store listing kit

Everything to paste or upload in the [Developer Dashboard](https://chrome.google.com/webstore/devconsole). Fields are listed in the order the dashboard asks for them.

## 1. Package

```bash
python scripts/build_zip.py     # writes dist/off-the-hook-<version>.zip
```

Upload that zip under **Package**. It holds only what the extension runs (no dev tools, tests or store art), and the script refuses to build if the manifest breaks a store limit. For a later release, raise `"version"` in `manifest.json` first: the store rejects a version it has already seen.

## 2. Store listing

**Title** and **Summary** come from `manifest.json` (`name` and `description`, 132 characters at most).

**Category:** Privacy & Security  
**Language:** English

**Description** (plain text, paste as is):

```text
Off the Hook reads the email you have open in Gmail or Outlook on the web, highlights the signs of phishing, and tells you why in plain English. Every check runs inside your browser.

WHAT IT DOES
• Highlights risky wording right in the email: urgency and threats, password requests, gift cards, wire transfers, changed bank details, pressure from "the boss".
• Checks the sender: look-alike domains, a display name that claims a brand from an unofficial address, a Reply-To that points somewhere else.
• Shows where a link really goes when you hover it, with every check listed. It never opens the link.
• Tags risky emails as Suspicious or Phishing in your inbox list, before you open them.
• Reads QR codes in email pictures and checks the link hidden inside.
• Flags disguised attachments such as invoice.pdf.exe, scripts, shortcuts and macro files.
• File checker: drop in a downloaded PDF, Office file, ZIP or web page before you open it.
• Reply Guard: warns you before you send a phone number, password, card or bank details to a suspicious sender.
• Warns when a coworker's account looks hacked (add your company's email domain in Settings).
• Checks links and senders against public lists of more than 500,000 known scam sites, on your computer.
• Learns from you: the "It's phishing" and "It's safe" buttons teach it senders, sites and wording.
• Learn: 24 short lessons on spotting phishing, with practice emails and quizzes.

PRIVACY
• In the default rule-based mode, your email never leaves your browser.
• No account, no ads, no analytics, no tracking.
• Read-only: it never sends, deletes, moves or edits email, and never opens links.
• The only download is a daily copy of public scam-site lists. Nothing about your email is sent with it.
• AI mode is optional and off by default. If you turn it on, a filtered copy of the email you open goes to the provider you choose: a local Ollama model (nothing leaves your computer), an OpenAI-compatible API, or Anthropic, using your own key.

WORKS ON
Gmail (mail.google.com) and Outlook on the web (outlook.live.com, outlook.office.com, outlook.office365.com, outlook.cloud.microsoft).

GOOD TO KNOW
Off the Hook is advisory. No detector catches everything, and some legitimate email will be flagged. Before you click, open, pay or share anything, confirm the request through a channel you already trust.

Off the Hook is an independent project, not affiliated with Google or Microsoft. Gmail is a trademark of Google LLC. Outlook is a trademark of Microsoft Corporation.
```

### Graphics

Every file is already the exact size the store asks for, full bleed, with no transparency. Rebuild them after a UI change with `node scripts/store_assets.js`.

| Dashboard field | File | Size |
|:--|:--|:--|
| Store icon | `icons/icon128.png` | 128×128 |
| Screenshot 1 | `store/screenshot-1-catches-phishing.png` | 1280×800 |
| Screenshot 2 | `store/screenshot-2-link-check.png` | 1280×800 |
| Screenshot 3 | `store/screenshot-3-inbox-tags.png` | 1280×800 |
| Screenshot 4 | `store/screenshot-4-file-checker.png` | 1280×800 |
| Screenshot 5 | `store/screenshot-5-privacy.png` | 1280×800 |
| Small promo tile | `store/promo-small-440x280.png` | 440×280 |
| Marquee promo tile | `store/promo-marquee-1400x560.png` | 1400×560 |

Upload the screenshots in that order: the first one is the listing's cover. The emails in them are the fictional samples from `dev/demo.html`.

### Links

- **Homepage URL:** `https://github.com/mrA2Z0101/OFF-THE-HOOK`
- **Support URL:** `https://github.com/mrA2Z0101/OFF-THE-HOOK/issues`

## 3. Privacy practices

**Single purpose:**

```text
Off the Hook detects signs of phishing in the email the user is reading in Gmail or Outlook on the web, and explains them. Every feature (highlights, link and QR code checks, attachment and file checks, inbox tags, reply warnings and the built-in lessons) serves that one purpose.
```

**Permission justifications:**

| Permission | Justification |
|:--|:--|
| `storage` | Saves the user's settings, their "It's phishing" / "It's safe" reports, contact memory (as salted hashes) and optional AI provider settings on the device. Nothing is synced. |
| Host: `mail.google.com`, `outlook.live.com`, `outlook.office.com`, `outlook.office365.com`, `outlook.cloud.microsoft` | Content scripts read the email the user has open (sender, subject, body, links, attachment names) and the inbox list previews, check them for phishing on the device, and draw the highlights and verdict panel on the page. |
| Host: `*.googleusercontent.com`, `*.office.net` | Gmail and Outlook serve the pictures inside emails from these image servers. The extension fetches a picture again from these hosts only, to decode a QR code on the device. It never contacts the sender's servers. |
| Host: `raw.githubusercontent.com`, `urlhaus.abuse.ch`, `phishing.army` | Downloads public lists of known phishing and malware sites once a day (Phishing.Database, OpenPhish, URLhaus, Phishing Army). The lists are text data. Nothing about the user or their email is sent. |
| Optional host: `https://*/*`, `http://*/*` | Requested at runtime, and only for the one address of the AI provider the user types into Settings (for example `http://localhost:11434` for a local Ollama model). Never requested unless the user turns on the optional AI mode. It is declared broadly because the provider address is chosen by the user. |

**Remote code:** No, I am not using remote code. All JavaScript ships in the package. Downloaded lists are parsed as text, and AI replies are parsed as JSON and never executed.

**Data usage.** The disclosure covers data handled on the device too, so tick what the extension reads even though the developer never receives it:

- **Personal communications:** the email that is open.
- **Website content:** text, links and pictures on the webmail page.
- **Personally identifiable information:** sender names and email addresses, in the reports and trusted-sender list the user keeps on the device.
- **Authentication information:** only the API key the user may add for their own AI provider.

Leave the rest unticked. Then tick all three certifications; each is true of the code as it stands:

- I do not sell or transfer user data to third parties, outside of the approved use cases.
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- I do not use or transfer user data to determine creditworthiness or for lending purposes.

**Privacy policy URL:** `https://github.com/mrA2Z0101/OFF-THE-HOOK/blob/main/PRIVACY.md`

## 4. Test instructions

No sign-in or account is needed. Paste this so the reviewer can see every feature without a mailbox:

```text
No account or setup is needed. To see it work:
1. Open any email in Gmail (mail.google.com) or Outlook on the web. A badge appears in the bottom-right corner with the verdict; click it for the findings. Suspicious wording is highlighted in the email, and hovering a link shows where it really goes.
2. Click the toolbar icon, then "Check a file" to open the file checker, or "Learn" for the lessons. Both work without an email open.
3. AI mode is optional and off by default (Settings > Detection mode). It is not needed for testing.
```

## 5. Before you press Submit

- [ ] The developer account has a verified contact email (Account tab) and two-step verification on its Google account. The store requires both.
- [ ] `PRIVACY.md` is on the `main` branch, so the privacy policy URL opens for someone who is signed out.
- [ ] Distribution: visibility (Public, Unlisted or Private), regions, and whether the item is free.
- [ ] Expect a longer review than usual: reading webmail pages and the optional `https://*/*` permission both get a closer look. The justifications above are what the reviewer reads.
