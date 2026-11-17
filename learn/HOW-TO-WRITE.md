# How to write a Learn post

Posts are plain text files in `learn/posts/`. You can write them in Notepad.

## Add a post in 3 steps

1. **Copy** one of the existing posts in `learn/posts/` and rename it, for example `fake-invoices.md`. Use only letters, numbers and dashes in the name.
2. **Write** your post (the format is below).
3. **List it** in `learn/posts/index.json`: add the file name to the list, with a comma after the line before it:

   ```json
   "posts": [
     "ai-writes-perfect-english.md",
     "the-10-second-check.md",
     "your-boss-can-be-faked.md",
     "fake-invoices.md"
   ]
   ```

Then reload the extension (`edge://extensions` → the reload arrow on Off the Hook) and open **Learn** from the toolbar popup. New posts get a **New** tag until someone opens them.

To check a post before publishing, put `draft: true` at the top. Drafts only show when you open the Learn page with `?drafts` at the end of its address.

## The top of every post

```
---
title: Fake invoices from real vendors
date: 2026-11-03
summary: One or two sentences shown on the post's card.
tags: invoices, vendors
---
```

Posts are listed newest first, by `date` (written year-month-day). `author:` is optional.

## Writing

| You type | You get |
|:--|:--|
| A blank line between paragraphs | Separate paragraphs |
| `## A heading` / `### A smaller heading` | Headings |
| `**bold**` / `*italic*` | **bold** / *italic* |
| `- item` or `1. item` | A list |
| `[text](https://example.com)` | A link (opens in a new tab) |
| `[text](#/the-10-second-check)` | A link to another post (its file name without `.md`) |
| `` `supplyco.com` `` | An address in code style |
| `==words==` | Highlighted words |
| `==words\|why==` | A red flag with an explanation (used in practice emails) |
| `> quoted text` | A quote |
| `---` on its own line | A divider |
| `![description](img/picture.png)` | A picture from `learn/posts/img/` |
| `\| A \| B \|` then `\|:--\|:--\|` then rows | A table (see `look-alike-letters.md`) |

### Call-out boxes

```
> [!TIP] Optional title
> The text of the box.
```

Use `[!TIP]` (lime), `[!NOTE]`, `[!WARNING]` (yellow) or `[!REDFLAG]` (red).

### A practice email

Readers see a mock email and click **Show red flags** to reveal your highlights and explanations.

````
```email
From: Microsoft 365 Admin <admin@m365-mailcenter.com>
To: you@yourcompany.com
Subject: Action required: storage limit reached
Verdict: phishing
Attachment: Storage_Report.pdf

Your mailbox is ==98% full|A classic reason to make you sign in==.

==Review storage settings|The button goes to m365-mailcenter.com==
```
````

`Verdict:` can be `phishing`, `suspicious` or `safe` (shown after the red flags are revealed). `Attachment:` is optional.

### A quiz question

````
```quiz
The question goes here.
- [ ] A wrong answer
- [x] The right answer
- [ ] Another wrong answer
Why: The explanation shown after they answer.
```
````

## Rules that keep it safe

- Pictures must be in `learn/posts/img/`. Pictures from websites aren't shown, so no site can see who reads the posts.
- Only `https://`, `http://`, `mailto:` and other-post links work. Anything else shows as plain text.
- Posts can't contain code: HTML in a post is shown as text.
- Don't use real people's names, real company names or real email addresses in examples. Use made-up ones like `supplyco.com` or `yourcompany.com`.
