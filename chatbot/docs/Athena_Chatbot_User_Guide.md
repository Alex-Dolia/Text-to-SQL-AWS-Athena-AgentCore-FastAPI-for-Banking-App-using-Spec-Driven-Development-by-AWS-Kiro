# Athena Data Chatbot — User Guide

*How to ask questions about company data in plain English, safely and
within your access permissions — including what to expect, what the
chatbot cannot do, and when to verify its answers.*

|                 |                                                                              |
|-----------------|------------------------------------------------------------------------------|
| **Audience**    | Business users, analysts, and anyone querying data through the chatbot       |
| **Applies to**  | Athena Data Chatbot (natural-language query assistant)                       |
| **Data scope**  | A few hundred tables across the bank's data lake                             |
| **Status**      | Companion to the Security Architecture Design (v2.1) and Implementation Plan |

## Table of Contents

- [1. What Is This Chatbot?](#1-what-is-this-chatbot)
- [2. What It Can and Can't Do](#2-what-it-can-and-cant-do)
  - [It can:](#it-can)
  - [It cannot / will not:](#it-cannot--will-not)
- [3. Getting Started](#3-getting-started)
  - [3.1 Logging In](#31-logging-in)
  - [3.2 Session Basics](#32-session-basics)
- [4. Asking Good Questions](#4-asking-good-questions)
  - [Example Interaction](#example-interaction)
  - [Tips for Better Results](#tips-for-better-results)
- [5. Understanding Your Results](#5-understanding-your-results)
- [6. Accuracy and Limitations — What You Need to Know](#6-accuracy-and-limitations--what-you-need-to-know)
  - [6.1 The Chatbot Can Be Wrong](#61-the-chatbot-can-be-wrong)
  - [6.2 When to Verify Before Acting](#62-when-to-verify-before-acting)
  - [6.3 What the Chatbot Is Designed to Get Right](#63-what-the-chatbot-is-designed-to-get-right)
- [7. How Your Data Access Is Protected](#7-how-your-data-access-is-protected)
- [8. Common Situations & What to Expect](#8-common-situations--what-to-expect)
- [9. Getting Help](#9-getting-help)
- [10. Frequently Asked Questions](#10-frequently-asked-questions)

[⬆ Back to top](#table-of-contents)

## 1. What Is This Chatbot?

This chatbot lets you ask questions about company data in plain English
instead of writing SQL or knowing which of the several hundred
underlying tables holds the answer. You type a question, and the system:

- Works out what you're really asking (even if you don't know the exact
  table or column names)

- Looks up only the data you're personally authorised to see

- Writes and runs a safe, read-only query behind the scenes

- Returns a formatted table and a short plain-English summary

> ***Note:** You never need to know a table name, a column name, or any
> SQL. Just ask your question the way you'd ask a colleague.*


[⬆ Back to Table of Contents](#table-of-contents)

## 2. What It Can and Can't Do

### It can:

- **Answer questions across hundreds of tables** without you needing to
  know which one holds the data — the system searches table and column
  descriptions to find the right source automatically.

- **Ask you a follow-up question** if your request is ambiguous (e.g.
  "which region?" or "do you mean this quarter or this year?") — up to
  three short clarifying questions before it proceeds.

- **Show only the rows and columns you're authorised to see** —
  restrictions are enforced by the underlying data platform itself, not
  just by the chatbot's own logic.

- **Tell you how fresh the data is** with a "data current as of"
  timestamp on every result.

- **Give you a plain-English summary** alongside the data table, so you
  can sanity-check the numbers at a glance.

### It cannot / will not:

- **Change, delete, or write data** — the chatbot is strictly read-only.
  It cannot modify any table under any circumstances.

- **Show you data outside your permissions** — even if you phrase a
  question cleverly or repeatedly, the system cannot be talked into
  showing unauthorised data. This is enforced independently of the
  chatbot's own "reasoning" by the database platform itself.

- **Run unlimited or extremely expensive queries** — very large scans
  are automatically blocked with a cost estimate and a suggestion to
  narrow your question (e.g. by adding a date range or a specific
  region).

- **Guarantee the data is real-time** — there's always a small delay
  between when data lands in the warehouse and when it's queryable.
  Check the freshness timestamp on any result you plan to act on.

- **Guarantee its answers are always correct** — the chatbot uses an AI
  model to translate your question into a database query. The model is
  accurate most of the time but not infallible. See Section 6 for
  guidance on when to verify before acting on results.


[⬆ Back to Table of Contents](#table-of-contents)

## 3. Getting Started

### 3.1 Logging In

You sign in using your normal corporate credentials (single sign-on) —
there is no separate chatbot password. Multi-factor authentication is
enforced the same way as your other corporate applications.

### 3.2 Session Basics

|                                   |                                                                                               |                                                                                      |
|-----------------------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| **What**                          | **How it works**                                                                              | **Why it matters to you**                                                            |
| Login session                     | Your sign-in token lasts 15 minutes at a time and refreshes automatically while you're active | You won't usually notice this — it's invisible unless your connection is interrupted |
| Idle timeout                      | If you don't interact with the chat for 45 minutes, your session ends automatically           | Protects your account if you walk away from your desk without locking it             |
| Maximum session length            | Up to 8 hours for a single continuous conversation                                            | Long analysis sessions are supported without needing to re-authenticate repeatedly   |
| Leaving the company / role change | Access is revoked automatically within 5 minutes of your access being deprovisioned by IT     | You can't use the chatbot after you've left, even mid-session                        |


[⬆ Back to Table of Contents](#table-of-contents)

## 4. Asking Good Questions

Because the chatbot searches across several hundred tables, the way you
phrase a question genuinely affects how quickly and accurately it finds
the right data.

### Tips for Better Results

- **Use business language, not technical terms.** "Show me EMEA sales
  last quarter" works better than trying to guess a table name — the
  system maintains a business glossary that maps everyday terms to the
  correct technical tables and columns.

- **Be specific about time periods and regions.** "Last quarter", "Q2
  2026", or "the last 30 days" all help the system apply the right
  filters and avoid scanning more data than necessary. Unspecific
  questions (e.g., "show me all transactions") may be blocked because
  they would scan too much data.

- **Expect a clarifying question sometimes — that's normal.** If your
  question could reasonably map to more than one table or definition
  (e.g. "revenue" might mean gross or net), the chatbot will ask you to
  clarify rather than guess. It will ask at most three short follow-up
  questions before proceeding.

- **One question at a time works best.** Complex multi-part requests are
  more reliable when broken into individual questions.

- **If you get an unexpected answer, try rephrasing.** A more specific
  question with explicit time filters and a clear metric name often
  improves accuracy.

### Example Interaction

**You:** "What was our EMEA sales revenue last quarter?"

**Chatbot:** "I found sales data broken down by both gross and net
revenue for EMEA. Did you want gross revenue, net revenue, or both?"

**You:** "Net revenue"

**Chatbot:** Returns a formatted table with a short narrative summary
and a "data current as of" timestamp.


[⬆ Back to Table of Contents](#table-of-contents)

## 5. Understanding Your Results

- **Formatted table + narrative summary.** Results are shown both as a
  data table and as a short plain-English explanation, so you can
  sanity-check the numbers at a glance.

- **Data freshness timestamp.** Every result includes a "data current as
  of" indicator. Always check this before making a decision based on the
  numbers — some source systems update daily, others less frequently. If
  a result is based on data from several days ago, that matters for time-
  sensitive decisions.

- **Sensitive information is automatically redacted.** The system scans
  every result for personal or sensitive information before showing it
  to you, and redacts anything that shouldn't be visible to you, even if
  it's technically part of the tables you queried. Redacted fields appear
  as `[REDACTED]`.

- **Results only reflect what you're authorised to see.** If a colleague
  on a different team asks the exact same question, they may see
  different (or fewer) rows — this is expected and by design, not an
  error.

- **Row count is shown.** The number of rows returned is always shown
  alongside the results. If you receive zero rows but expect data, try
  narrowing your question or checking the freshness timestamp.


[⬆ Back to Table of Contents](#table-of-contents)

## 6. Accuracy and Limitations — What You Need to Know

This section is important. Please read it before using the chatbot for
any decision that involves significant consequences.

### 6.1 The Chatbot Can Be Wrong

The chatbot uses an AI model (a large language model) to translate your
natural-language question into a database query. This model is accurate
for the vast majority of questions but is **not infallible**. Specific
ways it can fail:

**Logical translation errors.** The model may correctly understand your
question but translate it into SQL that returns plausible-but-wrong
numbers. For example, it might sum a column that should be averaged, or
join two tables on the wrong column. The data returned is real data from
the real database — but it may not be the right data for your question.

**Missing or wrong metric.** Business terms like "revenue", "profit", or
"sales" may map to multiple underlying columns. If the model picks the
wrong one and you didn't get a clarifying question, the answer may be
technically correct for a different definition than you intended.

**Schema gaps.** If the underlying table descriptions or business
glossary don't include the exact term you used, the model may choose the
closest-sounding table, which could be the wrong one.

**The system automatically detects and corrects some errors.** If the
query it generates fails to run, it will retry up to twice. If it still
fails, you'll get a clear "couldn't complete this request" message and a
suggestion to rephrase. However, a query that runs successfully can
still return logically incorrect results — the system cannot detect that
kind of error automatically.

### 6.2 When to Verify Before Acting

**Always verify before:**
- Making a business decision with financial consequences (budgeting,
  forecasting, external reporting)
- Sharing results with external stakeholders or regulators
- Acting on numbers that seem surprising or unexpectedly large/small

**How to verify:**
- Sanity-check the numbers against something you already know (e.g. last
  quarter's known figure)
- Review the generated SQL if it's displayed — does it match your
  question?
- Run the same question slightly differently and see if the answer is
  consistent
- If in doubt, contact your data team to confirm

**A plausible-looking answer is not necessarily a correct answer.** The
chatbot formats its responses to look clear and professional. This can
make wrong answers look credible. The formatting is not evidence of
accuracy.

### 6.3 What the Chatbot Is Designed to Get Right

Some things are handled deterministically (not by the AI model) and can
be relied upon:

- **Access control is always correct.** You will never see data you're
  not authorized to see, even if the AI makes errors. This is enforced
  by the database platform itself, independently of the model's
  decisions.

- **Query type is always safe.** The chatbot can only run read-only
  queries. It is structurally incapable of modifying data.

- **Cost limits are always enforced.** Very expensive queries are always
  blocked before they run, regardless of what the model generates.

- **Your session is always protected.** Authentication and session
  security operate independently of the model.

The distinction matters: the AI is responsible for the *quality* of the
answer (which metric, which table, which time range). The data platform
is responsible for *safety* (access control, data integrity, query
limits). Trust the latter completely; verify the former for high-stakes
decisions.


[⬆ Back to Table of Contents](#table-of-contents)

## 7. How Your Data Access Is Protected

In plain terms, there are two independent layers of protection standing
between your question and the underlying data:

- **Layer 1 — Permission check before anything runs.** The system checks
  whether you're allowed to ask this kind of question about this kind of
  data before it ever touches the data itself.

- **Layer 2 — Enforcement inside the database itself.** Even after Layer
  1 approves a request, the database engine independently double-checks
  your specific row and column permissions while running the query —
  this is the same protection that applies if you ran a query yourself
  directly, and it cannot be bypassed by how you phrase a chatbot
  question.

> ***Note:** Because both layers are independent, a mistake or clever
> prompt affecting one layer still can't expose data you're not
> authorised to see — the other layer catches it. This is the same
> principle as a bank vault having both a guard and a separate
> combination lock.*

**Your question text is also safety-scanned.** Before the model processes
your question, an automatic content filter checks for attempts to
manipulate the AI. If it detects such an attempt, your request is
declined with a generic message. This protects both you and the bank.

**Everything is logged for 7 years.** Every question, every result, and
every access decision is recorded in a tamper-proof audit log. This
protects you — it proves what was actually asked and returned — and
protects the bank. If you're concerned about a specific result, the
support team can look up exactly what happened.


[⬆ Back to Table of Contents](#table-of-contents)

## 8. Common Situations & What to Expect

|                                                                         |                                                                                                               |                                                                                              |
|-------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| **Situation**                                                           | **What happens**                                                                                              | **What you should do**                                                                       |
| Your question is ambiguous                                              | Chatbot asks a short clarifying question (up to 3 rounds)                                                     | Answer the clarifying question, or rephrase more specifically                                |
| You ask for data you're not authorised to see                           | Request is politely declined — no partial or "almost" data is shown                                           | Contact your manager or data governance team if you believe you should have access           |
| Your query would be very expensive to run                               | Chatbot explains the estimated scan size in GB and suggests narrowing the question (e.g. adding a date filter) | Add a time range, region, or other filter and try again                                      |
| The system generates an incorrect query internally                      | It automatically retries once or twice before showing you anything — you won't normally notice this happening | If you get a graceful "couldn't complete this request" message after retries, try rephrasing |
| A data source is temporarily disabled for maintenance/incident response | You'll get a clear "this data source is temporarily unavailable" message rather than an error or wrong answer | Try again later, or contact support if it persists                                           |
| You've been idle for 45 minutes                                         | Your session ends automatically                                                                               | Simply sign in again to start a new session                                                  |
| The answer looks wrong or surprising                                    | The model may have misinterpreted your question or chosen the wrong metric/table                              | Try rephrasing with more specific terms; verify against a known figure; contact data team    |
| You receive zero rows but expect data                                   | May be a date filter too narrow, wrong time period, or the data truly doesn't exist in accessible tables     | Check the freshness timestamp; try a different time range; ask a broader question first      |
| A field shows `[REDACTED]`                                              | The system detected a sensitive value in that field that you're not authorized to view                        | This is expected; if you believe you should see this data, contact the data governance team  |
| You're sending questions very quickly                                   | After 30 requests per minute, you'll see a brief wait message — the limit resets automatically              | Wait a few seconds and continue; this protects the system for all users                      |


[⬆ Back to Table of Contents](#table-of-contents)

## 9. Getting Help

If you're stuck, seeing unexpected behaviour, or believe a permissions
issue is incorrect, escalate through your normal IT service desk / data
platform support channel rather than trying to work around the chatbot.

**When contacting support, include:**
- The `trace_id` shown in any error message — this lets the support team
  look up exactly what happened with your specific request
- The question you asked (or a description of it)
- What result you expected vs. what you received
- The approximate time of the request

Every query you make is logged for audit purposes (this protects you as
much as the bank — it proves what was actually asked and returned), so
support teams can look up exactly what happened with your session.

**For data access requests** (e.g., you believe you should have access
to a table you can't reach): contact your manager to initiate an access
request through the Data Governance portal. Support cannot grant data
access directly.


[⬆ Back to Table of Contents](#table-of-contents)

## 10. Frequently Asked Questions

**Can the chatbot see or use data from tables I don't have access to?**
No. Even if such data exists in the same underlying systems, the
database-level enforcement described in Section 7 applies independently
of anything the chatbot itself decides. This cannot be bypassed by
rephrasing your question.

**Why did I get a different answer than my colleague for the same
question?** This is expected if you have different data permissions —
you may be authorised to see different rows or columns of the same
table. It can also occasionally indicate that the AI interpreted your
question differently. If you suspect the latter, check whether you each
got the same row count.

**Is my question text stored anywhere?** Yes — for audit and compliance
purposes, every question and result is logged in a secure, tamper-proof
record for seven years. This is standard practice for any system
touching bank data, and mirrors what already happens when you run a
query manually.

**Can I ask it to make changes to data?** No — the chatbot is read-only
by design and has no technical ability to modify, delete, or create
records under any circumstances.

**What happens if I ask something completely unrelated to company
data?** The chatbot will let you know the question is outside its scope
rather than attempting to answer from general knowledge.

**The chatbot gave me a number that seems wrong. What should I do?**
If the answer seems surprising, don't assume it's right. Note the
`trace_id` from the response, then verify the number through another
means (a known report, your data team, or a more specific follow-up
question). If it's consistently wrong for a particular type of question,
report it to support — that helps improve the system over time.

**Why does the chatbot sometimes give different answers to the same
question?** For most queries it should be consistent, since the model
runs at temperature=0 (deterministic). If you're seeing different
answers, check whether the data freshness timestamps are different
between the two responses — the underlying data may have been updated
between your two queries.

**How do I know what tables are available?** You can ask the chatbot
directly: "What data do I have access to?" or "What topics can I query?"
It will list the tables and domains accessible to you based on your
current permissions.

**Can the chatbot remember things from a previous session?** No — each
session starts fresh. The chatbot does not retain context between
separate login sessions. Within a single session (up to 8 hours), it
remembers your conversation history so you can ask follow-up questions.

**What does "[REDACTED]" mean in my results?** It means the system
detected sensitive information (such as personal data) in that field
that your current role doesn't permit you to view. The rest of the
results are unaffected. If you believe you should have access to that
data, contact the data governance team.


[⬆ Back to Table of Contents](#table-of-contents)
