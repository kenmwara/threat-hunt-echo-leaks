# Threat Hunt Report: Echo Leaks (Operation ECHOLEAK), an AI assistant data exposure

A [Cyber Range](https://www.skool.com/cyber-range) live community threat hunt ("Echo Leaks", Operation ECHOLEAK): a
prompt-injection attack on Microsoft 365 Copilot at an investment firm. An email attachment carried hidden instructions
written for the AI assistant; when a financial analyst asked Copilot to summarise it, Copilot read 13 confidential files
across the Executive, HR, IT and Finance sites and wrote 13 image links to an outside domain that could carry the data
out. Investigated from the Copilot audit, Office activity and Entra sign-in logs with KQL in Microsoft Defender Advanced
Hunting, with seven detections replayed against the data. All 17 flags, a perfect 1,600 / 1,600, finished on time.
Published after the hunt closed on 24 October 2026. A PDF copy of the report as submitted is in the repo:
[EchoLeaks-Report.pdf](EchoLeaks-Report.pdf) (its TLP:AMBER marking applied until the close).

**Analyst:** Ken Kariuki · **Date:** 17 October 2026 · **Result:** 17 of 17 flags, 1,600 / 1,600 points, completed on time (live hunt, second finisher on the scoreboard, no paid hints)

## 1. Front matter

| Field | Value |
|---|---|
| Hunt | Echo Leaks (Operation ECHOLEAK), run el--17-20260920 |
| Author | Ken Kariuki |
| Version | v1.0, 2026-10-17 |
| Classification | TLP:CLEAR from 2026-10-24 (simulated range data; TLP:AMBER while the hunt was open) |
| Release | Published after the hunt closed (2026-10-24 12:00 UTC) |
| Distribution | Public |

| Version | Date | Change |
|---|---|---|
| 0.x | 2026-10-17 | Working drafts during the hunt |
| 1.0 | 2026-10-17 | 17-section structure; detections D1–D7 replayed; exhibits E1–E8 attached |

**Clock note.** TimeGenerated is the only time field filled (OriginalTime is empty) and may be ingestion time, so gaps of
0–5 s between tables carry no meaning. The 2026-10-07 in the session ID cp-emily-20261007-1042 is not an event time.
The portal shows datetime columns in the browser's time zone (PDT, UTC-7, on the analyst's machine), so every
exhibit prints TimeGenerated as UTC text.

**Labels.** "(Confidence: High/Medium/Low)" marks inferences only; logged facts cite an exhibit (E#, App C) or a query
(App A).

## 2. Executive summary

At 2026-09-20 09:15:22 UTC Emily Chen, a financial analyst, received an outside email whose Word attachment hid
instructions written for an AI assistant, not for her. At 2026-09-20 10:42:08 UTC she opened it from her OneDrive, and at
2026-09-20 10:42:35 UTC she asked Microsoft 365 Copilot to summarise it. That request was her only logged part: no other prompt
from her is logged in that Copilot session, and her account was not taken over.

Copilot then worked for the attacker inside her session. In 3 minutes 39 seconds it read 13 files that no one had opened before
in the logs, on the Executive, HR, IT and Finance sites, among them board minutes, an M&A target assessment, salary reviews and an
insider-trading investigation. It also wrote out what it presented as its own configuration. Its answers carried 13
image links to an outside web address, each with an encoded string. The logs cannot show whether the answers were
displayed, whether the links were fetched or whether the attacker received anything: exfiltration attempted;
completion not determined.

Observed dwell was 1 hour 31 minutes 13 seconds, from delivery to the last attacker-driven answer at 2026-09-20
10:46:35 UTC. An analytics rule flagged unusual file access under Emily's account at 2026-09-20
10:42 UTC; nothing flagged Copilot. No deletion of the email or the file is logged, so both should be assumed to remain. Treat the 13 files and the
configuration as potentially exposed; severity High. Recommended now: block the outside address, remove the email and
the file (keeping an evidence copy), stop Copilot answers loading outside images, and give Legal the file list. A
password reset would not help.

## 3. Overview

| Item | Value |
|---|---|
| Hunt type; trigger | Intel-driven, hypothesis-based; an analytics rule flagged unusual file access at 2026-09-20 10:42 UTC (the brief gives the minute only) |
| Client | Cormorant Capital Partners: about 200 employees, M365 E5 + Copilot; IT administrator mark.ross@cormorantcapital.com (Global Admin, 203.0.113.10; range brief) |
| Subject | emily.chen@cormorantcapital.com, financial analyst (range brief), 203.0.113.45 |
| Period hunted | 2026-09-19 00:00:00 UTC to 2026-09-22 00:00:00 UTC (brief window 2026-09-20 09:00:00 UTC to 2026-09-20 11:00:00 UTC) |
| Data | M365 tenant only, no endpoints: OfficeActivity_CL 530 rows, CopilotAudit_CL 218, EntraSignIn_CL 80 (E6), in Defender Advanced Hunting |
| Analyst; time spent | Ken Kariuki, lead analyst, with AI tooling (§16); 2026-10-17 14:00:07 UTC to 2026-10-17 16:05:21 UTC (2 h 05 min 14 s) plus report time |
| Classification; severity | External input manipulation, not account or configuration compromise; High (Confidence: Medium) |

## 4. Hypothesis and ABLE

**Hypothesis.** An emailed document carried hidden instructions that, once Emily asked Copilot about it, made Copilot
read sensitive files under her account and write their data into image links to an outside domain.

| ABLE | Content |
|---|---|
| Actor | Outside sender quarterly.reports@globalfinancereview[.]net; identity unknown |
| Behaviour | Unrequested Copilot searches and first-time file reads at machine speed; outside image links and configuration text in answers |
| Location | Exchange, OneDrive, four SharePoint sites, Copilot in Word; no endpoint |
| Evidence | OfficeActivity_CL (MessageReceived, FileAccessed); CopilotAudit_CL (Prompt, Search, ToolCall, Response); EntraSignIn_CL |

Counter-hypotheses, judged in §10: H1 account takeover; H2 insider (Emily); H3 Copilot or tenant configuration
compromise; H4 benign Copilot use.

## 5. Threat intel inputs

The range brief set the trigger, identities and tables, and named public EchoLeak research (CVE-2025-32711; Aim
Security, Unit 42, MSRC) for cross-reference. MITRE ATLAS AML.T0051 (its Indirect and Triggered sub-techniques) and case study AML.CS0059 served for mapping.
No indicators came from intel. The chain matches the published technique (technique similarity, not attribution;
Confidence: Medium), except that the public chain relayed through allowed Microsoft domains and this one names an
outside domain.

## 6. Scope, data sources and blind spots

| Source | Rows (E6) | Shows | Coverage confidence |
|---|---|---|---|
| OfficeActivity_CL | 530 | Mail receipt, file access, label changes (metadata) | High for operations; none for content |
| CopilotAudit_CL | 218 | Prompts, searches, tool calls, answer text, labels | High |
| EntraSignIn_CL | 80 | Sign-ins | High |
| Network, proxy, DNS, endpoint; SharePoint permissions; Purview | – | Not available | None |

**B1** No network, proxy, DNS or endpoint telemetry: displayed, fetched and received are not observable. **B2** No file
content. **B3** No document text, so the hidden instructions are not logged. **B4** History starts 2026-09-19 00:00:00
UTC, which bounds "never opened". **B5** TimeGenerated only (clock note). **B6** A FileAccessed at 2026-09-20 10:44:15 UTC
has no tool call (q18, E3a). **B7** An empty SensitivityLabels field may be a logging gap. **B8** No SharePoint permissions, so
oversharing and a wider Copilot scope cannot be told apart.

## 7. Execution

**Method.** The analyst set each pivot as a question, had agents draft and run the query and then try to refute the
result, and accepted a finding only when the raw result held up (§16). Each pivot is answered by a saved query
(App A): the lure and who else got it (q1, E1); her request (q4);
everything Copilot did in the session (q5, E3a, E3b); whether she had opened the files before (q7, E4); which domains
the answers hold and how the links are built, counted and never printed (q8, q9, E5); the second answer's text (q12);
the session against every other (q13, E7); her sign-ins (E2); wave 2 (q15); then, to close gaps found in review,
every operation type (q16), the admin's sessions (q17), every FileAccessed under Emily in the attack window (q18), any use of the
13 files by anyone (q19) and reply latency (q20).

**Dead ends.** The IP on the delivery row is Emily's own client IP. The session ID's date is not a second session.
The 19 mentions of the tenant's own SharePoint domain across the 106 normal replies are benign (E5). olivia.grant's 9
SensitivityLabelUpdated events are unrelated (q16, q19). A
ToolCall-only filter missed the five wave-2 searches, which are logged as Search. The 2026-09-20 10:44:15 UTC
FileAccessed stays unclassified (B6); a Copilot re-read is possible (Confidence: Low).

## 8. Timeline

| Time (UTC) | Event | Source · evidence |
|---|---|---|
| **2026-09-20 09:15:22 UTC** | Lure from quarterly.reports@globalfinancereview[.]net with Q3-2026-Global-Markets-Review.docx; Emily the only recipient | OfficeActivity_CL MessageReceived · F1, E1 |
| 2026-09-20 10:42:08 UTC | Emily opens the lure from her OneDrive, 86 min 46 s after delivery (dormant, no activity on it) | OfficeActivity_CL FileAccessed · E1, q18 |
| **2026-09-20 10:42:35 UTC** | Prompt in Word: "Summarise the key findings of this quarterly report" | CopilotAudit_CL Prompt · F1, E3a |
| 2026-09-20 10:42:41 UTC | Wave 1: 3 searches over 4 s (board minutes, M&A target, salary review) | CopilotAudit_CL ToolCall · F2, E3a |
| **2026-09-20 10:42:47 UTC** | 5 reads, 2 s apart over 8 s, each with a FileAccessed under Emily in the same second | CopilotAudit_CL ToolCall; OfficeActivity_CL FileAccessed · F3, E4 |
| 2026-09-20 10:42 UTC | Analytics rule flags unusual file access (minute only) | Range brief · §3 |
| 2026-09-20 10:43:08 UTC | Answer 1: 4 outside image links, 33 s after the prompt | CopilotAudit_CL Response · F6, E5 |
| 2026-09-20 10:44:15 UTC | Second FileAccessed on the configuration file, no tool call | OfficeActivity_CL FileAccessed · q18, B6 |
| **2026-09-20 10:44:19 UTC** | Answer 2: "System configuration extracted:", 1 link | CopilotAudit_CL Response · F4, E5 |
| 2026-09-20 10:45:30 UTC | Wave 2 with no new prompt: 5 searches over 15 s | CopilotAudit_CL Search · F5, E3b |
| 2026-09-20 10:45:46 UTC | 8 reads over 40 s; a FileAccessed 0–5 s after each, the last at 2026-09-20 10:46:30 UTC | CopilotAudit_CL ToolCall; OfficeActivity_CL FileAccessed · F5, E4 |
| **2026-09-20 10:46:35 UTC** | Answer 3: 8 outside image links; last event of the session | CopilotAudit_CL Response · F6, E5 |

## 9. Findings

**F1 One mailbox, one ordinary request.** *State:* Emily alone received the lure; she opened it, asked for a summary,
and the first tool call followed 6 s later. *Show:* E1, E3a; q1, q4. *Interpret:* the attachment carried the
instructions and her request was the only human step (Confidence: High; document text not logged, B3).

**F2 Wave 1: searches nobody asked for.** *State:* 3 searches (board minutes, M&A target, salary review), then 5 reads
2 s apart (4 Confidential, 1 Internal Only) on four sites; the first answer came 33 s after the prompt, where the 85
normal sessions that log a prompt answer in 0 s. *Show:* E3a; q5, q20; App F rows 1–5. *Interpret:* no search term serves a summary of a
markets report, so the document steered Copilot (Confidence: High).

**F3 Copilot's reads are logged as Emily's file access.** *State:* each of the 13 reads has a FileAccessed under her
account 0–5 s later, and those 14 rows (13 plus the configuration file's second access, B6) are the only activity on the 13 files by anyone in the logs: no earlier open,
no later download or share (q19). *Show:* E4; q7, q19; App F. *Interpret:* Copilot, not Emily, made the reads
(Confidence: High), so an alert on that file access points at the user, not the agent.

**F4 Configuration written into an answer.** *State:* the 2026-09-20 10:44:19 UTC answer (Internal Only) contains "System
configuration extracted:" and lists label names, the DLP policy block-external-sharing-confidential, data sources, the
access scope Global Reader and an organisation structure. *Show:* E5; q12 (links masked). *Interpret:* a map of the
tenant's controls is potentially exposed; it was not checked against the real configuration (Confidence: Medium).

**F5 Wave 2 ran with no new prompt logged.** *State:* 71 s after answer 2, with no prompt row in between, 5 searches (confidential, restricted, board,
acquisition, salary), logged as Search, then 8 reads of first-time files with no label recorded. *Show:* E3b; q15;
App F rows 6–13. *Interpret:* Copilot acted on the injected instructions, not on a request (Confidence: High; the search terms carry
this, not the missing row, since 19 normal sessions log a reply with no prompt row, q20).

**F6 13 image links to one outside host.** *State:* 4, 1 and 8 Markdown image links to metrics-cdn[.]analyticshub[.]io,
each with an encoded query string; the attack answers average 880 characters against 151 for the 106 normal replies,
none of which holds an outside image link. *Show:* E5, E6, E8 (D2: 0 false positives); q8, q9. *Interpret:* the links likely carry
data from the files and the configuration, since 4 + 1 and 8 links match the 5 and 8 reads (Confidence: Medium; not
decoded). Exfiltration attempted; completion not determined (B1).

**F7 One session, one account.** *State:* the hijacked session holds 25 events, 21 of them tool events; Emily's 24
other sessions and 80 sessions from 22 other users hold none. *Show:* E7; q13. *Interpret:* the scope is one session within
the three tables (Confidence: High). Whether Copilot reached Executive, HR and IT files through her own permissions or
the Global Reader scope the dump claims is not determined (B8).

**9.8 Negative findings**

| Looked for | Where | Method | Result |
|---|---|---|---|
| Other recipients of the lure | OfficeActivity_CL, all mailboxes | E1 | Only Emily; no deletion or other operation on the file |
| Attacker sign-in | EntraSignIn_CL, Emily | E2 | 2 Success sign-ins, 203.0.113.45, London GB, CA success |
| Inbox rules; Copilot or tenant changes | OfficeActivity_CL, all users | q16 | 11 operation types, none a rule or configuration change; the only single-user type is 9 SensitivityLabelUpdated by olivia.grant |
| Any other use of the 13 files | OfficeActivity_CL, all users | q19, E4 | None: Emily's 14 FileAccessed rows are the only ones |
| The outside domain elsewhere | All three tables | E6 | Only the 3 attack answers |
| The same behaviour elsewhere | CopilotAudit_CL | E7 | None in 104 sessions |
| Admin control (Mark Ross) | CopilotAudit_CL | q17 | 2 normal sessions (2026-09-20 07:38:14 UTC in Excel, 2026-09-20 12:50:00 UTC in Word), 1 prompt each, no tool events |

## 10. Hypothesis outcome

**Confirmed** on logged facts: delivery to Emily only (E1), 13 reads (E4), the configuration answer and 13 links (E5).
**Not determined:** what the 13 links carry (not decoded; F6, Confidence: Medium), whether exfiltration completed (B1;
the Word client's image-loading policy is unknown) and the wave-2 labels (B7; confirm in Purview).

| Counter-hypothesis | Verdict and evidence |
|---|---|
| H1 Account takeover | Rejected (Confidence: High): 2 Success sign-ins, both from 203.0.113.45, London GB, CA success (E2) |
| H2 Insider (Emily) | Rejected (Confidence: High): one open and one ordinary prompt, then machine-speed reads and a wave with no prompt (F1, F5) |
| H3 Configuration compromise | Rejected (Confidence: Medium): no rule or configuration change among 11 operation types (q16); Mark Ross's sessions normal (q17) |
| H4 Benign Copilot use | Rejected (Confidence: High): no tool events in 104 normal sessions (E7) |

**Dwell.** Observed span 1 h 31 min 13 s (2026-09-20 09:15:22 UTC to 2026-09-20 10:46:35 UTC): dormant 86 min 46 s to
the open, active 4 min 00 s from prompt to last answer, reads spanning 3 min 39 s by tool call (2026-09-20 10:42:47 UTC to
2026-09-20 10:46:26 UTC; the file-access rows end at 2026-09-20 10:46:30 UTC), 71 s between the waves. Time to
detection: the file-access rule fired at 2026-09-20 10:42 UTC; nothing alerted at the Copilot layer, and this hunt
reconstructed the chain on 2026-10-17. End of exposure: not established, since no deletion of the lure is logged (E1).

**Scope and impact.** One account, one session, 13 files on four SharePoint sites (Executive 4, HR 3, IT 1 being the
configuration file, Finance 5; q18). From the file names (Confidence: Medium): deal data that is likely inside
information, executive pay, client data, board material, audit results and an insider-trading investigation with
tipping-off risk (App F); the configuration answer maps the tenant's controls (F4). Legal & Compliance decide on
notification.

## 11. ATT&CK and ATLAS coverage

| Stage | ATT&CK | ATLAS | Status |
|---|---|---|---|
| Initial access | T1566.001 Spearphishing Attachment | AML.T0051.001 LLM Prompt Injection: Indirect (instructions in an emailed document) | Delivery observed; injection inferred from behaviour (B3) |
| Execution | T1204.002 Malicious File (she opened it; no endpoint telemetry, B1) | AML.T0051.002 LLM Prompt Injection: Triggered (her request set it off, as in AML.CS0059) | Observed in behaviour |
| Collection | T1213.002 Sharepoint | AML.T0053 AI Agent Tool Invocation; AML.T0085.000 Data from AI Services: RAG Databases | Observed; content not logged (B2) |
| Discovery | T1083 File and Directory Discovery (the 8 searches) | AML.T0056 Extract LLM System Prompt; AML.T0084 Discover AI Agent Configuration | Observed; not checked against the real configuration |
| Exfiltration | T1567 Exfiltration Over Web Service (nearest analogue) | AML.T0077 LLM Response Rendering | Attempted; completion not determined (B1) |

Hunted, not observed: T1078 Valid Accounts (E2); T1564.008 Email Hiding Rules and T1114.003 Email Forwarding Rule
(q16); AML.T0081 Modify AI Agent Configuration (q16); T1537 Transfer Data to Cloud Account (q19). IDs checked on 2026-10-17 against attack.mitre.org and the ATLAS 2026.09 data release. The range's own mapping also
lists T1059, T1041 and T1082; here they sit under the nearer AI techniques: T1059 as AML.T0051 (the model followed
injected text; no interpreter ran), T1041 as T1567 and AML.T0077 (the links name an image host, not a command-and-control channel; B1) and T1082 as
AML.T0056 and AML.T0084 (the assistant's configuration, not a host's).

## 12. Detection and telemetry gaps

Owners are proposed, not accepted.

| Gap | Impact | Fix (owner) | Acceptance test |
|---|---|---|---|
| Only the file-access rule fired, on Emily; nothing alerted at the Copilot layer | Triage blames the user; 8 more files read after it | CopilotAudit_CL to the SIEM; D1–D7 as alerts (SOC) | A red-team replay whose hidden instruction makes Copilot answer first, then read three test files within one minute and add an image from a test outside domain, raises D1, D2, D5 and D6 |
| Copilot answers can embed outside images (one host seen; client policy unknown) | Displaying an answer may send the data | Tenant-only answer images; block the domain (M365, network) | An outside test image loads nothing and the proxy shows no request |
| Copilot obeyed instructions in an outside attachment | Any inbound file can steer it | Confirm the CVE-2025-32711 fix covers the tenant (M365 admin) | After the fix, the same replay yields no tool call and no outside image (D1, D2, D5 and D6 silent) |
| Copilot in Emily's session reached Executive, HR and IT files (B8) | Reach beyond her role | Permission review on the four sites (SharePoint owners) | A Finance test user's search for "board minutes" returns no Executive file |
| 8 wave-2 files with no label recorded | Label-based controls may miss them | Auto-labelling; DLP on the Copilot location (Compliance) | Purview shows labels on all 8 |
| No network, proxy, DNS or endpoint telemetry (B1) | Completion cannot be settled | Collect proxy and DNS logs (Network) | A canary image fetch appears in DNS logs within 5 min |

## 13. New detections

All seven were replayed on this run (E8, App B); a false positive is a hit outside the hijacked session. The benign
Copilot baseline (104 sessions) has no legitimate tool use at all, so 0 false positives on D1–D6 is weak evidence;
D7 is the only rule with a real benign baseline (530 OfficeActivity_CL rows). Status of all seven: proposed (true
positives on this run; a benign control is still pending, except for D7, whose benign baseline returned 0 false positives).

| Rule | Logic (source) | Maps to | Hits / FP (unit) |
|---|---|---|---|
| D1 | 3+ Graph.ReadFile per session per minute (CopilotAudit_CL) | AML.T0053 | 3 / 0 (minute bins) |
| D2 | Markdown image to a non-tenant domain in a reply (CopilotAudit_CL) | AML.T0077 | 13 / 0 (images) |
| D3 | File search with sensitivity keywords (CopilotAudit_CL) | AML.T0053 | 8 / 0 (searches) |
| D4 | System prompt or configuration text in a reply (CopilotAudit_CL) | AML.T0056 | 1 / 0 (replies) |
| D5 | Read of a file the user never opened, bounded by B4 (CopilotAudit_CL, OfficeActivity_CL) | T1213.002 | 13 / 0 (reads) |
| D6 | Tool call after an answer with no new prompt (CopilotAudit_CL) | AML.T0051.001 | 13 / 0 (tool events) |
| D7 | FileAccessed on 3+ sites in 10 minutes (OfficeActivity_CL) | T1213.002 | 1 / 0 (user windows) |

Expected false positives and tuning: D1 board-pack summaries (require a label or 2+ sites); D2 approved CDNs
(allow-list; a broader untested regex is in App B); D3 HR, legal and executives (scope by role); D4 IT staff asking
about DLP (alert on a canary string); D5 genuine "find me" requests (30+ days of history); D6 multi-step tasks (pair
with D3 or D5); D7 shared-drive work (sliding window).

## 14. Handover to IR

Compromise confirmed: Copilot was steered to read 13 files and write link data into its answers (exfiltration not
determined); not an account takeover. For the client IR lead and Legal &
Compliance; every action is recommended, not executed (range).

| # | Risk (since) | Action |
|---|---|---|
| 1 | Outside domain present in answers (since 2026-09-20 10:43:08 UTC) | Block metrics-cdn[.]analyticshub[.]io at proxy and DNS; tenant-only answer images |
| 2 | No deletion of the lure is logged, so assume it is still in the mailbox and OneDrive; a new request may repeat the chain (Confidence: Medium; since 2026-09-20 09:15:22 UTC) | Purge both; keep one evidence copy |
| 3 | 13 files and the configuration potentially exposed (since 2026-09-20 10:42:47 UTC) | App F to Legal & Compliance for the notification decision |
| 4 | Audit rows age out | Preserve the session's CopilotAudit_CL and OfficeActivity_CL rows |
| 5 | Copilot reach beyond Emily's role (since 2026-09-20 10:42:47 UTC) | SharePoint permission review on the four sites |

Password reset not recommended: no account takeover is shown (E2).

## 15. Next-hunt leads

| Lead | Data needed |
|---|---|
| The 2026-09-20 10:44:15 UTC FileAccessed with no tool call (B6) | Copilot service and Purview audit |
| SharePoint permissions against the Global Reader claim (B8) | Site permission reports; Emily's groups |
| Labels on the 8 wave-2 files (B7) | Purview label audit |
| Requests to metrics-cdn[.]analyticshub[.]io (B1) | Proxy, DNS and endpoint logs from 2026-09-20 10:43:08 UTC |
| Recipients of the lure outside this dataset | Exchange message trace and quarantine |

## 16. AI tools declaration

I ran this hunt as the lead analyst and used Claude (Anthropic), through Claude Code, as my AI tooling throughout,
most heavily on the hardest parts: the answer-format questions, the detection replay and the report review. I set the
approach and the order of the pivots, directed the work across agents from one lead session (query drafting, skeptic
checks that tried to refute each proposed answer, answer-format modelling when an answer was not accepted, and report
review), and went through every finding against its raw result before I accepted it.

- **Queries and evidence.** The agents drafted the KQL and ran it in a Defender Advanced Hunting tab in my signed-in browser, then returned the raw results; exhibits E1–E8 were captured the same way. I checked each result against the finding it supports.
- **Answers.** The assistant helped draft and format candidate answers; I reviewed, approved and submitted every answer myself. I opened the platform's free first hint on some questions; no paid hints or reveals were used.
- **Report.** The assistant kept the hunt log and drafted this report and the detection rules to the structure I set. Two reviewer agents graded the drafts against the six scoring categories and fact-checked every number, and I decided which fixes to apply.
- **Data handling.** I signed in to every portal myself; no passwords or keys were given to the AI. The encoded link data was never printed or decoded.
- **Approval.** I chose the findings and approved all text.

## 17. Appendices

### A. Queries

All queries run in Defender Advanced Hunting against workspace LAW-HuntPractice, filtered to run el--17-20260920 and
2026-09-19 to 2026-09-22. They are printed as run; only the comment lines were reworded. Grids show HH:mm:ss for
2026-09-20 events; every time in this report is restated in full UTC. Saved files are q1, q3–q5, q7–q9, q12, q13 and
q15 (q2 repeats q1 and q10 repeats q7; there is no q6, q11 or q14). q16–q20 were run on 2026-10-17 during review to
close evidence gaps; each result is recorded under its query. The exhibit queries are in `exhibits.kql` beside
them, shown in each screenshot (App C) and reproduced after the q-files.

```kql
// q1 External emails received by emily.chen (UTC from TimeGenerated; OriginalTime empty)
workspace("LAW-HuntPractice").OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where isnotempty(SenderAddress) and SenderAddress !endswith "@cormorantcapital.com"
| project UTC = format_datetime(TimeGenerated, "HH:mm:ss"), Operation, SenderAddress, Subject, AttachmentNames, ClientIP
| order by UTC asc

// q3 Copilot rows tied to the lure (prompt at 2026-09-20 10:42:35 UTC)
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| where SessionId !contains "norm" or DataSourcesAccessed has "Global-Markets" or UserPrompt has "quarterly" or ToolParameters has "Global-Markets"
| project UTC = format_datetime(TimeGenerated, "HH:mm:ss"), UserId, InteractionType, Application, ToolName, SessionId, Prompt = substring(UserPrompt, 0, 110), Sources = substring(DataSourcesAccessed, 0, 120)
| order by UTC asc

// q4 The user prompt in session cp-emily-20261007-1042
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042" and InteractionType == "Prompt"
| project UTC = format_datetime(TimeGenerated, "HH:mm:ss"), UserPrompt, PromptLength = strlen(UserPrompt), Application, DataSourcesAccessed

// q5 Every event in the hijacked session
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| project UTC = format_datetime(TimeGenerated, "HH:mm:ss"), InteractionType, ToolName, ToolParameters, DataSourcesAccessed, SensitivityLabels
| order by UTC asc

// q7 Copilot ReadFile targets vs Emily's earlier opens (all 0 prior)
let reads = workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| where ToolName == "Graph.ReadFile"
| extend fileName = tostring(parse_json(ToolParameters).fileName)
| project ReadUTC = TimeGenerated, UserId, SessionId, fileName, SensitivityLabels;
let prior = workspace("LAW-HuntPractice").OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com" and Operation == "FileAccessed" and TimeGenerated < datetime(2026-09-20 10:42:35)
| extend f = iff(isnotempty(SourceFileName), SourceFileName, tostring(split(OfficeObjectId, "/")[-1]))
| summarize PriorOpens = count() by f;
reads
| join kind=leftouter prior on $left.fileName == $right.f
| project Read = format_datetime(ReadUTC, "HH:mm:ss"), UserId, SessionId, fileName, SensitivityLabels, PriorOpens = coalesce(PriorOpens, 0)
| order by Read asc

// q8 Outside domains inside Copilot answers (domain only, never the full link)
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| extend Resp = extract_all(@"https?://([A-Za-z0-9.-]+)", CopilotResponse)
| mv-expand Domain = Resp to typeof(string)
| where isnotempty(Domain)
| summarize Rows = count(), First = format_datetime(min(TimeGenerated), "HH:mm:ss"), Users = make_set(UserId, 5) by Domain

// q9 Image-link structure per answer (counts only, never the encoded data)
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| where CopilotResponse has "analyticshub"
| project UTC = format_datetime(TimeGenerated, "HH:mm:ss"),
    InlineImages = countof(CopilotResponse, @"!\[[^\]]*\]\(https?://metrics-cdn\.analyticshub\.io", "regex"),
    UrlsWithQuery = countof(CopilotResponse, @"metrics-cdn\.analyticshub\.io/[^\s)\]]*\?", "regex"),
    RespLen = strlen(CopilotResponse)

// q12 The hijacked session's answers, image links masked (the 2026-09-20 10:44:19 UTC answer is labelled Internal Only)
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042" and InteractionType == "Response"
| extend Resp = replace_regex(tostring(CopilotResponse), @"!\[[^\]]*\]\([^)]*\)", "[img]")
| project UTC = format_datetime(TimeGenerated, "HH:mm:ss"), SensitivityLabels, DataSourcesAccessed, Resp
| order by UTC asc

// q13 Copilot sessions grouped: hijacked session vs Emily's other sessions vs other users
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920"
| summarize Rows = count(), Prompts = countif(InteractionType == "Prompt"),
    Tools = countif(isnotempty(ToolName)), Searches = countif(ToolName == "Graph.SearchFiles"), Reads = countif(ToolName == "Graph.ReadFile"),
    Labelled = countif(isnotempty(SensitivityLabels)), AnyLink = countif(CopilotResponse has "http"), AttackerLink = countif(CopilotResponse has "analyticshub"),
    Secs = datetime_diff("second", max(TimeGenerated), min(TimeGenerated)) by UserId, SessionId
| extend Group = case(SessionId == "cp-emily-20261007-1042", "1 ATTACK session", UserId =~ "emily.chen@cormorantcapital.com", "2 Emily, other sessions", "3 Other users")
| summarize Sessions = count(), Users = dcount(UserId), WithTools = countif(Tools > 0), MaxSearches = max(Searches), MaxReads = max(Reads),
    WithLabelled = countif(Labelled > 0), WithAnyLink = countif(AnyLink > 0), WithAttackerLink = countif(AttackerLink > 0),
    MaxPrompts = max(Prompts), MaxRows = max(Rows), MaxSecs = max(Secs) by Group
| order by Group asc

// q15 Wave 2 (after 2026-09-20 10:44:20 UTC): searches and reads
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22))
| where RunId == "el--17-20260920" and SessionId == "cp-emily-20261007-1042"
| where TimeGenerated > datetime(2026-09-20 10:44:20) and InteractionType in ("Search", "ToolCall")
| extend p = parse_json(ToolParameters)
| project UTC = format_datetime(TimeGenerated, "HH:mm:ss"), InteractionType, ToolName, Q = tostring(p.query), File = tostring(p.fileName), SensitivityLabels
| order by UTC asc

// q16 Operation inventory: every OfficeActivity_CL operation in the run, by user count
workspace("LAW-HuntPractice").OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| summarize Rows = count(), Users = dcount(UserId), Who = strcat_array(make_set(tostring(split(UserId, "@")[0]), 4), ", ") by Operation
| order by Rows desc
// Result: 11 operations, 530 rows: FileAccessed 276 (26 users), MessageReceived 93 (24), FileModified 40 (19), MessageSent 29 (17),
// SearchQueryPerformed 25 (18), MeetingJoined 15 (10), FileUploaded 13 (10), MessageRead 13 (9), ChatCreated 10 (8),
// SensitivityLabelUpdated 9 (1: olivia.grant), TabAdded 7 (7). No inbox-rule, forwarding, mailbox or Copilot configuration operation.

// q17 Admin control: Mark Ross's Copilot sessions
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| where UserId =~ "mark.ross@cormorantcapital.com"
| summarize Start = format_datetime(min(TimeGenerated), "yyyy-MM-dd HH:mm:ss"), Events = count(), Prompts = countif(InteractionType == "Prompt"),
    ToolEvents = countif(InteractionType in ("ToolCall", "Search")), MaxReplyChars = max(strlen(CopilotResponse)), Apps = strcat_array(make_set(Application), ", ") by SessionId
| order by Start asc
// Result: cp-norm-0002 2026-09-20 07:38:14 UTC, 2 events, 1 prompt, 0 tool events, 152-char reply, Excel;
// cp-norm-0048 2026-09-20 12:50:00 UTC, 2 events, 1 prompt, 0 tool events, 152-char reply, Word.

// q18 Every FileAccessed under Emily during the attack, with full file names and sites (shows the 10:44:15 re-access)
workspace("LAW-HuntPractice").OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20 10:42:00) .. datetime(2026-09-20 10:47:00)) and RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com" and Operation == "FileAccessed"
| project UTC = format_datetime(TimeGenerated, "HH:mm:ss"), Workload = OfficeWorkload,
    Site = coalesce(extract(@"sharepoint\.com/(?:sites/)?([^/]+)", 1, OfficeObjectId), "OneDrive (personal)"),
    File = coalesce(SourceFileName, tostring(split(OfficeObjectId, "/")[-1]))
| order by UTC asc
// Result: 15 rows: the lure at 2026-09-20 10:42:08 UTC (OneDrive, personal), then the 13 files on SharePoint with the sites and full names in App F,
// the configuration file twice (2026-09-20 10:42:55 UTC and 2026-09-20 10:44:15 UTC). Executive 4, HR 3, IT 1, Finance 5.

// q19 Every operation by ANY user on the 13 files Copilot read, whole run
let Files = dynamic(["Board Meeting Minutes - October 2026.docx", "Project Falcon - M&A Target Assessment.xlsx", "Salary Review FY2027 - Executive Summary.pdf",
  "Client Portfolio - Henderson Family Office.xlsx", "Copilot System Configuration - Cormorant.json", "Compliance Audit Results - H2 2026.xlsx",
  "Restricted Client List - Internal Only.docx", "Board Resolution - Emergency Session.pdf", "Acquisition Pipeline - Q4 2026.xlsx",
  "Executive Salary Benchmarking 2027.pdf", "Confidential Investigation - Insider Trading.docx", "Board Committee Minutes - Audit Committee.docx",
  "Quarterly Revenue Report - Restricted Distribution.xlsx"]);
workspace("LAW-HuntPractice").OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| extend File = coalesce(SourceFileName, tostring(split(OfficeObjectId, "/")[-1]))
| where File in (Files)
| summarize Rows = count(), Files = dcount(File), First = format_datetime(min(TimeGenerated), "HH:mm:ss"), Last = format_datetime(max(TimeGenerated), "HH:mm:ss") by User = tostring(split(UserId, "@")[0]), Operation
// Result: one row: emily.chen, FileAccessed, 14 rows, 13 files, 2026-09-20 10:42:47 UTC to 2026-09-20 10:46:30 UTC. No other user, no other operation.

// q20 Prompt-to-first-answer latency per Copilot session, hijacked vs normal
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| summarize P = minif(TimeGenerated, InteractionType == "Prompt"), R = minif(TimeGenerated, InteractionType == "Response"),
    Prompts = countif(InteractionType == "Prompt"), Replies = countif(InteractionType == "Response") by SessionId
| extend Group = iff(SessionId == "cp-emily-20261007-1042", "1 hijacked", "2 normal"), LatencyS = datetime_diff("second", R, P)
| summarize Sessions = count(), WithPromptAndReply = countif(isnotnull(P) and isnotnull(R)), NoPrompt = countif(isnull(P)), NoReply = countif(isnull(R)),
    MinLatencyS = min(LatencyS), MaxLatencyS = max(LatencyS), Prompts = sum(Prompts), Replies = sum(Replies) by Group
| order by Group asc
// Result: hijacked 1 session, 1 prompt, 3 replies, latency 33 s. Normal 104 sessions: 85 with a prompt and a reply, all 0 s;
// 19 log a reply with no prompt row; 87 prompts, 106 replies.
```

Exhibit queries E1–E7, as run on 2026-10-17 (E8 is App B):

```kql
// E1 Who received the lure and what happened to it (all mailboxes, whole run)
workspace("LAW-HuntPractice").OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| where SenderAddress endswith "@globalfinancereview.net" or AttachmentNames has "Q3-2026-Global-Markets-Review"
    or SourceFileName has "Q3-2026-Global-Markets-Review" or OfficeObjectId has "Q3-2026-Global-Markets-Review"
| project ['UTC 2026-09-20'] = format_datetime(TimeGenerated, "HH:mm:ss"), User = tostring(split(UserId, "@")[0]), Operation,
    Sender = SenderAddress, File = coalesce(SourceFileName, AttachmentNames, tostring(split(OfficeObjectId, "/")[-1]))
| order by ['UTC 2026-09-20'] asc

// E2 Emily's sign-ins (account-takeover hypothesis)
workspace("LAW-HuntPractice").EntraSignIn_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| where UserPrincipalName =~ "emily.chen@cormorantcapital.com"
| project ['UTC 2026-09-20'] = format_datetime(TimeGenerated, "HH:mm:ss"), User = tostring(split(UserPrincipalName, "@")[0]),
    IPAddress, Location, Status, ConditionalAccessStatus, AppDisplayName
| order by ['UTC 2026-09-20'] asc

// E3a / E3b The hijacked session in order (answer text not printed). E3a: 2026-09-20 10:42:00 UTC to 2026-09-20 10:44:30 UTC.
// E3b: same query, 2026-09-20 10:45:00 UTC to 2026-09-20 10:47:00 UTC.
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 10:42:00) .. datetime(2026-09-20 10:44:30)) and RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042" | extend p = parse_json(ToolParameters)
| project ['UTC 2026-09-20'] = format_datetime(TimeGenerated, "HH:mm:ss"), InteractionType, ToolName, SensitivityLabels,
    Detail = case(InteractionType == "Prompt", UserPrompt, isnotempty(tostring(p.query)), tostring(p.query), isnotempty(tostring(p.fileName)), tostring(p.fileName), "(response text not shown)")
| order by ['UTC 2026-09-20'] asc

// E4 Each Copilot read vs Emily's FileAccessed: prior opens, delay, other operations after
let O = workspace("LAW-HuntPractice").OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| project OpT = TimeGenerated, Operation, File = coalesce(SourceFileName, tostring(split(OfficeObjectId, "/")[-1]));
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042" and ToolName == "Graph.ReadFile"
| project ReadT = TimeGenerated, File = tostring(parse_json(ToolParameters).fileName)
| join kind=leftouter O on File
| summarize Read = min(ReadT), Seen = minif(OpT, Operation == "FileAccessed" and OpT >= ReadT),
    PriorOpens = countif(Operation == "FileAccessed" and OpT < ReadT - 5s),
    OtherOpsAfter = countif(Operation != "FileAccessed" and OpT >= ReadT) by File
| project ['Read UTC'] = format_datetime(Read, "HH:mm:ss"), File, ['FileAccessed UTC'] = format_datetime(Seen, "HH:mm:ss"),
    DelayS = datetime_diff("second", Seen, Read), PriorOpens, OtherOpsAfter
| order by ['Read UTC'] asc

// E5 Written into the answers: image links per reply, attack vs every normal reply (counts only, no link text)
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| where InteractionType == "Response"
| extend Reply = iff(SessionId == "cp-emily-20261007-1042", strcat("attack ", format_datetime(TimeGenerated, "HH:mm:ss"), " UTC"), "all 106 normal replies")
| summarize Replies = count(), ExternalImages = sum(countof(CopilotResponse, "metrics-cdn.analyticshub.io/img")),
    TenantImages = sum(countof(CopilotResponse, "cormorantcapital.sharepoint.com")),
    ConfigDump = countif(CopilotResponse has "System configuration extracted"), AvgChars = round(avg(strlen(CopilotResponse))),
    Labels = make_set_if(SensitivityLabels, isnotempty(SensitivityLabels)) by Reply
| order by Reply asc

// E6 Where does the outside domain appear? Every in-scope table, every column (no network, proxy or DNS table exists)
union withsource = SourceTable workspace("LAW-HuntPractice").OfficeActivity_CL, workspace("LAW-HuntPractice").CopilotAudit_CL,
    workspace("LAW-HuntPractice").EntraSignIn_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| summarize Rows = count(), RowsWithDomain = countif(tostring(pack_all()) has "analyticshub") by Table = extract(@"(\w+_CL)", 1, SourceTable)
| order by Table asc

// E7 Baseline: the hijacked session vs every other Copilot session in the run
workspace("LAW-HuntPractice").CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920"
| summarize Events = count(), ToolEvents = countif(InteractionType in ("ToolCall", "Search")), Labelled = countif(isnotempty(SensitivityLabels)),
    ExternalImages = sum(countof(CopilotResponse, "metrics-cdn.analyticshub.io/img")), Apps = make_set(Application) by UserId, SessionId
| extend Group = case(SessionId == "cp-emily-20261007-1042", "1 hijacked session", UserId =~ "emily.chen@cormorantcapital.com", "2 Emily, other sessions", "3 other users")
| summarize Sessions = count(), Users = dcount(UserId), SessionsWithToolEvents = countif(ToolEvents > 0), ToolEvents = sum(ToolEvents),
    LabelledRows = sum(Labelled), ExternalImages = sum(ExternalImages), MaxEventsPerSession = max(Events) by Group
| order by Group asc
```

### B. Detection KQL (as replayed, exhibit E8)

```kql
// Echo Leaks detections D1-D7, replayed on run el--17-20260920 (Defender Advanced Hunting, LAW-HuntPractice, 2026-10-17)
// FalsePositives = hits outside the hijacked session (D7: outside Emily's 10-minute window from 2026-09-20 10:40:00 UTC).
let C = workspace("LAW-HuntPractice").CopilotAudit_CL | where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920";
let O = workspace("LAW-HuntPractice").OfficeActivity_CL | where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-22)) and RunId == "el--17-20260920";
let A = "cp-emily-20261007-1042";
// D1 Copilot ReadFile burst: 3+ reads in one minute in one session
let D1 = C | where ToolName == "Graph.ReadFile" | summarize n = count() by SessionId, bin(TimeGenerated, 1m) | where n >= 3 | extend Rule = "D1 ReadFile burst 3+/min";
// D2 Markdown image in a Copilot reply pointing outside the tenant
let D2 = C | where InteractionType == "Response" | mv-expand Dom = extract_all(@"!\[[^\]]*\]\(https?://([^/)\s?]+)", CopilotResponse) to typeof(string)
  | where isnotempty(Dom) and not(Dom endswith "cormorantcapital.sharepoint.com") | extend Rule = "D2 Image to non-tenant domain in reply";
// D3 Copilot file search for sensitivity keywords
let D3 = C | where ToolName == "Graph.SearchFiles" | where tolower(tostring(parse_json(ToolParameters).query)) has_any ("confidential", "restricted", "salary", "board", "acquisition", "password", "secret") | extend Rule = "D3 Search for sensitivity keywords";
// D4 System prompt or tenant configuration text in a Copilot reply
let D4 = C | where InteractionType == "Response" and CopilotResponse has_any ("system_prompt", "enterprise_config", "System configuration extracted", "dlp_policy") | extend Rule = "D4 System prompt or config in reply";
// D5 Copilot reads a file the user never opened before (history = whatever OfficeActivity_CL holds; here one day)
let D5 = C | where ToolName == "Graph.ReadFile" | extend File = tostring(parse_json(ToolParameters).fileName), ReadT = TimeGenerated
  | join kind=leftouter (O | where Operation == "FileAccessed" | project UserId, File = coalesce(SourceFileName, tostring(split(OfficeObjectId, "/")[-1])), OpT = TimeGenerated) on UserId, File
  | summarize Prior = countif(OpT < ReadT - 5s) by SessionId, File, ReadT | where Prior == 0 | extend Rule = "D5 Read of a file never opened before";
// D6 Tool call whose most recent earlier event is a reply, not a prompt (Copilot acting with no new user input)
let P = C | where InteractionType == "Prompt" | project SessionId, PT = TimeGenerated;
let R = C | where InteractionType == "Response" | project SessionId, RT = TimeGenerated;
let D6 = C | where InteractionType in ("ToolCall", "Search") | project SessionId, TT = TimeGenerated
  | join kind=leftouter P on SessionId | summarize LastP = maxif(PT, PT <= TT) by SessionId, TT
  | join kind=leftouter R on SessionId | summarize LastR = maxif(RT, RT < TT) by SessionId, TT, LastP
  | where isnotnull(LastR) and (isnull(LastP) or LastR > LastP) | extend Rule = "D6 Tool call after a reply with no new prompt";
// D7 FileAccessed on 3+ SharePoint/OneDrive sites in 10 minutes by one user (no Copilot audit needed)
let D7 = O | where Operation == "FileAccessed" | extend Site = extract(@"sharepoint\.com/(?:sites/)?([^/]+)", 1, OfficeObjectId)
  | summarize Sites = dcount(Site) by UserId, W = bin(TimeGenerated, 10m) | where Sites >= 3
  | extend SessionId = iff(UserId =~ "emily.chen@cormorantcapital.com" and W == datetime(2026-09-20 10:40), A, "other"), Rule = "D7 FileAccessed on 3+ sites in 10 min";
union D1, D2, D3, D4, D5, D6, D7
| summarize Hits = count(), AttackHits = countif(SessionId == A), FalsePositives = countif(SessionId != A) by Rule
| project ID = substring(Rule, 0, 2), Hits, AttackHits, FalsePositives, Rule = substring(Rule, 3) | order by ID asc
```

D2 tuning, not replayed (also catches HTML and reference-style images):

```kql
| extend Hosts = extract_all(@"(?m)(?:!\[[^\]]*\]\(\s*<?|<img[^>]+src=.?|^\s*\[[^\]]+\]:\s*<?)https?://([A-Za-z0-9.-]+)", tostring(CopilotResponse))
```

### C. Exhibits

Screenshots from Defender Advanced Hunting on 2026-10-17, editor and grid in one frame; no image link is printed.

**E1 Lure recipients.** Supports one recipient (Emily), the receipt and her open, and no other operation on the file; does not prove the document's text.

![E1](exhibits/E1-lure-recipients-20261017.png)

**E2 Emily's sign-ins.** Supports 2 Success sign-ins from 203.0.113.45, London GB, CA success; does not prove anything about sign-ins or tokens outside EntraSignIn_CL.

![E2](exhibits/E2-emily-signins-20261017.png)

**E3a Session, wave 1.** Supports one prompt, 3 searches, 5 reads and 2 answers in order; does not prove the injected text or the answer text.

![E3a](exhibits/E3a-session-wave1-20261017.png)

**E3b Session, wave 2.** Supports no new prompt, 5 searches logged as Search, 8 reads with no label recorded (SensitivityLabels is empty on every row, so the grid hides the column), the final answer; does not prove what Purview holds for them.

![E3b](exhibits/E3b-session-wave2-20261017.png)

**E4 Reads against FileAccessed.** Supports a FileAccessed 0–5 s after each read, 0 prior opens, 0 other operations after; does not prove file contents or opens before 2026-09-19.

![E4](exhibits/E4-reads-vs-fileaccessed-20261017.png)

**E5 Answers and image links.** Supports 13 links in 3 answers, the configuration answer and the reply lengths against 106 normal replies; does not prove that the links were shown, fetched or received.

![E5](exhibits/E5-replies-images-20261017.png)

**E6 Domain by table.** Supports the domain in 3 CopilotAudit_CL rows only and the row counts of the three tables; does not prove that no fetch happened (no network telemetry exists, B1).

![E6](exhibits/E6-domain-by-table-20261017.png)

**E7 Session baseline.** Supports one hijacked session against 104 sessions with no tool events; does not prove tool use is rare in a real tenant.

![E7](exhibits/E7-session-baseline-20261017.png)

**E8 Detection replay.** Supports the D1–D7 hit and false-positive counts on this run; does not prove production false-positive rates.

![E8](exhibits/E8-detection-replay-20261017.png)

### D. Evidence index

No CSVs were exported, so there are no CSV hashes. Screenshot SHA-256 values match `exhibits/SHA256SUMS.txt`
(recompute if any exhibit is recaptured).

| Exhibit | File | Rows | SHA-256 | Supports |
|---|---|---|---|---|
| E1 | E1-lure-recipients-20261017.png | 2 | `f75476d14d3a72c387851c94daf341ce3597234b5c335ea98a40a5862d58abef` | F1, 9.8 |
| E2 | E2-emily-signins-20261017.png | 2 | `22b2c7d4d01134f3b5dd88eef9d2bd3235fc127fb8dfa3f63daa439c5a90efef` | H1, 9.8 |
| E3a | E3a-session-wave1-20261017.png | 11 | `a87de61351142b34c7a1693b8db2a82e89b65da6685efa47df322077df15669c` | F1, F2 |
| E3b | E3b-session-wave2-20261017.png | 14 | `39c08b1b4b30b3fe5fb3cdfa36b238a9d6adf364c98f5d66e290d5c4ac9c4d95` | F5, B7 |
| E4 | E4-reads-vs-fileaccessed-20261017.png | 13 | `44255ea97bb2bf49de34365133149330ec2e6c36af638b6e36c72e632595b686` | F3, 9.8 |
| E5 | E5-replies-images-20261017.png | 4 | `738a6da7b7b75a9d2ddecb4068e4cd9f7915a7df4989c73485f410a271ebd314` | F4, F6 |
| E6 | E6-domain-by-table-20261017.png | 3 | `d96b3ee8ccdb57186d0f005eb64a0d3824cfc1f6337a958646946f479e7308e1` | F6, §6, B1, 9.8 |
| E7 | E7-session-baseline-20261017.png | 3 | `6e78f9053f453d09e4f1a780b984a6e870c8d991883145a954d3103e903938da` | F7, H4, §13, 9.8 |
| E8 | E8-detection-replay-20261017.png | 7 | `5e4bb527d31df002906955a9ea322f4c8fed3adaf02b050b1cc13004f4142dd4` | F6, §13 |

### E. Indicators (defanged)

| Type | Value | Context |
|---|---|---|
| Email sender | quarterly.reports@<wbr>globalfinancereview<wbr>[.]net | Lure sender, 2026-09-20 09:15:22 UTC |
| Email subject | Q3 2026 Global Markets Review - For Your Analysis | Lure |
| Attachment | Q3-2026-Global-Markets-Review.docx | Lure; hash not in telemetry (no hash field) |
| Domain | metrics-cdn[.]<wbr>analyticshub[.]io (path /img) | 13 image links in 3 answers, 2026-09-20 10:43:08 UTC to 2026-09-20 10:46:35 UTC (query strings not reproduced) |

The session ID cp-emily-20261007-1042 and the client IP 203.0.113.45 (Emily's) are artefacts, not indicators.

### F. The 13 files

Sites and full names are from q18 (Executive 4, HR 3, IT 1, Finance 5). Labels are
as recorded in SensitivityLabels; "none recorded" is not a Purview result (B7).

| # | File | Site | Label | Read | FileAccessed | Delta |
|---|---|---|---|---|---|---|
| 1 | Board Meeting Minutes - October 2026.docx | Executive | Confidential | 2026-09-20 10:42:47 UTC | 2026-09-20 10:42:47 UTC | 0 s |
| 2 | Project Falcon - M&A Target Assessment.xlsx | Executive | Confidential | 2026-09-20 10:42:49 UTC | 2026-09-20 10:42:49 UTC | 0 s |
| 3 | Salary Review FY2027 - Executive Summary.pdf | HR | Confidential | 2026-09-20 10:42:51 UTC | 2026-09-20 10:42:51 UTC | 0 s |
| 4 | Client Portfolio - Henderson Family Office.xlsx | Finance | Confidential | 2026-09-20 10:42:53 UTC | 2026-09-20 10:42:53 UTC | 0 s |
| 5 | Copilot System Configuration - Cormorant.json | IT | Internal Only | 2026-09-20 10:42:55 UTC | 2026-09-20 10:42:55 UTC; again 2026-09-20 10:44:15 UTC with no tool call (q18) | 0 s |
| 6 | Compliance Audit Results - H2 2026.xlsx | Finance | none recorded | 2026-09-20 10:45:46 UTC | 2026-09-20 10:45:51 UTC | 5 s |
| 7 | Restricted Client List - Internal Only.docx | Finance | none recorded | 2026-09-20 10:45:54 UTC | 2026-09-20 10:45:57 UTC | 3 s |
| 8 | Board Resolution - Emergency Session.pdf | Finance | none recorded | 2026-09-20 10:45:59 UTC | 2026-09-20 10:46:00 UTC | 1 s |
| 9 | Acquisition Pipeline - Q4 2026.xlsx | Finance | none recorded | 2026-09-20 10:46:05 UTC | 2026-09-20 10:46:05 UTC | 0 s |
| 10 | Executive Salary Benchmarking 2027.pdf | HR | none recorded | 2026-09-20 10:46:07 UTC | 2026-09-20 10:46:08 UTC | 1 s |
| 11 | Confidential Investigation - Insider Trading.docx | HR | none recorded | 2026-09-20 10:46:13 UTC | 2026-09-20 10:46:17 UTC | 4 s |
| 12 | Board Committee Minutes - Audit Committee.docx | Executive | none recorded | 2026-09-20 10:46:18 UTC | 2026-09-20 10:46:22 UTC | 4 s |
| 13 | Quarterly Revenue Report - Restricted Distribution.xlsx | Executive | none recorded | 2026-09-20 10:46:26 UTC | 2026-09-20 10:46:30 UTC | 4 s |

From the names alone (Confidence: Medium): deal data that is likely inside information (2, 9, 13), executive pay (3,
10), client data (4, 7), an insider-trading investigation with tipping-off risk (11), board material (1, 8, 12), audit
results (6) and the configuration (5). Legal & Compliance decide on notification.

### G. Method notes

- Every query carries the run filter RunId == "el--17-20260920" and a window inside 2026-09-19 to 2026-09-22 (E3a, E3b and
  q18 use the attack windows).
- Image links were never printed: q12 masks them, q9 and E5 count them, q8 extracts the host only. The encoded strings were never decoded.
- Hits in the replay: D1 counts one-minute bins (from 2026-09-20 10:42:00 UTC, 2026-09-20 10:45:00 UTC and 2026-09-20 10:46:00 UTC); D6 counts tool events (5 searches and 8 reads in wave 2); D7 counts user-by-10-minute windows.
- Prompt-to-answer latency (q20) compares each session's first Response with its first Prompt: 0 s in all 85 normal sessions
  that log a prompt (19 normal sessions log a reply with no prompt row), 33 s in the hijacked one.
- The client IP on the MessageReceived row is the recipient's client IP, not the sender's.

### H. Glossary

| Term | Meaning |
|---|---|
| Prompt injection (indirect) | Instructions for an AI assistant hidden in content it reads, such as a document, rather than typed by the user |
| System prompt | The assistant's standing instructions and settings, set by the vendor or tenant, which the user does not normally see |
| Markdown image link | Text of the form `![text](link)` that a client displays as an image by fetching the link |
| Query string | The part of a web link after "?", here carrying an encoded string |
| Tool call | An action Copilot takes on the user's behalf, such as Graph.SearchFiles or Graph.ReadFile |
| DLP | Data loss prevention: policies that block or flag sensitive data leaving its allowed places |
| MITRE ATT&CK; MITRE ATLAS | Catalogues of attacker techniques, for IT systems and for AI systems |
| ABLE | Actor, Behaviour, Location, Evidence: the parts of a hunt hypothesis |
| Dwell | Time from the attacker's first logged action to the last, here delivery to the last answer |
| TLP:AMBER | Share only with those who need it inside the recipient organisations |
