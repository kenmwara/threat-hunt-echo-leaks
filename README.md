<!-- banner --><a href="https://github.com/kenmwara"><img src="https://raw.githubusercontent.com/kenmwara/kenmwara/main/assets/brand/card-echo-leaks.png?v=d27a77c352" width="100%" alt="Echo Leaks: A prompt-injection attack on Microsoft 365 Copilot that read 13 confidential files and tried to carry them out. 17/17 flags · 1,600 / 1,600."></a>

# Echo Leaks: an AI assistant tricked into reading private files

**A Word file sent to a financial analyst carried hidden instructions written for Microsoft 365 Copilot, the AI assistant built into the company's Office apps. When she asked Copilot to summarise it, Copilot followed the hidden instructions instead: it read 13 confidential files she had never opened, and its answers carried links that could send the data to an outside server. Her account was never taken over; the AI was.**

**Analyst:** Ken Kariuki · **Live hunt:** 17 October 2026 ([Cyber Range](https://www.skool.com/cyber-range)) · **Result:** all 17 questions answered, a perfect 1,600 of 1,600, on time (second finisher on the scoreboard)

## Key takeaways

<img src="images/scorecard.png" width="100%" alt="Key takeaways. One normal question to an AI assistant set off hidden instructions in a Word file. 13: Private files read. Copilot opened 13 confidential files the employee had never touched, across 4 company sites. 13: Hidden links to an outside server. Its answers carried links that could have sent the data out. 3 m 39 s: All in under four minutes. The second wave ran with no new question from anyone. 0: Accounts hacked. The AI was tricked, not the person. Resetting her password wouldn't have helped. 17 / 17: Every question answered. A perfect score, with seven alert rules tested against the evidence.">

## How the attack unfolded

<img src="images/story.png" width="100%" alt="Echo Leaks: how the attack unfolded. 20 September 2026, times in UTC. Four minutes from the first question to the last answer. 09:15, The trap: 09:15 · An outside email arrives with a Word file, sent to one analyst; Hidden inside: instructions written for the AI, not for her. 10:42, The trigger: 10:42 · She opens it and asks Copilot to summarise it; Six seconds later Copilot starts searching for files she never asked about. 10:42 – 10:46, The reading: 10:42 · Copilot reads 5 confidential files, 2 seconds apart; 10:45 · With no new question from anyone, it reads 8 more; 13 files in all, from the Executive, HR, IT and Finance sites. 10:43 – 10:46, The leak: Its answers carry 13 image links to an outside server; 10:44 · One answer dumps what it calls its own configuration; The only alert fires on the analyst; nothing flags Copilot.">

## The evidence

<img src="images/evidence.png" width="100%" alt="Key evidence, straight from the logs. Each screenshot is a saved search and its results. The full report has every one. Searches nobody asked for: Copilot's own log of the first wave. 13 files read for the first time: Copilot's reads matched to the file-access log. Answers with hidden image links: 13 links to one outside server, in 3 answers. New alert rules, re-run: Each rule tested against the hunt's data.">

## What went wrong, and the fix

<img src="images/gaps.png" width="100%" alt="What went wrong, and how to fix it. Each fix comes with a test that proves it works. Owners are proposed, not yet agreed. What went wrong: Only one alert fired, and it pointed at the analyst. Why it mattered: Nothing watched what Copilot itself did. The fix: Send Copilot's activity log to the security team, with alerts on it. What went wrong: Answers could load images from outside the company. Why it mattered: An image link can carry data out when it loads. The fix: Allow only the company's own images; block the outside address. What went wrong: Copilot obeyed instructions from an outside file. Why it mattered: This is a known flaw (CVE-2025-32711). The fix: Confirm Microsoft's fix covers the company, then replay the attack. What went wrong: Copilot could reach Executive, HR and IT files. Why it mattered: It reads whatever the user is allowed to read. The fix: Review who can see what on the four sites. What went wrong: Eight files had no sensitivity label. Why it mattered: Unlabelled files get no extra protection. The fix: Label files automatically, and stop Copilot sharing labelled data. What went wrong: No network or web-lookup logs. Why it mattered: Nobody can tell whether the data actually left. The fix: Collect those logs, and prove it with a test image.">

## What to do now

1. Block the outside server's address.
2. Remove the email and the Word file, keeping one copy as evidence.
3. Stop Copilot answers loading images from outside the company.
4. Give Legal & Compliance the list of the 13 files.
5. Skip the password reset: her account was never taken over, so it would not help.

## The full report

This page is the short version. The full incident report covers the hunt's method, every finding with its evidence,
the attacker techniques seen (MITRE ATT&CK), the new alert rules and how they were tested, and the indicators.

- **[The full report (REPORT.md)](REPORT.md)**, readable on GitHub.
- **[The report as a PDF](EchoLeaks-Report.pdf)**, as submitted.
- **[The exhibits](exhibits/)**: every saved search with its results, with checksums.

---

*More hunts: [kenmwara/threat-hunts](https://github.com/kenmwara/threat-hunts). Analysis is AI-assisted: the analyst directs the tools and checks every finding against the raw logs (section 16 of the full report).*
