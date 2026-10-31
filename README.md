# Operation ECHOLEAK

### Cybersecurity Portfolio / Threat Hunt

**Investigation Questions, Answers, KQL & Screenshot Evidence**  
**Prepared by:** Corey Lee  
**Exercise type:** Simulated Microsoft 365 Copilot prompt-injection investigation

> [!NOTE]
> This is a first-person **training case study**, not a verified production incident. I distinguish findings visible in screenshots from exercise-reported details and conclusions requiring further validation. All investigation times are **UTC** unless otherwise stated; screenshots use **Central Daylight Time (CDT, UTC−5)**.

## Report Purpose

This report provides a deduplicated, evidence-led account of my Microsoft 365 Copilot investigation. Each of the **17 distinct questions** appears once, with its answer, reasoning, supporting evidence, and relevant KQL. The **18 original screenshots** are linked directly from the [`evidence/`](evidence/) folder.

## Case Information

| Field | Value |
|---|---|
| Prepared by | Corey Lee |
| Exercise | Operation ECHOLEAK (simulated training environment) |
| Incident date | September 20, 2026 |
| Report prepared | October 19, 2026 |
| Workspace | `LAW-HuntPractice` |
| Run ID | `el--17-20260920` |
| Primary identity | `emily.chen@cormorantcapital.com` |
| Source | *Corey Lee - Threat Hunting Live Event .docx* (35 pages; 18 screenshots) |
| Primary telemetry | `OfficeActivity_CL`, `CopilotAudit_CL` |

## Contents

- [Executive Assessment](#executive-assessment)
- [My Investigative Approach](#my-investigative-approach)
- [Key Event Timeline](#key-event-timeline)
- [Evidence and Confidence Key](#evidence-and-confidence-key)
- [01 — Delivery and Initial Access (Q01–Q03)](#delivery-and-initial-access)
- [02 — Copilot Interaction and Tool Misuse (Q04–Q08)](#copilot-interaction-and-tool-misuse)
- [03 — Exfiltration Pathway and Visibility (Q09–Q12)](#exfiltration-pathway-and-visibility)
- [04 — Baseline Comparison and Follow-on Search (Q13–Q16)](#baseline-comparison-and-follow-on-search)
- [05 — Root Cause and Disposition (Q17)](#root-cause-and-disposition)
- [Appendix A — Query Troubleshooting](#appendix-a--query-troubleshooting)
- [Appendix B — Follow-up Verification Checklist](#appendix-b--follow-up-verification-checklist)
- [Evidence Screenshot Index](#evidence-screenshot-index)
- [Source and Format Notes](#source-and-format-notes)

---

## Executive Assessment

I investigated whether unusual sensitive-document access in Microsoft 365 Copilot represented routine file exploration, a compromised account, altered Copilot configuration, or malicious instructions embedded in an external report. The strongest evidence supported an **indirect prompt-injection scenario**: after Emily Chen requested a quarterly-report summary, Copilot searched for unrelated confidential materials and read SharePoint files via legitimate Graph tool calls. Its response also contained externally hosted Markdown chart-image links.

**Main conclusion:** The attacker appears to have influenced Copilot through **untrusted document content**, rather than through observed credential theft or documented configuration tampering. The screenshots demonstrate suspicious tool use and **potential image-URL exfiltration**, but they do **not independently prove that a remote image request completed or that specific content left the environment**.

### Main Findings

| Finding | Status | Why it matters |
|---|---|---|
| Benign request to summarize a quarterly report | **Observed** | Establishes Emily's authorized task |
| `Graph.SearchFiles` queries for board, M&A, and salary material | **Observed** | Demonstrates task-irrelevant sensitive-data discovery |
| `Graph.ReadFile` activity involving confidential material | **Observed** | Shows file access beyond the user's summary request |
| Five initial previously unopened sensitive files | **Exercise-reported** | Six-second burst is unusual; full filenames remain unavailable |
| Five external Markdown image URLs in the Copilot response | **Observed** | Supports a possible URL-based data exfiltration route |
| Thirteen total `Graph.ReadFile` events | **Observed** | Five initial plus eight later reads; not necessarily 13 unique files |
| Successful network exfiltration and exact leaked bytes | **Not independently confirmed** | Requires network/renderer evidence and payload visibility |

## My Investigative Approach

I began by confirming the correct log workspace and converting UTC incident times to the local time filter. Then I traced Exchange mail delivery and SharePoint access in `OfficeActivity_CL`. Next I isolated Emily's normal prompt from unrelated Copilot activity, examined tool names and JSON parameters in `CopilotAudit_CL`, and searched the Copilot response for external URLs. Finally, I reviewed later SearchLeak terms and counted file-read events separately from file searches.

## Key Event Timeline

| Time (UTC), September 20, 2026 | Observation | Evidentiary note |
|---|---|---|
| **09:15:22** | `MessageReceived` for Emily | Recipient visible; sender and attachment filename not exposed in shared capture |
| **09:25:07** | First visible `FileAccessed` event | 9 minutes 45 seconds after delivery; document identity not visible |
| **~10:42** | Quarterly-summary prompt and suspicious tool use | `Graph.SearchFiles` and `Graph.ReadFile` |
| **~10:43** | Copilot response | Five external Markdown chart-image URLs |
| **~10:45** | Later SearchLeak activity | `confidential`, `restricted`, `board`, `acquisition`, `salary` |

## Evidence and Confidence Key

- **Observed:** Visible in one or more screenshots from the investigation document.
- **Exercise-reported:** Supplied by the lab scenario or associated Q&A, but not directly recoverable from the visible screenshot fields.
- **Not independently confirmed:** More complete records, file IDs, payloads, or network evidence are required.
- **Event count ≠ unique-file count:** Multiple `Graph.ReadFile` operations can refer to the same file.

---

<a id="delivery-and-initial-access"></a>

## 01 — Delivery and Initial Access (Q01–Q03)

### Q01. Which external email address delivered the document that preceded the anomalous file access?

**Answer — Not independently confirmed.** The full external sender address is not visible in the supplied evidence. `emily.chen@cormorantcapital.com` is the **recipient**, not the sender.

**My reasoning:** I started with Exchange `MessageReceived` records in `OfficeActivity_CL`, corrected the workspace and time filters, and located Emily's **09:15:22 UTC** delivery event. The screenshots did not expose a sender field, so I did not assign an unsupported external address.

**Evidence:** The `MessageReceived` event lists Emily as recipient at 09:15:22 UTC; sender remains unverified. [Exhibits 01–02](#evidence-screenshot-index).

**KQL — Verify the mail-delivery event**

```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where Operation == "MessageReceived"
| where UserId == "emily.chen@cormorantcapital.com"
| where TimeGenerated between (
    datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T10:00:00Z))
| order by TimeGenerated asc
```

<details>
<summary><strong>Screenshot evidence — Exhibits 01–02 (workspace and delivery results)</strong></summary>

**Exhibit 01 —** `OfficeActivity_CL` could not be resolved while the wrong workspace (`LAW-Cyber-Range`) was selected.

![Exhibit 01 — Workspace/table resolution error](evidence/exhibit-01.png)

**Exhibit 02 —** Successful Exchange `MessageReceived` search in `LAW-HuntPractice`.

![Exhibit 02 — Exchange delivery results](evidence/exhibit-02.png)

</details>

### Q02. What is the name of the document attached to the delivery email?

**Answer — Not independently confirmed.** The exact attachment filename is not shown in the screenshots. The scenario describes it as a **quarterly market-review/report document**.

**My reasoning:** I would expand the 09:15:22 UTC `MessageReceived` event and inspect its attachment or event-parameter fields. The visible results show the delivery operation and recipient, not the attachment name.

**Evidence:** `OfficeActivity_CL` Exchange delivery event; the attachment filename is not visible. See [Exhibit 02](#evidence-screenshot-index).

### Q03. How much time elapsed between email delivery and Emily's first interaction with the document? What does the gap suggest?

**Answer — Approximately 10 minutes.** The difference between **09:15:22** and **09:25:07 UTC** is **9 minutes, 45 seconds**. The gap is consistent with a delayed, user-triggered attack model rather than execution automatically occurring at delivery.

**My reasoning:** I sorted Emily's records chronologically and compared `MessageReceived` with the earliest visible SharePoint `FileAccessed` event. Because the event's filename is not visible, I cannot definitively tie the **09:25:07** access to the suspicious attachment without further inspection.

**Evidence:** Delivery at 09:15:22; first visible file access at 09:25:07; elapsed time `00:09:45`. [Exhibits 03–04](#evidence-screenshot-index).

**KQL — Compare delivery and access times**

```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where TimeGenerated between (
    datetime(2026-09-20T09:15:00Z) .. datetime(2026-09-20T10:42:00Z))
| order by TimeGenerated asc
```

<details>
<summary><strong>Screenshot evidence — Exhibits 03–04 (first file access)</strong></summary>

**Exhibit 03 —** Delivery and earliest recorded SharePoint access times.

![Exhibit 03 — Event chronology](evidence/exhibit-03.png)

**Exhibit 04 —** Expanded `FileAccessed` event near 09:25 UTC.

![Exhibit 04 — FileAccessed record](evidence/exhibit-04.png)

</details>

---

<a id="copilot-interaction-and-tool-misuse"></a>

## 02 — Copilot Interaction and Tool Misuse (Q04–Q08)

### Q04. What did Emily ask Copilot to do with the document?

**Answer — Observed:**

> Summarise the key findings of this quarterly report.

**My reasoning:** I filtered `CopilotAudit_CL` to Emily's `Prompt` events and examined `UserPrompt`. Other entries reflected normal grammar checks, writing assistance, and summaries. Her request was narrow: summarize a specific report, not search unrelated confidential files.

**Evidence:** `InteractionType=Prompt`, `Application=Word`, around 10:42 UTC. [Exhibits 05–06](#evidence-screenshot-index).

**KQL — Review Emily's prompts**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where InteractionType == "Prompt"
| project TimeGenerated, Application, UserPrompt
| order by TimeGenerated asc
```

<details>
<summary><strong>Screenshot evidence — Exhibits 05–06 (normal prompt baseline)</strong></summary>

**Exhibit 05 —** Routine Copilot prompt/response activity in the noise floor.

![Exhibit 05 — Normal Copilot activity](evidence/exhibit-05.png)

**Exhibit 06 —** Filtered `UserPrompt` values, including the quarterly-summary request.

![Exhibit 06 — Quarterly-report prompt](evidence/exhibit-06.png)

</details>

### Q05. After Emily's prompt, which tool calls went beyond a normal summary? Name the tools and targets.

**Answer — Observed.** Copilot used **`Graph.SearchFiles`** to locate confidential board minutes, M&A/acquisition documents, and salary reviews, then invoked **`Graph.ReadFile`** on SharePoint files unrelated to the quarterly report.

**My reasoning:** I reviewed `ToolCall` events just after 10:42 UTC. An initial query failed because I guessed a column named `ToolInput`; examining the event schema revealed the actual fields **`ToolName`** and **`ToolParameters`**. The JSON included a `Graph.SearchFiles` query for `board minutes confidential`, scoped to `site:cormorantcapital.sharepoint.com`, as well as additional sensitive-category searches. This behavior was not part of Emily's summary request.

**Evidence:** Search terms and SharePoint targets in the Graph tool call logs; subsequent `Graph.ReadFile` records with `fileId` references. [Exhibits 07–12](#evidence-screenshot-index).

**KQL — Inspect Graph tool calls and arguments**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where InteractionType == "ToolCall"
| where TimeGenerated between (
    datetime(2026-09-20T10:40:00Z) .. datetime(2026-09-20T10:45:00Z))
| project TimeGenerated, ToolName, ToolParameters
| order by TimeGenerated asc
```

<details>
<summary><strong>Screenshot evidence — Exhibits 07–12 (tool calls and query troubleshooting)</strong></summary>

**Exhibit 07 —** Copilot `ToolCall` events following the summary prompt.

![Exhibit 07 — Copilot tool calls](evidence/exhibit-07.png)

**Exhibit 08 —** Schema correction: `ToolInput` was not a recognized column.

![Exhibit 08 — ToolInput query error](evidence/exhibit-08.png)

**Exhibit 09 —** Expanded `Graph.SearchFiles` event containing confidential-board search parameters.

![Exhibit 09 — Confidential board search](evidence/exhibit-09.png)

**Exhibit 10 —** Searches followed by `Graph.ReadFile` activity.

![Exhibit 10 — SearchFiles and ReadFile](evidence/exhibit-10.png)

**Exhibit 11 —** `ToolName` and `ToolParameters` projected together.

![Exhibit 11 — Tool name and parameters](evidence/exhibit-11.png)

**Exhibit 12 —** Early tool-call timeline in `CopilotAudit_CL`.

![Exhibit 12 — Tool-call timeline](evidence/exhibit-12.png)

</details>

### Q06. Which MITRE ATLAS technique describes the malicious document instructions?

**Answer — Exercise-supported classification.** **MITRE ATLAS `AML.T0051` — LLM Prompt Injection**, specifically **indirect prompt injection** through a lower-trust document.

**My reasoning:** Emily asked for a normal summary, yet Copilot performed unrelated searches after processing the report. In the exercise narrative, the malicious behavioral instructions were carried in external content rather than typed by Emily. The screenshots establish the prompt/tool mismatch; they do not show the full injected document payload.

**Evidence:** Benign user prompt plus unrelated Graph searches and reads. The origin of the injected instructions is provided by the scenario.

### Q07. How many sensitive files did Copilot access that Emily had never opened previously?

**Answer — Exercise-reported:** **Five sensitive files**, in an initial burst lasting approximately **six seconds** around 10:42 UTC.

**My reasoning:** I compared the reported file-access burst against Emily's ordinary document workflow. Five previously unopened sensitive documents accessed in seconds, outside the scope of the user's request, are more suspicious than isolated normal document reads.

**Evidence:** Case handoff reports five previously unopened sensitive files. Exact filenames and historical-open comparisons are not completely displayed in the shared screenshots.

### Q08. What are the names of the five sensitive files Copilot accessed?

**Answer — Not independently confirmed.** I cannot accurately list the five **filenames** from the screenshots. Supported categories are **confidential board materials**, **M&A/acquisition assessments**, and **salary-review documents**.

**My reasoning:** The `Graph.ReadFile` `fileId` values were truncated in the result grid. I would extract each complete ID/path and derive its filename rather than inventing names. I would also check whether any paths refer to the same underlying file.

**Evidence:** `Graph.ReadFile` entries in `CopilotAudit_CL`; complete file IDs were not supplied in the visible capture.

**KQL — Extract read targets and filenames**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where ToolName == "Graph.ReadFile"
| extend FileURL = tostring(parse_json(tostring(ToolParameters)).fileId)
| extend FileName = tostring(split(FileURL, "/")[-1])
| project TimeGenerated, FileName, FileURL
| order by TimeGenerated asc
```

> **Verification note:** This filename extraction assumes that `fileId` holds a URL/path. If it is an opaque ID, the full records or an additional Graph/SharePoint lookup will be needed to resolve filenames.

---

<a id="exfiltration-pathway-and-visibility"></a>

## 03 — Exfiltration Pathway and Visibility (Q09–Q12)

### Q09. Through which domain was the extracted data exfiltrated, and where does that appear in telemetry?

**Answer — Partially observed.** Five external image URLs shared a hostname beginning **`metrics-cdn.analyt…`**, but the **complete domain is truncated** in the screenshots. The links appear inside `CopilotAudit_CL` → `CopilotResponse` → `Response`, formatted as Markdown images in a **Charts** section. The URLs are evidence of a *potential* exfiltration mechanism; a completed transfer is not proven.

**My reasoning:** I pivoted from tool calls to the final Copilot response, noticed remote Markdown chart-image links, and extracted hostnames. My first `extract_all` expression failed because it lacked a regex capturing group. Adding parentheses returned five URL matches. I did not infer a complete hostname from the displayed prefix.

**Evidence:** Five image URL strings in the Copilot response and a corrected five-result URL extraction. [Exhibits 13–15](#evidence-screenshot-index).

**KQL — Extract URLs and hostnames**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where InteractionType == "Response"
| where TimeGenerated between (
    datetime(2026-09-20T10:40:00Z) .. datetime(2026-09-20T10:45:00Z))
| extend URLs = extract_all(@"(https?://[^\s\)]+)", CopilotResponse)
| mv-expand URL = URLs
| extend Domain = tostring(parse_url(tostring(URL)).Host)
| project Domain, URL
```

<details>
<summary><strong>Screenshot evidence — Exhibits 13–15 (image URLs and regex fix)</strong></summary>

**Exhibit 13 —** Copilot response showing Markdown chart-image URLs.

![Exhibit 13 — Copilot response URLs](evidence/exhibit-13.png)

**Exhibit 14 —** Initial `extract_all` failure caused by a missing capturing group.

![Exhibit 14 — Regex capture error](evidence/exhibit-14.png)

**Exhibit 15 —** Corrected extraction producing five external URLs with the same visible host prefix.

![Exhibit 15 — Five extracted URLs](evidence/exhibit-15.png)

</details>

### Q10. How could Copilot transmit data through these URLs, and why might endpoint monitoring miss it?

**Answer — Suspected mechanism, not a confirmed transfer.** The suspected mechanism is **URL-based exfiltration through Markdown image rendering**. Sensitive data could be encoded in attacker-hosted image URLs; if a response renderer requests those URLs, an outbound HTTP request could transmit their contents. Activity initiated by cloud-side Copilot or a remote renderer might not be visible to sensors monitoring only Emily's endpoint.

**My reasoning:** The suspicious SharePoint reads preceded the unexpected chart-image URLs. This ordering is consistent with exfiltration through generated output, but the presence of a link alone does not prove it was fetched. A monitoring blind spot is conditional on where rendering occurred and on the organization’s available network sensors.

**Evidence:** `Graph.SearchFiles`/`Graph.ReadFile` activity and response URLs; **no HTTP fetch record** was included in the provided evidence.

### Q11. Can the audit logs identify the exact exfiltrated content?

**Answer — No.** The supplied audit records show searches, file-read tool calls, and suspicious URLs. They do **not** establish the exact payload transmitted or independently confirm any successful transfer.

**My reasoning:** I separated file-access and tool metadata from the contents of a network request. To verify exfiltrated bytes, I would need full URLs, HTTP/proxy or renderer logs, and any available payload-level evidence.

**Evidence:** No raw outgoing request, confirmed image fetch, or full exfiltration payload in the supplied captures.

### Q12. What did the CoSnitch pattern leak beyond user files, and why would that matter?

**Answer — Exercise-reported.** The lab discussion identifies **Copilot's internal instructions/configuration information** as the additional leak. Such details could help an attacker refine future prompt injections or tool-abuse attempts.

**My reasoning:** The exercise Q&A reports this outcome, but the supplied screenshots do not reveal the raw leaked internal text. I therefore treat it as an exercise-reported finding rather than independently observed content.

**Evidence:** Exercise discussion; no direct capture of the CoSnitch payload.

---

<a id="baseline-comparison-and-follow-on-search"></a>

## 04 — Baseline Comparison and Follow-on Search (Q13–Q16)

### Q13. A manager says Copilot normally accesses files during summaries and research. Does that explain the observed behavior?

**Answer — Not adequately.** Individual file accesses can be legitimate, but this session combined **sensitive searches unrelated to Emily's request**, **five rapid previously unopened file accesses**, and **unusual external image links**.

**My reasoning:** I contrasted Emily's limited summary prompt and routine writing/grammar tasks with the targets, volume, speed, and output of the suspicious session. This combined pattern is not adequately explained by ordinary file access alone.

**Evidence:** Baseline activity ([Exhibits 05–06](#evidence-screenshot-index)); Graph operations ([Exhibits 09–12](#evidence-screenshot-index)); response URLs ([Exhibits 13 and 15](#evidence-screenshot-index)).

### Q14. What three differences distinguish the suspicious Copilot session from normal activity?

**Answer — Three specific differences:**

1. **Search intent:** Copilot searched for confidential board, M&A/acquisition, and salary files rather than focusing on the quarterly report.
2. **Access pattern:** The scenario reports five sensitive, previously unopened file accesses in about six seconds.
3. **Output:** The response included external Markdown chart-image URLs absent from the described normal summary workflow.

**My reasoning:** Comparing user intent, tool behavior, and response artifacts established an anomaly without relying on evidence of an unusual sign-in.

**Evidence:** `UserPrompt` baseline, `Graph.SearchFiles`/`Graph.ReadFile` records, and image-URL extraction.

### Q15. How many additional files did Copilot access during SearchLeak, and what keywords drove the search?

**Answer — Event-count basis:** There were **eight additional `Graph.ReadFile` events** beyond the five initial events, and five later `Graph.SearchFiles` terms: **`confidential`, `restricted`, `board`, `acquisition`, `salary`**.

**My reasoning:** I counted **read events** separately from **search events**. The read query returned thirteen events in the incident period; subtracting the five initial reads leaves eight later reads. Without deduplicating `fileId`, eight *additional distinct files* are not confirmed.

**Evidence:** Thirteen `Graph.ReadFile` records; five later keywords around 10:45 UTC. [Exhibits 16–18](#evidence-screenshot-index).

**KQL — Review later SearchLeak queries**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where ToolName == "Graph.SearchFiles"
| where TimeGenerated between (
    datetime(2026-09-20T10:44:00Z) .. datetime(2026-09-20T11:00:00Z))
| extend SearchKeyword = tostring(parse_json(tostring(ToolParameters)).query)
| project TimeGenerated, SearchKeyword
| order by TimeGenerated asc
```

<details>
<summary><strong>Screenshot evidence — Exhibits 16–18 (SearchLeak and 13 read events)</strong></summary>

**Exhibit 16 —** Broader tool-call activity following the initial session.

![Exhibit 16 — Follow-on tool activity](evidence/exhibit-16.png)

**Exhibit 17 —** Thirteen `Graph.ReadFile` events across the incident window.

![Exhibit 17 — Thirteen ReadFile events](evidence/exhibit-17.png)

**Exhibit 18 —** Later SearchLeak keywords: `confidential`, `restricted`, `board`, `acquisition`, `salary`.

![Exhibit 18 — SearchLeak keywords](evidence/exhibit-18.png)

</details>

### Q16. What is the total number of sensitive files accessed throughout the incident?

**Answer — Thirteen read events**, consisting of **five initial** and **eight later `Graph.ReadFile` events**. The number of **unique files** has **not** been independently established.

**My reasoning:** I reconciled the two incident phases using `Graph.ReadFile` events, excluding `Graph.SearchFiles` operations. I would deduplicate complete `fileId` values before claiming that all thirteen reads targeted different files.

**Evidence:** Thirteen-read query result in [Exhibit 17](#evidence-screenshot-index).

**KQL — Count reads and estimate unique IDs**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where ToolName == "Graph.ReadFile"
| where TimeGenerated between (
    datetime(2026-09-20T10:40:00Z) .. datetime(2026-09-20T11:00:00Z))
| extend FileId = tostring(parse_json(tostring(ToolParameters)).fileId)
| summarize ReadEvents=count(), DistinctFileIds=dcount(FileId)
```

> **Analyst note:** `dcount()` returns an **approximate** distinct count. For an exact file-ID count on this small result set, use `count_distinct(FileId)` if supported by the workspace. Verify that empty/failed `FileId` extraction is not conflating records.

---

<a id="root-cause-and-disposition"></a>

## 05 — Root Cause and Disposition (Q17)

### Q17. Was this account compromise, compromised Copilot configuration, or external input manipulation?

**Answer — Best-supported classification: external input manipulation / indirect prompt injection.** The exercise reports no anomalous sign-in activity for Emily. The suspicious operations used native Copilot/Graph tools, and the screenshots do not show a changed Copilot configuration.

**My reasoning:** I compared three competing explanations:

| Hypothesis | Evidence considered | Assessment |
|---|---|---|
| **Compromised account** | Exercise reports ordinary Entra sign-ins; Emily's prompt itself was legitimate | Not supported by the provided evidence; not conclusively excluded |
| **Compromised Copilot configuration** | No observed configuration-change events; native Graph tool calls were used | Not supported by the provided evidence; not conclusively excluded |
| **External document/input manipulation** | Benign summary prompt followed by irrelevant sensitive searches and reads | **Best-supported explanation** |

**Evidence:** Scenario handoff (normal Entra sign-ins), prompt and tool-call screenshots, and no supplied configuration-tampering records.

**Disposition:** Suspicious Copilot tool use consistent with a document-borne indirect prompt injection. **Exfiltration success, exact payload, sender identity, attachment filename, and unique accessed files remain subject to verification.**

---

## Appendix A — Query Troubleshooting

My investigation encountered several tooling and query obstacles:

1. **Workspace mismatch:** `OfficeActivity_CL` did not resolve under `LAW-Cyber-Range`. I switched to **`LAW-HuntPractice`**.
2. **Time-window mismatch:** I aligned the UI's local custom time range with the UTC incident period. On September 20, 2026, **04:00–06:00 CDT corresponds to 09:00–11:00 UTC**.
3. **Incorrect column name:** `ToolInput` was not available in the lab schema. I inspected the event and used **`ToolParameters`** and **`ToolName`**.
4. **Regex extraction:** `extract_all` required a **capturing group** to return the intended URLs, so I added parentheses around the URL pattern.
5. **Count interpretation:** I counted `Graph.ReadFile` operations independently of `Graph.SearchFiles` results and avoided equating read events with unique documents.

These corrections were part of the investigative process and are preserved in the screenshots instead of being removed from the case study.

## Appendix B — Follow-up Verification Checklist

- [ ] Expand the original Exchange `MessageReceived` event to identify the actual sender and full attachment filename.
- [ ] Retrieve all untruncated `Graph.ReadFile` `fileId` values, resolve filenames, and deduplicate the thirteen read events.
- [ ] Capture the complete external hostname instead of assuming the full spelling of `metrics-cdn.analyt…`.
- [ ] Correlate generated image URLs with HTTP, proxy, cloud-renderer, or server-side request logs before confirming exfiltration.
- [ ] Retrieve actual CoSnitch internal-instruction leakage if independent validation is required.
- [ ] Review `EntraSignIn_CL` and configuration-change audit data before definitively excluding account or configuration compromise.

## Evidence Screenshot Index

All images below were **extracted from the original 35-page investigation document**, retaining their original 1920×1080 resolution. Each image is available at the relative path shown here and is embedded in the relevant question above.

| Exhibit | Description | Image |
|---|---|---|
| 01 | Wrong workspace / unresolved custom table | [View](evidence/exhibit-01.png) |
| 02 | Exchange `MessageReceived` results | [View](evidence/exhibit-02.png) |
| 03 | Delivery and earliest visible file-access events | [View](evidence/exhibit-03.png) |
| 04 | Expanded `FileAccessed` event | [View](evidence/exhibit-04.png) |
| 05 | Routine Copilot prompts / noise floor | [View](evidence/exhibit-05.png) |
| 06 | Filtered `UserPrompt` entries | [View](evidence/exhibit-06.png) |
| 07 | Copilot `ToolCall` records | [View](evidence/exhibit-07.png) |
| 08 | Query error: `ToolInput` is not recognized | [View](evidence/exhibit-08.png) |
| 09 | `Graph.SearchFiles` confidential-board arguments | [View](evidence/exhibit-09.png) |
| 10 | Graph search and read operations | [View](evidence/exhibit-10.png) |
| 11 | `ToolName` with `ToolParameters` | [View](evidence/exhibit-11.png) |
| 12 | Initial tool-call timeline | [View](evidence/exhibit-12.png) |
| 13 | Copilot response with Markdown image URLs | [View](evidence/exhibit-13.png) |
| 14 | Failed `extract_all` expression | [View](evidence/exhibit-14.png) |
| 15 | Five extracted external image URLs | [View](evidence/exhibit-15.png) |
| 16 | Later tool-call activity | [View](evidence/exhibit-16.png) |
| 17 | Thirteen `Graph.ReadFile` events | [View](evidence/exhibit-17.png) |
| 18 | SearchLeak keyword evidence | [View](evidence/exhibit-18.png) |

## Source and Format Notes

**Primary source:** *Corey Lee - Threat Hunting Live Event .docx* (35 pages and 18 embedded Microsoft Defender screenshots). The provided investigation summary and Q&A were consolidated into **17 unique questions**; repeated questions were omitted. Screenshot evidence is original, not recreated. Where the available screenshots truncate fields or the exercise narrative goes beyond visible telemetry, the distinction is stated explicitly.

**Research focus:** Prompt injection, Microsoft 365 Copilot, Kusto Query Language (KQL), Microsoft Graph tool abuse, SharePoint file access, investigative troubleshooting, and evidence-based incident reporting.

---

*Portfolio case study by Corey Lee — Operation ECHOLEAK — simulated training environment.*
