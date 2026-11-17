# How OAR records line up with rules in the EU, the US and Canada

*As of 17 November 2026. Not legal advice.*

OAR records are evidence: of what an AI agent asked to do, what the rules decided, who approved it, and what actually
changed. **Evidence helps an organisation meet a rule; it does not make anyone compliant.** Whether a system meets a
rule depends on how it is built and run, and on legal advice for that organisation.

This page maps what OAR records today (`SPEC.md`, version 0.3 with the November 2026 additions) to rules that ask for that kind of evidence. Where OAR
does not cover something yet, the last column says so, and items marked *proposed* are open proposals for a future
version, not part of the specification.

## European Union

| Rule | What it asks for | What OAR records | Not covered yet |
|---|---|---|---|
| **AI Act, Article 12** (record-keeping for high-risk AI systems) | Systems must "technically allow for the automatic recording of events (logs) over the lifetime of the system", to identify risks, support post-market monitoring and let deployers monitor operation. No log format is prescribed. | One signed record per step of each action: decision, approval, execution, confirmation (sections 4.1, 4.2). Records are chained per agent, so a missing or reordered record shows (section 6, check 3). | The model and agent version that acted (*proposed*: agent and model identity). |
| **AI Act, Article 14 and Article 26(2)** (human oversight) | People assigned to oversee the system, able to intervene. | Who approved or rejected each held action, by what method (`approval`, section 4.3), and which rules version decided (`authorization_ref`). | Records of who changed the rules (*proposed*: governance records). An emergency stop shows on each refused action as `agents_paused` (section 7). |
| **AI Act, Article 19(1) and Article 26(6)** (keeping logs) | Providers and deployers keep logs under their control "for a period appropriate to the intended purpose … of at least six months", unless other law says otherwise. | Bundles keep records verifiable offline for as long as they are kept, without relying on the system that wrote them (section 8). | Covered by the retention section (section 11.1) and the bundle's optional `retention` field (section 8). |
| **AI Act application dates** | High-risk obligations were due to apply in August 2026. A provisional agreement on the Digital Omnibus (6 May 2026, confirmed by member states on 13 May 2026) moves stand-alone high-risk systems (Annex III) to 2 December 2027 and AI in regulated products (Annex I) to 2 August 2028, once published in the Official Journal. | | |
| **ISO/IEC 24970, AI system logging** (final draft, FDIS) | Common capabilities, requirements and an information model for logging events in AI systems; built to be used with a risk management system. | OAR is a record format for one kind of event, agent actions, and could be one source of events in such a log. | A link from each record to an organisation's other logs (*proposed*: `trace_ref`). |
| **PSD2 strong customer authentication, Delegated Regulation 2018/389, Article 5** (dynamic linking) | The payer "is made aware of the amount … and of the payee"; the authentication code is "specific to the amount … and the payee"; "any change to the amount or the payee results in the invalidation" of the code. | The approval is bound to the exact action and to what the approver was shown, including the amount and payee; any change gives a different binding, and every verifier checks it (sections 4.3 and 4.3.1, check 7). Approvals by an outside service, such as a bank app or a SIM check, carry the same binding and the digest of the service's proof. | Whether the outside service showed the approver the same details is that service's evidence; OAR records its proof by digest. |
| **PSD3 and the Payment Services Regulation** (final compromise texts, April 2026; not yet adopted) | Among other things, a check that the payee's name matches the account identifier before a credit transfer, applying 27 months after the Regulation enters into force, and refunds for some impersonation fraud. | Common reason codes for a new payee and changed payee details (`new_payee`, `payee_details_changed`, section 7) let a record show why a payment was held. | OAR does not perform the name check; it can record that one was done and its result. |
| **GDPR** (data minimisation, erasure, pseudonymisation) | Personal data kept only as needed; a right to erasure. In *EDPS v SRB* (C-413/23 P, 4 September 2025) the Court of Justice held that pseudonymised data is not personal data for a recipient who cannot reasonably re-identify the person; it stays personal data for the controller who can. | No personal data in clear: values sit behind salted commitments and are opened field by field (sections 2, 11). Deleting the salts and disclosures for a value means it can never be opened again, while the record still verifies. | The method is in section 11.1. Whether it meets a given erasure request is a question for that organisation's counsel. |

## United States

| Rule | What it asks for | What OAR records | Not covered yet |
|---|---|---|---|
| **New York DFS cybersecurity regulation, 23 NYCRR 500.6** (audit trail) | Systems that can "reconstruct material financial transactions" and audit trails to detect and respond to cybersecurity events; records kept "for not fewer than five years". | The decision, approval, execution and confirmation of each agent action, with commitments to the state before and after the change (section 4.2), so a transaction an agent made can be reconstructed and checked. | Retention: section 11.1. |
| **NIST AI Agent Standards Initiative** (CAISI, launched February 2026) | Industry-led standards and open protocols for agents; NCCoE draft concept paper on agent identity and authorization (comments closed 2 April 2026). No logging or approval requirements yet. | Which agent acted (`agent_id`, a chain per agent), who approved, and on what rules. | Agent and model identity in more detail (*proposed*). |

## Canada

| Rule | What it asks for | What OAR records | Not covered yet |
|---|---|---|---|
| **OSFI Guideline E-23, Model Risk Management** (final August 2025, in force May 2027) | Governance and oversight of models at federally regulated financial institutions, explicitly including AI and machine learning. | Which rules decided each action (`authorization_ref`), the outcome, and who approved exceptions. | Which model and agent version acted, and who changed the rules (*proposed*). |
| **Federal AI and privacy law** | No federal AI law: the national strategy, *AI for All* (4 June 2026), proposes none. New consumer privacy legislation is expected, including on automated processing of personal information. | Commitments keep personal data out of records. | To be reviewed when the privacy bill is published. |

## Proposed changes this page refers to

These are proposals for discussion, not part of OAR 0.3. Comments are welcome in an issue.

| Proposal | What it adds | Rules it supports |
|---|---|---|
| Governance records | Who changed the rules, when, and who approved the change; emergency stops | AI Act Articles 14 and 26, OSFI E-23 |
| Agent and model identity | Agent version, model and provider, as a commitment | AI Act Article 12, OSFI E-23, NIST |
| Incident bundle | All records in a time window, with a completeness check | Incident reporting rules |
| `trace_ref` | A link to the organisation's other logs (OpenTelemetry trace and span) | ISO/IEC 24970 |
| Long-term timestamps | Re-timestamping before algorithms age; certificate status captured at timestamp time | Long-term evidence |

## Sources

- AI Act Article 19: [AI Act Service Desk, European Commission](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-19)
- AI Act Article 12: [Help Net Security, 16 April 2026](https://www.helpnetsecurity.com/2026/04/16/eu-ai-act-logging-requirements/)
- Digital Omnibus on AI: [Gibson Dunn](https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/)
- ISO/IEC 24970: [StandICT.eu](https://standict.eu/standards-repository/artificial-intelligence-ai-system-logging-isoiec-fdis-24970)
- Delegated Regulation 2018/389, Article 5 (UK retained text, quoted): [legislation.gov.uk](https://legislation.gov.uk/eur/2018/389/article/5); EU text: [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2018/389)
- PSD3 and the PSR: [Arthur Cox, 30 April 2026](https://www.arthurcox.com/insights/psd3-and-psr-final-compromise-texts-published/)
- *EDPS v SRB*: [Clifford Chance](https://www.cliffordchance.com/insights/resources/blogs/talking-tech/en/articles/2025/09/pseudonymized-data-after-edps-v-srb.html)
- 23 NYCRR 500.6: [Cornell Legal Information Institute](https://www.law.cornell.edu/regulations/new-york/23-NYCRR-500.6)
- NIST AI Agent Standards Initiative: [NIST](https://www.nist.gov/caisi/ai-agent-standards-initiative)
- OSFI Guideline E-23: [OSFI backgrounder](https://www.osfi-bsif.gc.ca/en/news/backgrounder-guideline-e-23-model-risk-management)
- *AI for All*: [Blakes](https://www.blakes.com/insights/canada-s-ai-for-all-strategy-key-takeaways-for-businesses/)
