# VAJRA Engineering Instructions

Project: VAJRA
Full name: Vigilant AI for Judicious Real-time Asymmetric Analysis
Problem Statement: SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Organization: NTRO

MISSION
Build a technically defensible research prototype for passive cyber-threat detection over strictly unidirectional IP traffic.

CORE CONSTRAINTS
1. The system is read-only.
2. Never send packets, probes, queries, acknowledgements, mitigation commands, or feedback toward the observed network.
3. Never assume a return path exists.
4. Never require a TCP handshake to identify or analyse observed traffic.
5. Never decrypt TLS/QUIC payloads.
6. Analyse encrypted sessions using observable metadata only.
7. Process traffic incrementally rather than relying only on end-of-run batch analysis.
8. Every detection must provide supporting evidence.
9. Never fabricate accuracy, latency, throughput, confidence, or benchmark numbers.
10. Synthetic/lab traffic must be clearly identified as synthetic/lab traffic.
11. Do not claim VAJRA is the "first" system in the world unless independently verified.
12. Do not create features that require information unavailable from one-way observation.

ENGINEERING PRINCIPLES
- Prefer simple, testable components over unnecessary complexity.
- Do not introduce Rust, eBPF, Kubernetes, cloud services, databases, or microservices unless there is a demonstrated need.
- Python is the primary implementation language for the prototype.
- Keep ingestion, flow tracking, feature extraction, detection, ML, alerting, API, and frontend logically separated.
- Do not duplicate business logic in the frontend.
- Do not hard-code fake dashboard values.
- Do not silently invent missing data.
- Every important calculation must have tests.
- Preserve existing interfaces when extending the project.
- Inspect the existing repository before modifying it.
- Do not rewrite working modules unnecessarily.

DETECTION SCOPE
The prototype should address the SIH26145 threat categories where feasible:
- volumetric/protocol anomalies
- C2 beaconing
- DGA/DNS tunnelling
- encrypted-session behavioural anomalies using metadata
- reconnaissance/port scanning
- data-exfiltration anomalies

EVIDENCE
Alerts should contain, where available:
- timestamp
- flow identifier
- threat class
- confidence/score
- severity
- supporting feature values
- explanation/evidence

TESTING
Every module must have tests.
Use controlled synthetic/lab traffic for repeatable demonstrations.
Separate training, validation, and test data when ML is used.
Avoid temporal/data leakage.
Never fabricate evaluation metrics.

STYLE
Write code that looks like a deliberate student cybersecurity project, not a generated toy application.
Use meaningful names, small modules, clear comments where reasoning matters, and documentation of important design decisions.
Avoid excessive comments that merely restate code.
