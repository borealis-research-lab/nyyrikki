# Nyyrikki scope

- **Input:** Windows Security events exported to XML (with `wevtutil` or Event Viewer). This is the initially selected source. The live event log isn't read yet.
- **Task:** identify potentially suspicious activity. The current rules are listed in [detections.md](detections.md).
- **Optional local AI:** a local model may help interpret event context. It must not invent evidence, and its output is checked against the cited events.
- **Output:** a structured finding tied to the source event or events, by `EventRecordID`.
- **Execution:** local.
- **Model and runtime:** llama.cpp is the adopted local runtime (via its OpenAI-compatible `llama-server`). No model has been selected; Qwen3.5 0.8B and 2B are being benchmarked.
- **System changes:** none. Nyyrikki only reads the file it is given.

## Non-goals

- Distributed compute or worker networking.
- A Borealis coordinator.
- Multi-agent orchestration or agent frameworks.
- Multiple agents or a general-purpose AI assistant.
- Public threat-intelligence aggregation or feed monitoring.
- Vulnerability scanning or vulnerability-feed monitoring.
- Network scanning.
- Offensive security, exploit execution, retaliation or counterattacks.
- Automatic remediation, blocking, account changes or destructive actions.
- A web dashboard or hosted service.
- Cloud LLM APIs or mandatory external AI services.
- Kubernetes, message brokers, databases or microservices.
- A large collection of detection rules or operating-system integrations.
