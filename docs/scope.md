# Nyyrikki scope

- **Input:** local security events from one initially selected source. The source has not yet been selected.
- **Task:** identify potentially suspicious activity.
- **Optional local AI:** a local model may help interpret event context. It must not invent evidence.
- **Output:** a structured finding tied to the source event or events.
- **Execution:** local.
- **Model and runtime:** none selected yet.
- **System changes:** none. Nyyrikki does not change the system automatically.

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
