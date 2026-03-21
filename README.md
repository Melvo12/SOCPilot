# 🛡️ SOCPilot — On-Prem AI Assistant

An AI-powered assistant that helps SOC analysts investigate security incidents, write professional observations, and make faster decisions running entirely on your infrastructure, no cloud required.

---

## The Problem

SOC teams face daily challenges that slow down incident response:

- **Alert fatigue** — thousands of events per day, hard to prioritize
- **Junior analyst gap** — difficulty interpreting logs and making decisions under pressure
- **Poor report quality** — inconsistent observations, unprofessional language
- **Time waste** — analyzing a single event can take 10–20 minutes manually

## The Solution

SOC Copilot acts as an intelligent analyst assistant that:

- Analyzes security logs automatically
- Classifies severity (LOW / MEDIUM / HIGH / CRITICAL)
- Generates professional incident observations
- Suggests concrete actions (block IP, reset credentials, isolate endpoint)
- Maps events to MITRE ATT&CK techniques
- Generates a full incident report ready to paste into your ticket

**All in seconds. All on your servers.**

---

## Features

- AI-powered log analysis via local LLM (no data leaves your network)
- Severity classification with strict rules
- MITRE ATT&CK mapping
- Incident report generation with download
- Standard log format template with one-click copy
- 100% on-premises via Docker

---

## Requirements

- [Docker](https://www.docker.com/products/docker-desktop) installed
- 8 GB RAM minimum (16 GB recommended)
- ~6 GB disk space for the model and containers

---

## Quick Start

**1. Clone the repository**
```bash
git clone https://github.com/Melvo12/SOC-IA-Improve.git
cd SOC-IA-Improve
```

**2. Start the containers**
```bash
docker compose up -d
```

**3. Download the AI model** (first time only, ~4.7 GB)
```bash
docker exec -it soc-ollama ollama pull llama3.1:8b
```

**4. Open the app**
```
http://localhost:8501
```

---

## How to Use

**Tab 1 — Analyze Event**
1. Click **Copy Format** to get the standard log template
2. Fill in the template with your security event details
3. Paste it in the text area and click **Analyze**
4. Review severity, observation, and recommended actions

**Tab 2 — Incident Report**
1. Fields are pre-filled from your last analysis
2. Fill in manual fields (Incident ID, Analyst Name, Affected Asset)
3. Click **Generate Report**
4. Download the `.txt` file ready for your ticketing system

---

## Supported Event Types

- Brute force / credential attacks
- Port scanning
- Data exfiltration
- Malware alerts
- Suspicious outbound connections
- Privilege escalation attempts
- And more — the model handles any security event description

---

## Architecture
```
┌─────────────────────────────────────┐
│           Docker Network            │
│                                     │
│  ┌─────────────┐  ┌───────────────┐ │
│  │  soc-ollama │  │  soc-copilot  │ │
│  │             │◄─│               │ │
│  │  Llama 3.1  │  │   Streamlit   │ │
│  │  Port 11434 │  │   Port 8501   │ │
│  └─────────────┘  └───────────────┘ │
└─────────────────────────────────────┘
         │
         ▼
  http://localhost:8501
```

---

## Roadmap

- [ ] Analysis session history
- [ ] PDF report export
- [ ] Custom report templates per organization
- [ ] Multi-format log support (Syslog, Windows Event Log, JSON)
- [ ] SIEM integration (Splunk, Elastic)
- [ ] Fine-tuned model for SOC-specific analysis

---

## Who Is This For

- Small SOC teams without mature security tooling
- MSSPs managing multiple clients
- Junior analysts who need guidance on incident response
- Security students learning log analysis
- Blue teams looking to accelerate triage

---

## Disclaimer

SOC Copilot is an AI assistant designed to **support** analysts, not replace them. Always validate AI-generated observations with human judgment before taking action.

---

## License

MIT License — free to use, modify, and distribute.

---

Built with 🛡️ by a SOC analyst, for SOC analysts.
