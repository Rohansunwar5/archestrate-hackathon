# 🛡️ Archestrate — AI-Powered IAM Security Audit Agent

> An MCP (Model Context Protocol) server that audits AWS IAM policies for security vulnerabilities, built on the [Archestra](https://archestra.ai) platform.

## 🚀 Quick Start

### Prerequisites
- Docker Desktop installed and running
- An LLM API key (OpenAI, Anthropic, etc.)

### 1. Start Archestra Platform
```bash
docker pull archestra/platform:latest
docker run -d --name archestra -p 9000:9000 -p 3000:3000 \
  -e ARCHESTRA_QUICKSTART=true \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v archestra-postgres-data:/var/lib/postgresql/data \
  -v archestra-app-data:/app/data \
  archestra/platform:latest
```

Wait ~5 minutes, then open http://localhost:3000

### 2. Build the MCP Server
```bash
npm install
npm run build
```

### 3. Register in Archestra
1. Open Archestra UI → **MCP Registry**
2. Add Local MCP Server with Docker image
3. Create a **Security Auditor** agent
4. Test via **Chat UI**

## 🏗️ Architecture

```
User → Archestra Chat UI → Security Auditor Agent → MCP Orchestrator
                                                          ↓
                                                  Archestrate MCP Server
                                                          ↓
                                                  IAM Rule Engine (10 rules)
                                                          ↓
                                                  Structured Findings
```

## 🔍 What It Detects

| # | Rule | Severity |
|---|------|----------|
| 1 | Full admin access (`*:*`) | 🔴 HIGH |
| 2 | Wildcard actions | 🔴 HIGH |
| 3 | Wildcard resources | 🔴 HIGH |
| 4 | `iam:PassRole` without conditions (privilege escalation) | 🔴 HIGH |
| 5 | `sts:AssumeRole` on `*` (role chaining) | 🔴 HIGH |
| 6 | Broad data service access (`s3:*`, `dynamodb:*`) | 🟡 MEDIUM |
| 7 | Sensitive service access (KMS, Secrets Manager, CloudTrail) | 🟡 MEDIUM |
| 8 | IAM write actions without MFA | 🟡 MEDIUM |
| 9 | Security group modification on `*` | 🟡 MEDIUM |
| 10 | Lambda function access on `*` | 🟡 MEDIUM |

## 🛡️ Archestra Features Used

1. **Docker Quickstart** — 1-command platform setup
2. **Chat UI** — Primary interface
3. **Private MCP Registry** — Server registration
4. **MCP Orchestrator** — Kubernetes-native execution
5. **No-Code Agent Builder** — Agent configuration
6. **Security Sub-Agents (Dual LLM)** — Prompt injection defense
7. **Cost Monitoring** — Per-audit cost tracking
8. **Observability** — Prometheus/Grafana metrics
9. **Multi-LLM Support** — Cost vs accuracy comparison
10. **MCP Gateway** — External API access

## 📁 Project Structure

```
archestrate-mcp/
├── src/
│   ├── index.ts                 # MCP server entry point
│   ├── tools/audit-iam.ts       # Tool handler + validation
│   ├── analyzers/iam-rules.ts   # 10 security detection rules
│   └── types/index.ts           # TypeScript interfaces
├── examples/
│   ├── benign-policy.json       # Clean policy (0 findings)
│   ├── privesc-policy.json      # Privilege escalation demo
│   └── malicious-policy.json    # Prompt injection test
├── Dockerfile
├── package.json
└── tsconfig.json
```

## 🏆 Hackathon

Built for the **2 Fast 2 MCP** hackathon — **Speed Racer (Best Solo)** track.

## License

MIT
