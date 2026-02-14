# 🛡️ Archestrate — AI-Powered IAM Security Audit Agent

> An MCP (Model Context Protocol) server that audits AWS IAM policies for security vulnerabilities, built on the [Archestra](https://archestra.ai) platform.

**Hackathon:** 2 Fast 2 MCP · **Track:** Speed Racer (Best Solo)

---

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
Default login: `admin@example.com` / `password`

### 2. Build the MCP Server
```bash
cd archestrate-mcp
npm install
npm run build
docker build -t archestrate-security:latest .
```

### 3. Load Image into KinD Cluster
Since Archestra uses KinD (Kubernetes-in-Docker), the image must be loaded into the cluster:
```bash
# Save docker image to tarball
docker save archestrate-security:latest -o image.tar

# Copy into Archestra container and load into KinD
docker cp image.tar archestra:/tmp/
docker exec archestra kind load image-archive /tmp/image.tar --name archestra-mcp

# Cleanup
rm image.tar
```

### 4. Register in Archestra
1. Open Archestra UI → **Settings** → Add your LLM API key
2. Go to **MCP Registry** → **Add MCP Server to the Registry**
3. Select **Self-hosted** tab and configure:
   - **Name:** `archestrate-security`
   - **Command:** `node`
   - **Docker Image:** `archestrate-security:latest`
   - **Arguments:** `dist/index.js`
   - **Transport Type:** `stdio`
4. Go to **Agents** → **Create Agent**
   - **Name:** `Security Auditor`
   - **Description:** `Audits AWS IAM policies for security vulnerabilities`
   - **Tools:** Enable `audit_iam_policy` from `archestrate-security`
   - **System Prompt:**
     ```
     You are an expert AWS IAM security auditor. When the user provides an
     IAM policy JSON, use the audit_iam_policy tool to analyze it. Present
     the findings clearly with severity levels, explain the security risks,
     and provide actionable remediation steps.
     ```
5. Go to **Chat** → Select **Security Auditor** → Paste an IAM policy

---

## 🏗️ Architecture

```
User → Archestra Chat UI → Security Auditor Agent (LLM)
                                      ↓
                              MCP Orchestrator (K8s)
                                      ↓
                            Archestrate MCP Server (Docker)
                                      ↓
                              IAM Rule Engine (10 rules)
                                      ↓
                             Structured JSON Findings
```

**How it works:**
1. User pastes an IAM policy JSON in the Archestra Chat UI
2. The LLM agent recognizes it as an IAM policy and calls `audit_iam_policy`
3. The MCP Orchestrator routes the request to the Kubernetes-deployed container
4. Our rule engine analyzes the policy against 10 security rules
5. Structured findings (severity, risk, remediation) are returned to the LLM
6. The agent presents a human-readable security report

---

## 🔍 Detection Rules

| # | Rule | What It Catches | Severity |
|---|------|-----------------|----------|
| 1 | Full admin access | `Action: "*"` + `Resource: "*"` grants god-mode | 🔴 HIGH |
| 2 | Wildcard actions | `Action: "*"` allows all API calls on a service | 🔴 HIGH |
| 3 | Wildcard resources | `Resource: "*"` removes resource-level scoping | 🔴 HIGH |
| 4 | PassRole abuse | `iam:PassRole` without `Condition` enables priv-esc | 🔴 HIGH |
| 5 | Role chaining | `sts:AssumeRole` on `*` enables cross-account pivoting | 🔴 HIGH |
| 6 | Data service blast radius | `s3:*`, `dynamodb:*`, `rds:*` on wildcard resources | 🟡 MEDIUM |
| 7 | Sensitive service access | KMS, Secrets Manager, CloudTrail operations | 🟡 MEDIUM |
| 8 | IAM write without MFA | IAM mutations (CreateUser, AttachPolicy) without MFA | 🟡 MEDIUM |
| 9 | Network exposure | Security group modifications on all resources | 🟡 MEDIUM |
| 10 | Lambda code execution | InvokeFunction/CreateFunction on wildcard resources | 🟡 MEDIUM |

### Rule Details

**Rule 4 — iam:PassRole Privilege Escalation:**  
`iam:PassRole` allows an entity to assign a role to an AWS service. Without conditions, an attacker can pass a high-privilege role to a compromised service, escalating their own access. The fix is adding `iam:PassedToService` condition.

**Rule 5 — sts:AssumeRole Role Chaining:**  
Unrestricted `sts:AssumeRole` combined with Organizations read access enables an attacker to enumerate all accounts, then assume any role in any account — a devastating cross-account attack vector.

**Rule 7 — Sensitive Service Access:**  
CloudTrail modifications (`StopLogging`, `DeleteTrail`) are particularly dangerous because they allow attackers to disable audit logging, covering their tracks during an active breach.

---

## 🧪 Test Cases

| # | File | Description | Expected Findings |
|---|------|-------------|-------------------|
| 1 | `benign-policy.json` | S3 read-only on specific bucket | ✅ 0 findings |
| 2 | `privesc-policy.json` | PassRole + AssumeRole + full admin | 🔴 9 findings (5H, 3M, 1L) |
| 3 | `malicious-policy.json` | Prompt injection embedded in policy | 🛡️ Dual LLM blocks attack |
| 4 | `network-lambda-policy.json` | Security groups + Lambda on `*` | 🟡 4 findings (2H, 2M) |
| 5 | `data-exfiltration-policy.json` | S3/DynamoDB/RDS + KMS + CloudTrail | 🟡 4 findings (2H, 2M) |
| 6 | `iam-write-no-mfa-policy.json` | IAM user/role management without MFA | 🟡 2 findings (1H, 1M) |
| 7 | `role-chaining-policy.json` | AssumeRole on `*` + Orgs read | 🔴 2 findings (2H) |
| 8 | `outdated-version-policy.json` | Old policy version 2008-10-17 | 🔵 1 finding (1L) |

### Try in Chat
Paste any test policy directly into the Archestra Chat UI:
```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
```

---

## 🛡️ Archestra Platform Features Used

| Feature | How We Use It |
|---------|---------------|
| **Docker Quickstart** | One-command platform setup |
| **Private MCP Registry** | Registered and managed `archestrate-security` server |
| **MCP Orchestrator** | Kubernetes-native container execution in KinD |
| **No-Code Agent Builder** | Created Security Auditor agent via UI |
| **Chat UI** | Primary user interface for policy audits |
| **Security Sub-Agents (Dual LLM)** | Defense against prompt injection attacks |
| **Multi-LLM Support** | Flexible model selection |
| **Observability** | Request logging and deployment monitoring |
| **Cost Monitoring** | Per-request cost tracking |
| **A2A Protocol** | External API endpoint for agent integration |

---

## 📁 Project Structure

```
archestrate-mcp/
├── src/
│   ├── index.ts                     # MCP server entry point (stdio transport)
│   ├── tools/audit-iam.ts           # Tool handler + Zod schema validation
│   ├── analyzers/iam-rules.ts       # 10 security detection rules
│   └── types/index.ts               # TypeScript interfaces (IAMPolicy, Finding)
├── examples/
│   ├── benign-policy.json           # Least-privilege S3 read-only
│   ├── privesc-policy.json          # Multi-vulnerability privilege escalation
│   ├── malicious-policy.json        # Prompt injection test case
│   ├── network-lambda-policy.json   # Security group + Lambda exposure
│   ├── data-exfiltration-policy.json# Data service + KMS + CloudTrail
│   ├── iam-write-no-mfa-policy.json # IAM write without MFA conditions
│   ├── role-chaining-policy.json    # sts:AssumeRole cross-account pivot
│   └── outdated-version-policy.json # Old policy version detection
├── Dockerfile                       # Alpine Node.js multi-stage build
├── DEMO_SCRIPT.md                   # 3-minute demo video script
├── package.json                     # ESM module config + dependencies
└── tsconfig.json                    # TypeScript NodeNext module setup
```

---

## 🔧 Development

```bash
# Install dependencies
npm install

# Build TypeScript to JavaScript
npm run build

# Run locally (stdio mode)
npm start

# Dev mode with watch
npm run dev
```

### Tech Stack
- **Language:** TypeScript (ESM modules)
- **Runtime:** Node.js 22 (Alpine)
- **Protocol:** MCP (Model Context Protocol) via `@modelcontextprotocol/sdk`
- **Validation:** Zod for input schema validation
- **Container:** Docker (multi-stage build)
- **Orchestration:** Kubernetes via KinD (inside Archestra)

---

## 📊 Sample Output

When analyzing `privesc-policy.json`, the agent returns:

```
Total Findings: 9
├── HIGH Severity: 5
│   ├── Statement 1: Resource: "*" — applies to ALL resources
│   ├── Statement 1: iam:PassRole without conditions — privilege escalation
│   ├── Statement 1: sts:AssumeRole on all resources — role chaining
│   ├── Statement 2: Full admin access — Action:"*" on Resource:"*"
│   └── Statement 3: Resource: "*" — applies to ALL resources
├── MEDIUM Severity: 3
│   ├── Statement 1: IAM write actions without MFA
│   ├── Statement 3: Broad data service access with wildcard resources
│   └── Statement 4: Sensitive service access (KMS/Secrets/CloudTrail)
└── LOW Severity: 1
    └── (none in this policy — version is current)
```

Each finding includes:
- **Severity:** HIGH / MEDIUM / LOW
- **Finding:** Human-readable description of the vulnerability
- **Recommendation:** Specific remediation steps (e.g., add Condition block)
- **Affected Statement:** Which statement triggered the rule

---

## 🏆 Hackathon Alignment

| Criteria | Weight | How We Address It |
|----------|--------|-------------------|
| **Potential Impact** | 35% | Automates real-world IAM security auditing |
| **Creativity** | 20% | Security-focused MCP (not just RAG/retrieval) |
| **Technical Implementation** | 20% | 10 rules, Zod validation, Docker + K8s |
| **Best Use of Archestra** | 15% | Uses 10 platform features |
| **Aesthetics & UX** | 5% | Clean, actionable output with severity levels |
| **Learning & Growth** | 5% | Overcame Docker-in-Docker, KinD image loading |

---

## 🔮 Future Enhancements

- **AWS API integration** — Fetch live IAM policies via AWS SDK
- **IaC scanning** — Parse Terraform/CloudFormation for IAM resources
- **Compliance mapping** — Map findings to CIS, SOC 2, ISO 27001
- **Auto-remediation** — Generate least-privilege policy suggestions
- **Multi-account** — Scan entire AWS Organizations

---

## 📜 License

MIT

## 🙏 Acknowledgments

Built for the **2 Fast 2 MCP** hackathon using the [Archestra](https://archestra.ai) platform.
