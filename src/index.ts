import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { auditIamPolicy, auditIamSchema } from './tools/audit-iam.js';

const server = new Server(
    { name: 'archestrate-security', version: '1.0.0' },
    { capabilities: { tools: {} } }
);

/**
 * List all available tools.
 * Archestra's orchestrator calls this to discover what our server can do.
 */
server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        {
            name: 'audit_iam_policy',
            description:
                'Analyzes an AWS IAM policy JSON document for security vulnerabilities. ' +
                'Checks for privilege escalation risks (iam:PassRole, sts:AssumeRole), ' +
                'overly permissive actions and resources (wildcards), missing conditions, ' +
                'sensitive service access (KMS, Secrets Manager, CloudTrail), ' +
                'and network/Lambda security issues. ' +
                'Returns structured findings with severity levels (HIGH/MEDIUM/LOW) ' +
                'and actionable remediation guidance.',
            inputSchema: {
                type: 'object' as const,
                properties: {
                    policyJson: {
                        type: 'string',
                        description: 'The AWS IAM policy JSON document to analyze',
                    },
                },
                required: ['policyJson'],
            },
        },
    ],
}));

/**
 * Handle tool execution requests.
 * The agent sends tool calls here; we validate, run, and return results.
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === 'audit_iam_policy') {
        try {
            const validated = auditIamSchema.parse(args);
            const result = auditIamPolicy(validated);
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify(result, null, 2),
                    },
                ],
            };
        } catch (error) {
            const message =
                error instanceof Error ? error.message : 'Unknown error occurred';
            return {
                content: [{ type: 'text', text: `Error: ${message}` }],
                isError: true,
            };
        }
    }

    throw new Error(`Unknown tool: ${name}`);
});

/**
 * Start the MCP server using stdio transport.
 * Archestra connects to this via stdin/stdout.
 */
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('🛡️ Archestrate Security MCP Server running');
}

main().catch(console.error);
