import { z } from 'zod';
import { analyzePolicy } from '../analyzers/iam-rules.js';
import { AuditResult, IAMPolicy } from '../types/index.js';

/**
 * Zod schema for validating audit_iam_policy tool input.
 */
export const auditIamSchema = z.object({
    policyJson: z
        .string()
        .describe(
            'The AWS IAM policy JSON document to analyze for security vulnerabilities'
        ),
});

export type AuditIamInput = z.infer<typeof auditIamSchema>;

/**
 * Parses an IAM policy JSON string, runs it through the rule engine,
 * and returns structured findings with summary counts.
 */
export function auditIamPolicy(input: AuditIamInput): AuditResult {
    let policy: IAMPolicy;

    try {
        policy = JSON.parse(input.policyJson);
    } catch {
        throw new Error(
            'Invalid JSON: Please provide a valid IAM policy document. ' +
            'Expected format: {"Version": "2012-10-17", "Statement": [...]}'
        );
    }

    if (!policy.Statement || !Array.isArray(policy.Statement)) {
        throw new Error(
            'Invalid IAM policy: Missing "Statement" array. ' +
            'An IAM policy must contain a "Statement" field with an array of permission statements.'
        );
    }

    if (policy.Statement.length === 0) {
        throw new Error(
            'Invalid IAM policy: "Statement" array is empty. ' +
            'Provide at least one permission statement to audit.'
        );
    }

    const findings = analyzePolicy(policy);

    return {
        findings,
        summary: {
            total: findings.length,
            high: findings.filter((f) => f.severity === 'HIGH').length,
            medium: findings.filter((f) => f.severity === 'MEDIUM').length,
            low: findings.filter((f) => f.severity === 'LOW').length,
        },
        auditedAt: new Date().toISOString(),
    };
}
