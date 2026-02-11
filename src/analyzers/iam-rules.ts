import { IAMPolicy, Finding } from '../types/index.js';

/**
 * Analyzes an IAM policy document against a set of security rules.
 * Returns an array of findings with severity, description, and remediation guidance.
 */
export function analyzePolicy(policy: IAMPolicy): Finding[] {
    const findings: Finding[] = [];

    // Check policy version
    if (policy.Version !== '2012-10-17') {
        findings.push({
            severity: 'LOW',
            finding: 'Policy uses outdated version or missing Version field',
            recommendation: 'Set Version to "2012-10-17" for full policy feature support',
        });
    }

    policy.Statement.forEach((stmt, index) => {
        if (stmt.Effect !== 'Allow') return;

        const actions = normalizeArray(stmt.Action);
        const resources = normalizeArray(stmt.Resource);
        const stmtNum = index + 1;

        // Rule 1: Full admin detection (most critical — subsumes wildcard checks)
        if (actions.includes('*') && resources.includes('*')) {
            findings.push({
                severity: 'HIGH',
                finding: `Statement ${stmtNum}: Full administrator access — Action:"*" on Resource:"*"`,
                recommendation:
                    'Never grant full admin. Use specific service actions and resource ARNs following least-privilege principles',
                affectedStatement: stmtNum,
            });
            return; // This subsumes Rules 2 & 3
        }

        // Rule 2: Wildcard actions
        if (actions.includes('*')) {
            findings.push({
                severity: 'HIGH',
                finding: `Statement ${stmtNum}: Grants ALL actions (Action: "*")`,
                recommendation:
                    'Replace with specific actions like "s3:GetObject", "ec2:DescribeInstances"',
                affectedStatement: stmtNum,
            });
        }

        // Rule 3: Wildcard resources
        if (resources.includes('*')) {
            findings.push({
                severity: 'HIGH',
                finding: `Statement ${stmtNum}: Applies to ALL resources (Resource: "*")`,
                recommendation: 'Restrict to specific resource ARNs',
                affectedStatement: stmtNum,
            });
        }

        // Rule 4: iam:PassRole without conditions — privilege escalation vector
        if (
            actions.some((a) => matchAction(a, 'iam:PassRole')) &&
            !stmt.Condition
        ) {
            findings.push({
                severity: 'HIGH',
                finding: `Statement ${stmtNum}: iam:PassRole without conditions enables privilege escalation`,
                recommendation:
                    'Add Condition: {"StringEquals": {"iam:PassedToService": "specific-service.amazonaws.com"}}',
                affectedStatement: stmtNum,
            });
        }

        // Rule 5: sts:AssumeRole on wildcard — role chaining attack
        if (
            actions.some((a) => matchAction(a, 'sts:AssumeRole')) &&
            resources.includes('*')
        ) {
            findings.push({
                severity: 'HIGH',
                finding: `Statement ${stmtNum}: sts:AssumeRole on all resources enables role chaining attacks`,
                recommendation:
                    'Restrict to specific role ARNs: "arn:aws:iam::ACCOUNT:role/SPECIFIC-ROLE"',
                affectedStatement: stmtNum,
            });
        }

        // Rule 6: Broad data service access with wildcard resources
        const dataPatterns = ['s3:*', 'dynamodb:*', 'rds:*'];
        const hasDataWildcard = actions.some((a) =>
            dataPatterns.some((p) => matchAction(a, p))
        );
        if (hasDataWildcard && resources.includes('*')) {
            findings.push({
                severity: 'MEDIUM',
                finding: `Statement ${stmtNum}: Broad data service access with wildcard resources`,
                recommendation: 'Limit to specific buckets, tables, or DB instances',
                affectedStatement: stmtNum,
            });
        }

        // Rule 7: Sensitive service access (KMS, Secrets Manager, CloudTrail)
        const sensitiveServices = ['kms:', 'secretsmanager:', 'cloudtrail:'];
        const hasSensitive = actions.some((a) =>
            sensitiveServices.some((s) => a.toLowerCase().includes(s))
        );
        if (hasSensitive) {
            findings.push({
                severity: 'MEDIUM',
                finding: `Statement ${stmtNum}: Access to sensitive services (KMS/Secrets Manager/CloudTrail)`,
                recommendation:
                    'Ensure this access is justified and restrict to specific resources with conditions',
                affectedStatement: stmtNum,
            });
        }

        // Rule 8: IAM write actions without MFA condition
        const iamWriteActions = [
            'iam:CreateUser',
            'iam:DeleteUser',
            'iam:CreateRole',
            'iam:DeleteRole',
            'iam:AttachUserPolicy',
            'iam:AttachRolePolicy',
            'iam:PutUserPolicy',
            'iam:PutRolePolicy',
        ];
        const hasIamWrite = actions.some((a) =>
            iamWriteActions.some((w) => matchAction(a, w))
        );
        if (hasIamWrite && !stmt.Condition) {
            findings.push({
                severity: 'MEDIUM',
                finding: `Statement ${stmtNum}: IAM write actions without MFA or condition constraints`,
                recommendation:
                    'Add Condition: {"Bool": {"aws:MultiFactorAuthPresent": "true"}} for IAM modifications',
                affectedStatement: stmtNum,
            });
        }

        // Rule 9: Network/security group manipulation
        const networkActions = [
            'ec2:AuthorizeSecurityGroupIngress',
            'ec2:AuthorizeSecurityGroupEgress',
            'ec2:RevokeSecurityGroupIngress',
            'ec2:RevokeSecurityGroupEgress',
            'ec2:CreateSecurityGroup',
            'ec2:DeleteSecurityGroup',
        ];
        const hasNetworkActions = actions.some((a) =>
            networkActions.some((n) => matchAction(a, n))
        );
        if (hasNetworkActions && resources.includes('*')) {
            findings.push({
                severity: 'MEDIUM',
                finding: `Statement ${stmtNum}: Security group modification on all resources`,
                recommendation:
                    'Restrict to specific VPCs or security groups to prevent unauthorized network changes',
                affectedStatement: stmtNum,
            });
        }

        // Rule 10: Lambda invoke/create without resource restriction
        const lambdaActions = [
            'lambda:InvokeFunction',
            'lambda:CreateFunction',
            'lambda:UpdateFunctionCode',
        ];
        const hasLambdaActions = actions.some((a) =>
            lambdaActions.some((l) => matchAction(a, l))
        );
        if (hasLambdaActions && resources.includes('*')) {
            findings.push({
                severity: 'MEDIUM',
                finding: `Statement ${stmtNum}: Lambda function access on all resources`,
                recommendation:
                    'Restrict to specific function ARNs to prevent unauthorized code execution',
                affectedStatement: stmtNum,
            });
        }
    });

    return findings;
}

/**
 * Normalizes a string or string array into a consistent string array.
 */
function normalizeArray(value: string | string[]): string[] {
    return Array.isArray(value) ? value : [value];
}

/**
 * Case-insensitive action matching.
 * Handles exact matches and wildcard service patterns (e.g. "s3:*")
 */
function matchAction(action: string, pattern: string): boolean {
    const a = action.toLowerCase();
    const p = pattern.toLowerCase();

    if (a === p) return true;

    // Handle wildcard patterns like "s3:*" matching "s3:GetObject"
    if (p.endsWith(':*')) {
        const prefix = p.slice(0, -1); // "s3:"
        return a.startsWith(prefix);
    }

    return false;
}
