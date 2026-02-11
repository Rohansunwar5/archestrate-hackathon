export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export interface Finding {
    severity: Severity;
    finding: string;
    recommendation: string;
    affectedStatement?: number;
}

export interface AuditResult {
    findings: Finding[];
    summary: {
        total: number;
        high: number;
        medium: number;
        low: number;
    };
    auditedAt: string;
}

export interface IAMStatement {
    Sid?: string;
    Effect: string;
    Action: string | string[];
    Resource: string | string[];
    Condition?: Record<string, unknown>;
}

export interface IAMPolicy {
    Version: string;
    Statement: IAMStatement[];
}
