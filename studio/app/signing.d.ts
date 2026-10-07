export function canonicalStatement(value: unknown): string;
export function signApproval(bytes: Uint8Array, statement: Record<string, unknown>, approver: {approverId: string; keyId: string; publicKeyHex: string}): Promise<{approverId: string; keyId: string; signature: string}>;
