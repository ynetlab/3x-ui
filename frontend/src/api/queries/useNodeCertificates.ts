import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { httpRequest, HttpError } from '@/api/http-init';
import type { NodeRecord } from '@/schemas/node';

export const acmeConfigSchema = z.object({ email: z.string(), acceptTos: z.boolean() });
export type ACMEConfig = z.infer<typeof acmeConfigSchema>;
const certificateSchema = z.object({
  id: z.string(),
  nodeId: z.number(),
  status: z.string(),
  domains: z.array(z.string()),
  primaryDomain: z.string(),
  fingerprint: z.string(),
  expiresAt: z.number(),
  activeExpiresAt: z.number(),
  activeFingerprint: z.string(),
  nextAttemptAt: z.number(),
  lastError: z.string(),
  updatedAt: z.number(),
});

async function request<T>(
  method: 'GET' | 'POST',
  path: string,
  schema: z.ZodType<T>,
  input?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  let data: unknown;
  try {
    const response = await httpRequest(method, `/panel/api/certificates${path}`, input, {
      signal,
      timeout: 35_000,
      headers: { 'Content-Type': 'application/json' },
    });
    data = response.data;
  } catch (error) {
    if (!(error instanceof HttpError)) throw new Error('certificate_request_failed');
    data = error.response.data;
  }
  const envelope = data as { success?: unknown; msg?: unknown; obj?: unknown } | null;
  if (envelope?.success !== true)
    throw new Error(
      typeof envelope?.msg === 'string' ? envelope.msg : 'certificate_request_failed',
    );
  const parsed = schema.safeParse(envelope.obj);
  if (!parsed.success) throw new Error('certificate_invalid_response');
  return parsed.data;
}

export function useACMEConfig() {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ['acme-settings'],
    queryFn: ({ signal }) => request('GET', '/settings', acmeConfigSchema, undefined, signal),
    retry: false,
  });
  const save = useMutation({
    mutationFn: (config: ACMEConfig) => request('POST', '/settings', acmeConfigSchema, config),
    retry: false,
    onSuccess: (config) => client.setQueryData(['acme-settings'], config),
  });
  return { query, save };
}

export function useNodeCertificates(node: NodeRecord) {
  const client = useQueryClient();
  const key = ['node-certificates', node.id, node.guid ?? '', node.address] as const;
  const enabled = node.id > 0 && !node.transitive && !!node.controlConnection;
  const query = useQuery({
    queryKey: key,
    enabled,
    retry: false,
    gcTime: 0,
    queryFn: ({ signal }) =>
      request('GET', `/nodes/${node.id}`, certificateSchema, undefined, signal),
    refetchInterval: (query) =>
      ['queued', 'issuing', 'deploying', 'retrying', 'staged'].includes(
        query.state.data?.status ?? '',
      )
        ? 2_000
        : false,
  });
  const mutation = useMutation({
    mutationFn: (
      operation:
        | { action: 'request'; recordIds: string[]; primaryDomain: string }
        | { action: 'retry' },
    ) =>
      operation.action === 'retry'
        ? request('POST', `/nodes/${node.id}/retry`, certificateSchema, {})
        : request('POST', `/nodes/${node.id}`, certificateSchema, {
            recordIds: operation.recordIds,
            primaryDomain: operation.primaryDomain,
          }),
    retry: false,
    onSuccess: () => client.invalidateQueries({ queryKey: key }),
  });
  return { query, mutation, enabled };
}
