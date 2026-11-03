import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { NodeRecord } from '@/schemas/node';
import {
  NodeDNSRecordSchema,
  NodeDNSRecordsSchema,
  NodePublicIPSchema,
  type NodeDNSInput,
} from '@/schemas/node-dns';
import { HttpUtil } from '@/utils';
import { httpRequest, HttpError } from '@/api/http-init';

export class NodeDNSRequestError extends Error {
  constructor(
    code: string,
    readonly recordId?: string,
  ) {
    super(code);
  }
}

const rootKey = (node: NodeRecord) =>
  ['node-dns', node.id, node.guid ?? '', node.address ?? ''] as const;
const urlFor = (id: number) => `/panel/api/cloudflare/nodes/${id}`;
export type NodeDNSOperation =
  | { action: 'create'; input: NodeDNSInput }
  | { action: 'update'; recordId: string; input: NodeDNSInput }
  | { action: 'bind'; recordId: string; input: { content: string } }
  | { action: 'proxied'; recordId: string; input: { proxied: boolean } }
  | { action: 'delete'; recordId: string };

export function useNodeDNS(node: NodeRecord) {
  const queryClient = useQueryClient();
  const key = rootKey(node);
  const enabled = node.id > 0 && !node.transitive;
  const records = useQuery({
    queryKey: [...key, 'records'],
    enabled,
    queryFn: async ({ signal }) => {
      const msg = await HttpUtil.get(`${urlFor(node.id)}/records`, undefined, {
        signal,
        silent: true,
        timeout: 35_000,
      });
      if (!msg.success) throw new Error(msg.msg);
      const parsed = NodeDNSRecordsSchema.safeParse(msg.obj);
      if (!parsed.success || parsed.data.nodeId !== node.id)
        throw new Error('cloudflare_invalid_response');
      if (node.guid && parsed.data.publicIp.nodeGuid !== node.guid)
        throw new Error('cloudflare_node_changed');
      return parsed.data;
    },
    retry: false,
    staleTime: 0,
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const publicIP = useQuery({
    queryKey: [...key, 'ip'],
    enabled,
    queryFn: async ({ signal }) => {
      const msg = await HttpUtil.get(`${urlFor(node.id)}/ip`, undefined, { signal, silent: true });
      if (!msg.success) throw new Error(msg.msg);
      const parsed = NodePublicIPSchema.safeParse(msg.obj);
      if (!parsed.success || parsed.data.nodeId !== node.id)
        throw new Error('cloudflare_invalid_response');
      if (node.guid && parsed.data.nodeGuid !== node.guid)
        throw new Error('cloudflare_node_changed');
      return parsed.data;
    },
    staleTime: 0,
    gcTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const mutation = useMutation({
    mutationFn: async (operation: NodeDNSOperation) => {
      await queryClient.cancelQueries({ queryKey: [...key, 'records'] });
      const path =
        operation.action === 'create'
          ? ''
          : `/${encodeURIComponent(operation.recordId)}/${operation.action}`;
      let payload: unknown;
      try {
        const response = await httpRequest(
          'POST',
          `${urlFor(node.id)}/records${path}`,
          'input' in operation ? operation.input : {},
          { headers: { 'Content-Type': 'application/json' }, timeout: 35_000 },
        );
        payload = response.data;
      } catch (error) {
        if (!(error instanceof HttpError)) throw new NodeDNSRequestError('requestFailed');
        payload = error.response.data;
      }
      const envelope = payload as { success?: unknown; msg?: unknown; obj?: unknown } | null;
      if (!envelope || envelope.success !== true) {
        const obj = envelope?.obj as { recordId?: unknown } | null;
        const recordId =
          typeof obj?.recordId === 'string' && /^[a-f0-9]{32}$/.test(obj.recordId)
            ? obj.recordId
            : undefined;
        throw new NodeDNSRequestError(
          typeof envelope?.msg === 'string' ? envelope.msg : 'requestFailed',
          recordId,
        );
      }
      if (operation.action === 'delete') return null;
      const parsed = NodeDNSRecordSchema.safeParse(envelope.obj);
      if (!parsed.success) throw new Error('cloudflare_invalid_response');
      return parsed.data;
    },
    retry: false,
    onSettled: () => queryClient.invalidateQueries({ queryKey: [...key, 'records'] }),
  });
  return {
    records,
    publicIP,
    mutation,
    refresh: () => {
      void records.refetch();
      void publicIP.refetch();
    },
  };
}
