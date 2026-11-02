import { useQuery } from '@tanstack/react-query';
import { z } from 'zod';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import { keys } from '@/api/queryKeys';
import { nodeTargetUrl, useNodeTarget } from '@/api/nodeTarget';
import { ClientRecordSchema, type ClientRecord } from '@/schemas/client';

const ClientRecordListSchema = z
  .array(ClientRecordSchema)
  .nullable()
  .transform((value) => value ?? []);

async function fetchClients(nodeId?: number): Promise<ClientRecord[]> {
  const msg = await HttpUtil.get(nodeTargetUrl('/panel/api/clients/list', nodeId), undefined, {
    silent: true,
  });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to load clients');
  const validated = parseMsg(msg, ClientRecordListSchema, 'clients/list');
  return validated.obj ?? [];
}

export function useClientOptions(enabled = true) {
  const target = useNodeTarget();
  return useQuery({
    queryKey: target.queryKey(keys.clients.all()),
    queryFn: () => fetchClients(target.nodeId),
    enabled,
    staleTime: 30_000,
    select: (clients) =>
      clients
        .map((client) => client.email.trim())
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b)),
  });
}
