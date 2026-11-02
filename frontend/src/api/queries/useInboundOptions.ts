import { useQuery } from '@tanstack/react-query';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import { keys } from '@/api/queryKeys';
import { nodeTargetUrl, useNodeTarget } from '@/api/nodeTarget';
import { InboundOptionsSchema, type InboundOption } from '@/schemas/client';

async function fetchInboundOptions(nodeId?: number): Promise<InboundOption[]> {
  const msg = await HttpUtil.get(nodeTargetUrl('/panel/api/inbounds/options', nodeId), undefined, {
    silent: true,
  });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch inbound options');
  const validated = parseMsg(msg, InboundOptionsSchema, 'inbounds/options');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

export function useInboundOptions() {
  const target = useNodeTarget();
  return useQuery({
    queryKey: target.queryKey(keys.inbounds.options()),
    queryFn: () => fetchInboundOptions(target.nodeId),
    staleTime: target.nodeId === undefined ? Infinity : 0,
  });
}
