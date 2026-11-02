import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import { Status } from '@/models/status';
import { StatusSchema } from '@/schemas/status';
import { keys } from '@/api/queryKeys';
import { nodeTargetUrl, useNodeTarget } from '@/api/nodeTarget';

const POLL_INTERVAL_MS = 2000;

async function fetchStatus(nodeId?: number): Promise<Status> {
  const msg = await HttpUtil.get(
    nodeTargetUrl('/panel/api/server/status', nodeId),
    undefined,
    nodeId === undefined ? { silent: true } : { silent: true, timeout: 15000 },
  );
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch status');
  if (
    nodeId !== undefined &&
    (!msg.obj || typeof msg.obj !== 'object' || !('mem' in msg.obj) || !('xray' in msg.obj))
  ) {
    throw new Error('Malformed node status response');
  }
  const validated = parseMsg(msg, StatusSchema, 'server/status');
  return new Status(validated.obj);
}

export function useStatusQuery(options: { enabled?: boolean } = {}) {
  const target = useNodeTarget();
  const query = useQuery({
    queryKey: target.queryKey(keys.server.status()),
    queryFn: () => fetchStatus(target.nodeId),
    enabled: options.enabled,
    refetchInterval: target.nodeId === undefined ? POLL_INTERVAL_MS : 5000,
    refetchIntervalInBackground: false,
    staleTime: 0,
    ...(target.nodeId === undefined ? {} : { gcTime: 0, retry: false }),
  });

  const status = useMemo(() => query.data ?? new Status(), [query.data]);
  const refresh = async () => {
    await query.refetch();
  };

  return {
    status,
    fetched: query.data !== undefined || query.isError,
    fetchError: query.error ? (query.error as Error).message : '',
    refresh,
  };
}
