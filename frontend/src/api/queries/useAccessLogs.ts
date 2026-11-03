import { useQuery } from '@tanstack/react-query';

import { HttpUtil } from '@/utils';
import {
  AccessLogNodesSchema,
  AccessLogPageSchema,
  type AccessLogQuery,
} from '@/schemas/access-log';

export function useAccessLogs(params: AccessLogQuery) {
  return useQuery({
    queryKey: ['access-logs', 'page', params],
    queryFn: async ({ signal }) => {
      const msg = await HttpUtil.get('/panel/api/access-logs', params, { silent: true, signal });
      if (!msg.success) throw new Error(msg.msg);
      return AccessLogPageSchema.parse(msg.obj);
    },
    refetchOnWindowFocus: false,
    staleTime: 0,
    gcTime: 60_000,
  });
}

export function useAccessLogNodes() {
  return useQuery({
    queryKey: ['access-logs', 'nodes'],
    queryFn: async ({ signal }) => {
      const msg = await HttpUtil.get('/panel/api/access-logs/nodes', undefined, {
        silent: true,
        signal,
      });
      if (!msg.success) throw new Error(msg.msg);
      return AccessLogNodesSchema.parse(msg.obj);
    },
    refetchOnWindowFocus: false,
  });
}
