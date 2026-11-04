import { useInfiniteQuery, useQuery } from '@tanstack/react-query';

import { HttpUtil } from '@/utils';
import { ClientPageResponseSchema } from '@/schemas/client';
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

// Reuse the existing slim, paginated user list; no full credentials are loaded.
export function useAccessLogUsers(search: string, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: ['access-logs', 'users', search],
    initialPageParam: 1,
    enabled,
    queryFn: async ({ pageParam, signal }) => {
      const msg = await HttpUtil.get(
        '/panel/api/clients/list/paged',
        {
          page: pageParam,
          pageSize: 50,
          search: search || undefined,
          sort: 'email',
          order: 'ascend',
        },
        { silent: true, signal },
      );
      if (!msg.success) throw new Error(msg.msg);
      return ClientPageResponseSchema.parse(msg.obj);
    },
    getNextPageParam: (last) =>
      last.page * last.pageSize < last.filtered ? last.page + 1 : undefined,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
}
