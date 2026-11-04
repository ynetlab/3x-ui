import { useQuery } from '@tanstack/react-query';
import { HttpUtil } from '@/utils';
import {
  AnalysisOverviewSchema,
  AnalysisPageSchema,
  type AnalysisQuery,
  type AnalysisOverview,
} from '@/schemas/access-analysis';

export function useAccessOverview(params: AnalysisQuery, enabled = true) {
  return useQuery<AnalysisOverview>({
    queryKey: ['access-analysis', 'overview', params],
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && (!status.ready || status.rebuilding || status.processedId < status.latestId)
        ? 2000
        : status && !status.locationReady
          ? 10000
          : false;
    },
    enabled,
    queryFn: async ({ signal }) => {
      const msg = await HttpUtil.get('/panel/api/access-analysis/overview', params, {
        silent: true,
        signal,
      });
      if (!msg.success) throw new Error(msg.msg);
      return AnalysisOverviewSchema.parse(msg.obj);
    },
    refetchOnWindowFocus: false,
  });
}
export function useAccessStats(params: AnalysisQuery, enabled = true) {
  return useQuery({
    queryKey: ['access-analysis', 'stats', params],
    enabled,
    queryFn: async ({ signal }) => {
      const msg = await HttpUtil.get('/panel/api/access-analysis/stats', params, {
        silent: true,
        signal,
      });
      if (!msg.success) throw new Error(msg.msg);
      return AnalysisPageSchema.parse(msg.obj);
    },
    refetchOnWindowFocus: false,
  });
}
