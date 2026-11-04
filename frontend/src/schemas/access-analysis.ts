import { z } from 'zod';
import { AccessLogRecordSchema } from './access-log';

export const AnalysisItemSchema = z.object({
  name: z.string(),
  count: z.number(),
  lastSeen: z.number(),
  country: z.string(),
  subdivision: z.string(),
  latitude: z.number(),
  longitude: z.number(),
});
export const ApplicationSchema = z.object({ id: z.string(), name: z.string(), color: z.string() });
export const AnalysisPageSchema = z.object({
  items: z.array(AnalysisItemSchema),
  total: z.number(),
  page: z.number(),
  pageSize: z.number(),
  userComments: z.record(z.string(), z.string()),
  catalog: z.array(ApplicationSchema).default([]),
});
export const AnalysisOverviewSchema = z.object({
  status: z.object({
    ready: z.boolean(),
    rebuilding: z.boolean(),
    processedId: z.number(),
    latestId: z.number(),
    locationReady: z.boolean(),
    generation: z.string(),
  }),
  total: z.number(),
  apps: z.array(AnalysisItemSchema),
  domains: z.array(AnalysisItemSchema),
  sources: z.array(AnalysisItemSchema),
  regions: z.array(AnalysisItemSchema),
  users: z.array(AnalysisItemSchema),
  blocked: z.array(AccessLogRecordSchema),
  userComments: z.record(z.string(), z.string()),
  catalog: z.array(ApplicationSchema),
});
export interface AnalysisQuery {
  from?: number;
  to?: number;
  nodeGuid?: string;
  user?: string;
  userSet?: boolean;
  category?: 'direct' | 'blocked' | 'proxy';
  kind?: 'apps' | 'domains' | 'sources' | 'users';
  page?: number;
  pageSize?: number;
}
export type AnalysisItem = z.infer<typeof AnalysisItemSchema>;
export type AnalysisOverview = z.infer<typeof AnalysisOverviewSchema>;
export type Application = z.infer<typeof ApplicationSchema>;
