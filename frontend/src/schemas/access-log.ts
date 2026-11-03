import { z } from 'zod';

export const AccessLogRecordSchema = z.object({
  id: z.number(),
  nodeGuid: z.string(),
  occurredAt: z.number(),
  receivedAt: z.number(),
  source: z.string(),
  target: z.string(),
  email: z.string(),
  inbound: z.string(),
  outbound: z.string(),
  category: z.enum(['direct', 'blocked', 'proxy']),
});

export const AccessLogPageSchema = z.object({
  items: z.array(AccessLogRecordSchema),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  pageSize: z.number().int().positive(),
});

export const AccessLogNodesSchema = z.array(
  z.object({ guid: z.string(), name: z.string(), local: z.boolean() }),
);

export type AccessLogRecord = z.infer<typeof AccessLogRecordSchema>;
export interface AccessLogQuery {
  page: number;
  pageSize: number;
  nodeGuid?: string;
  from?: number;
  to?: number;
  user?: string;
  source?: string;
  target?: string;
  inbound?: string;
  outbound?: string;
  category?: 'direct' | 'blocked' | 'proxy';
}
