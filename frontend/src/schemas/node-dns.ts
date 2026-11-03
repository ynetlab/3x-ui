import { z } from 'zod';

export const NodeDNSTypeSchema = z.enum(['A', 'AAAA']);
export const NodeDNSRecordSchema = z.object({
  id: z.string().regex(/^[a-f0-9]{32}$/),
  name: z.string(),
  type: z.string(),
  content: z.string(),
  ttl: z.number().int(),
  proxied: z.boolean(),
  proxiable: z.boolean(),
  bound: z.boolean(),
  ownerNodeId: z.number().int().optional(),
  missing: z.boolean(),
  changed: z.boolean(),
  lastSyncError: z.string(),
  lastSyncedAt: z.number(),
});

export const NodePublicIPSchema = z.object({
  nodeId: z.number().int(),
  nodeGuid: z.string(),
  ipv4: z.string(),
  ipv6: z.string(),
  ipv4Available: z.boolean(),
  ipv6Available: z.boolean(),
  observedAt: z.number(),
  receivedAt: z.number(),
});

export const NodeDNSRecordsSchema = z.object({
  zoneId: z.string(),
  zoneName: z.string(),
  nodeId: z.number().int(),
  nodeAddress: z.string(),
  records: z.array(NodeDNSRecordSchema),
  publicIp: NodePublicIPSchema,
});

export type NodeDNSRecord = z.infer<typeof NodeDNSRecordSchema>;
export type NodePublicIP = z.infer<typeof NodePublicIPSchema>;
export interface NodeDNSInput {
  name?: string;
  type?: 'A' | 'AAAA';
  content?: string;
  ttl?: number;
  proxied?: boolean;
}
