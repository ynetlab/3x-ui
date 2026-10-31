import { z } from 'zod';

import { PortSchema } from '@/schemas/primitives';

export const AnyTLSOutboundSettingsSchema = z.object({
  address: z.string().min(1),
  port: PortSchema.default(443),
  password: z.string().min(1),
  email: z.string().default(''),
  level: z.number().int().min(0).max(4294967295).default(0),
  idleSessionCheckInterval: z.number().int().min(0).max(4294967295).default(30),
  idleSessionTimeout: z.number().int().min(0).max(4294967295).default(60),
  minIdleSession: z.number().int().min(0).max(4294967295).default(0),
});
export type AnyTLSOutboundSettings = z.infer<typeof AnyTLSOutboundSettingsSchema>;
