import { z } from 'zod';

import { TrojanClientSchema } from './trojan';

export const AnyTLSClientSchema = TrojanClientSchema;
export type AnyTLSClient = z.infer<typeof AnyTLSClientSchema>;

export const AnyTLSFallbackSchema = z.object({
  alpn: z.string().default(''),
  dest: z.union([z.string(), z.number()]).default(''),
  type: z.enum(['tcp', 'unix']).optional(),
});

export const AnyTLSInboundSettingsSchema = z.object({
  clients: z.array(AnyTLSClientSchema).default([]),
  paddingScheme: z.array(z.string()).default([]),
  fallbacks: z.array(AnyTLSFallbackSchema).default([]),
});
export type AnyTLSInboundSettings = z.infer<typeof AnyTLSInboundSettingsSchema>;
