import { z } from 'zod';

import { TrojanClientSchema } from './trojan';

export const AnyTLSClientSchema = TrojanClientSchema;
export type AnyTLSClient = z.infer<typeof AnyTLSClientSchema>;

export const AnyTLSInboundSettingsSchema = z.object({
  clients: z.array(AnyTLSClientSchema).default([]),
  paddingScheme: z.array(z.string()).default([]),
});
export type AnyTLSInboundSettings = z.infer<typeof AnyTLSInboundSettingsSchema>;
