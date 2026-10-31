import { z } from 'zod';

// Panel clients use the shared id; the backend projects it to core auth.
// xray-core builds version 2 only — it answers anything else
// with "version != 2" and rejects the entire config, so a legacy row is
// coerced rather than carried through.
export const HysteriaClientSchema = z.object({
  id: z.string().min(1),
  email: z.string().min(1),
  limitIp: z.number().int().min(0).default(0),
  totalGB: z.number().int().min(0).default(0),
  expiryTime: z.number().int().default(0),
  enable: z.boolean().default(true),
  tgId: z
    .union([z.number(), z.string()])
    .transform((v) => Number(v) || 0)
    .default(0),
  subId: z.string().default(''),
  comment: z.string().default(''),
  reset: z.number().int().min(0).default(0),
  created_at: z.number().int().optional(),
  updated_at: z.number().int().optional(),
});
export type HysteriaClient = z.infer<typeof HysteriaClientSchema>;

export const HysteriaInboundSettingsSchema = z.object({
  version: z.preprocess(() => 2, z.literal(2)).default(2),
  clients: z.array(HysteriaClientSchema).default([]),
});
export type HysteriaInboundSettings = z.infer<typeof HysteriaInboundSettingsSchema>;
