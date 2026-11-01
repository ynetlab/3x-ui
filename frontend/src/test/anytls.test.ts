import { describe, expect, it } from 'vitest';

import { InboundSettingsSchema } from '@/schemas/protocols/inbound';
import { AnyTLSOutboundSettingsSchema } from '@/schemas/protocols/outbound';
import { createDefaultInboundSettings } from '@/lib/xray/inbound-defaults';
import { createDefaultOutboundSettings } from '@/lib/xray/outbound-defaults';
import { rawOutboundToFormValues, formValuesToWirePayload } from '@/lib/xray/outbound-form-adapter';
import {
  rawInboundToFormValues,
  formValuesToWirePayload as inboundToWire,
} from '@/lib/xray/inbound-form-adapter';
import { canEnableTls, canEnableReality, canEnableTlsFlow } from '@/lib/xray/protocol-capabilities';
import { isInboundMultiUser } from '@/pages/inbounds/list/helpers';

describe('AnyTLS configuration', () => {
  it('preserves padding and client credentials through inbound editing', () => {
    const settings = {
      clients: [{ email: 'user@example.com', id: '5783a3e7-e373-0000-8642-c83782b807c5' }],
      paddingScheme: ['stop=8', '0=30-30'],
    };
    const values = rawInboundToFormValues({ protocol: 'anytls', port: 443, settings });
    expect(JSON.parse(inboundToWire(values).settings)).toMatchObject(settings);
    expect(
      InboundSettingsSchema.parse({
        protocol: 'anytls',
        settings: createDefaultInboundSettings('anytls'),
      }).protocol,
    ).toBe('anytls');
    expect(isInboundMultiUser({ protocol: 'anytls' })).toBe(true);
  });
  it('preserves flat outbound settings and session options without adding Mux', () => {
    const settings = {
      address: 'example.com',
      port: 443,
      password: '5783a3e7-e373-03e9-8642-c83782b807c5',
      email: 'user@example.com',
      level: 2,
      idleSessionCheckInterval: 12,
      idleSessionTimeout: 45,
      minIdleSession: 3,
    };
    const values = rawOutboundToFormValues({
      protocol: 'anytls',
      tag: 'anytls-out',
      settings,
      streamSettings: {
        network: 'tcp',
        security: 'reality',
        realitySettings: {
          serverName: 'example.com',
          publicKey: 'key',
          fingerprint: 'chrome',
          shortId: '',
        },
      },
    });
    const wire = formValuesToWirePayload(values);
    expect(wire.settings).toEqual(settings);
    expect(wire.streamSettings).toMatchObject({ network: 'tcp', security: 'reality' });
    expect(wire.mux).toBeUndefined();
    expect(createDefaultOutboundSettings('anytls')).toMatchObject({
      idleSessionCheckInterval: 30,
      idleSessionTimeout: 60,
      minIdleSession: 0,
    });
    expect(
      AnyTLSOutboundSettingsSchema.safeParse({ ...settings, minIdleSession: -1 }).success,
    ).toBe(false);
  });
  it('offers TLS and REALITY without Vision flow', () => {
    const values = { protocol: 'anytls', streamSettings: { network: 'tcp', security: 'tls' } };
    expect(canEnableTls(values)).toBe(true);
    expect(canEnableReality(values)).toBe(true);
    expect(canEnableTlsFlow(values)).toBe(false);
  });
  it('preserves default and ALPN fallbacks through editing, and leaves them disabled by default', () => {
    const fallbacks = [
      { alpn: '', dest: 8080 },
      { alpn: 'h2', dest: '[::1]:8081', type: 'tcp' },
    ];
    const values = rawInboundToFormValues({
      protocol: 'anytls',
      port: 443,
      settings: { clients: [], paddingScheme: ['stop=8'], fallbacks },
    });
    expect(JSON.parse(inboundToWire(values).settings).fallbacks).toEqual(fallbacks);
    const defaults = createDefaultInboundSettings('anytls');
    expect(defaults).toMatchObject({ fallbacks: [] });
    expect(
      JSON.parse(
        inboundToWire(rawInboundToFormValues({ protocol: 'anytls', settings: defaults })).settings,
      ),
    ).not.toHaveProperty('fallbacks');
  });
});
