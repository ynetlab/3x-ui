import { afterEach, expect, it, vi } from 'vitest';
import { act, renderHook, screen } from '@testing-library/react';

import FallbacksCard from '@/pages/inbounds/form/FallbacksCard';
import { useInboundFallbacks } from '@/pages/inbounds/form/useInboundFallbacks';
import { DBInbound } from '@/models/dbinbound';
import { HttpUtil } from '@/utils';
import { renderWithProviders } from './test-utils';

afterEach(() => vi.restoreAllMocks());

for (const protocol of ['anytls', 'trojan']) {
  it(`shows supported ${protocol} fallback fields`, () => {
    renderWithProviders(
      <FallbacksCard
        protocol={protocol}
        fallbacks={[
          { rowKey: 'one', childId: null, name: '', alpn: '', path: '', dest: '8080', xver: 0 },
        ]}
        fallbackChildOptions={[]}
        addFallback={() => {}}
        updateFallback={() => {}}
        removeFallback={() => {}}
        moveFallback={() => {}}
        addAllFallbacks={() => {}}
      />,
    );
    expect(screen.getByRole('textbox', { name: 'ALPN' })).toBeTruthy();
    expect(screen.getByRole('textbox', { name: 'Dest' })).toBeTruthy();
    for (const label of ['SNI', 'Path', 'xver']) {
      expect(screen.queryByLabelText(label) !== null).toBe(protocol === 'trojan');
    }
  });
}

it('keeps AnyTLS child defaults plaintext and saves only supported matchers', async () => {
  const child = new DBInbound({
    id: 2,
    protocol: 'vless',
    port: 8080,
    streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/backend' } },
  });
  const tlsChild = new DBInbound({ id: 3, streamSettings: { network: 'tcp', security: 'tls' } });
  const proxyChild = new DBInbound({
    id: 4,
    streamSettings: { network: 'tcp', sockopt: { acceptProxyProtocol: true } },
  });
  const post = vi.spyOn(HttpUtil, 'post').mockResolvedValue({ success: true, obj: null, msg: '' });
  const { result } = renderHook(() =>
    useInboundFallbacks(null, [child, tlsChild, proxyChild], 'anytls'),
  );
  expect(result.current.fallbackChildOptions.map((c) => c.value)).toEqual([2]);
  act(() => result.current.addFallback());
  const key = result.current.fallbacks[0].rowKey;
  act(() => result.current.updateFallback(key, { childId: 2 }));
  expect(result.current.fallbacks[0]).toMatchObject({ name: '', path: '', xver: 0, alpn: '' });
  act(() =>
    result.current.updateFallback(key, { alpn: 'h2', name: 'stale', path: '/stale', xver: 2 }),
  );
  await act(async () => {
    expect(await result.current.saveFallbacks(1)).toBe(true);
  });
  expect(post).toHaveBeenCalledWith(
    '/panel/api/inbounds/1/fallbacks',
    {
      fallbacks: [{ childId: 2, name: '', alpn: 'h2', path: '', dest: '', xver: 0, sortOrder: 0 }],
    },
    expect.anything(),
  );
});

it('loads AnyTLS default and ALPN rows through the shared fallback API', async () => {
  vi.spyOn(HttpUtil, 'get').mockResolvedValue({
    success: true,
    msg: '',
    obj: [
      { childId: 0, dest: '8080', alpn: '' },
      { childId: 0, dest: '8081', alpn: 'h2' },
    ],
  });
  const { result } = renderHook(() => useInboundFallbacks(null, [], 'anytls'));
  await act(async () => {
    await result.current.loadFallbacks(1);
  });
  expect(result.current.fallbacks).toMatchObject([
    { childId: null, dest: '8080', alpn: '' },
    { childId: null, dest: '8081', alpn: 'h2' },
  ]);
});
