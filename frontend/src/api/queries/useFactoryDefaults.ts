import { useQuery } from '@tanstack/react-query';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import { FactoryDefaultsSchema, type FactoryDefaults } from '@/schemas/setting';
import { keys } from '@/api/queryKeys';
import { nodeTargetUrl, useNodeTarget } from '@/api/nodeTarget';

async function fetchFactoryDefaults(nodeId?: number): Promise<FactoryDefaults> {
  const msg = await HttpUtil.post(
    nodeTargetUrl('/panel/api/setting/factoryDefaults', nodeId),
    undefined,
    {
      silent: true,
    },
  );
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch factory defaults');
  const validated = parseMsg(msg, FactoryDefaultsSchema, 'setting/factoryDefaults');
  const parsed = FactoryDefaultsSchema.safeParse(validated.obj);
  return parsed.success ? parsed.data : {};
}

export function useFactoryDefaults() {
  const target = useNodeTarget();
  return useQuery({
    queryKey: target.queryKey(keys.settings.factoryDefaults()),
    queryFn: () => fetchFactoryDefaults(target.nodeId),
    staleTime: target.nodeId === undefined ? Infinity : 0,
    gcTime: target.nodeId === undefined ? undefined : 0,
  });
}
