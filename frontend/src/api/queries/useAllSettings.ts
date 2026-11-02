import { useCallback, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { HttpUtil, Msg } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import { AllSetting } from '@/models/setting';
import {
  AllSettingResponseSchema,
  AllSettingSchema,
  type AllSettingInput,
} from '@/schemas/setting';
import { keys } from '@/api/queryKeys';
import { useServerDraft } from '@/hooks/useServerDraft';
import { nodeTargetUrl, useNodeTarget } from '@/api/nodeTarget';

type SettingSavePayload = Partial<AllSetting> & Record<string, unknown>;
type SettingSaveResult = {
  msg: Msg<unknown>;
  saved?: AllSetting;
};

async function fetchAllSetting(nodeId?: number): Promise<AllSettingInput | null> {
  const msg = await HttpUtil.post(nodeTargetUrl('/panel/api/setting/all', nodeId), undefined, {
    silent: true,
  });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch settings');
  if (nodeId !== undefined && (!msg.obj || typeof msg.obj !== 'object' || Array.isArray(msg.obj))) {
    throw new Error('Malformed node settings response');
  }
  const validated = parseMsg(msg, AllSettingResponseSchema, 'setting/all');
  return nodeId === undefined ? validated.obj : (msg.obj as AllSettingInput);
}

export function useAllSettings() {
  const target = useNodeTarget();
  const queryClient = useQueryClient();
  const [extraSpinning, setExtraSpinning] = useState(false);
  const editedFields = useRef(new Set<string>());

  const query = useQuery({
    queryKey: target.queryKey(keys.settings.all()),
    queryFn: () => fetchAllSetting(target.nodeId),
    staleTime: target.nodeId === undefined ? Infinity : 0,
    gcTime: target.nodeId === undefined ? undefined : 0,
  });

  const server = useMemo(() => new AllSetting(query.data), [query.data]);
  const { draft, setDraft, isDirty, markSaved } = useServerDraft(
    query.data === undefined ? undefined : server,
    (setting) => new AllSetting(setting),
    (left, right) => left.equals(right),
  );
  const allSetting = draft ?? server;

  const updateSetting = useCallback(
    (patch: Partial<AllSetting>) => {
      for (const key of Object.keys(patch)) editedFields.current.add(key);
      setDraft((prev) => {
        const next = new AllSetting(prev ?? server);
        Object.assign(next, patch);
        return next;
      });
    },
    [server, setDraft],
  );

  const saveMut = useMutation({
    mutationFn: async ({
      payload,
      saved,
    }: {
      payload: SettingSavePayload;
      saved?: AllSetting;
    }): Promise<SettingSaveResult> => {
      // The endpoint saves all settings. Preserve the node's raw response and
      // replace only edited fields, without applying local defaults elsewhere.
      const next: SettingSavePayload =
        target.nodeId === undefined ? { ...payload } : { ...query.data };
      if (target.nodeId !== undefined) {
        for (const [key, value] of Object.entries(payload)) {
          if (editedFields.current.has(key) && !Object.is(value, server[key as keyof AllSetting]))
            next[key] = value;
        }
      }
      const body = AllSettingSchema.partial().safeParse(next);
      if (!body.success) {
        console.warn('[zod] setting/update body failed validation', body.error.issues);
      }
      const msg = await HttpUtil.post(
        target.url('/panel/api/setting/update'),
        target.nodeId === undefined && body.success ? { ...next, ...body.data } : next,
      );
      return { msg, saved };
    },
    onSuccess: ({ msg, saved }) => {
      if (!msg?.success) return;
      editedFields.current.clear();
      if (saved) markSaved(saved);
      queryClient.invalidateQueries({ queryKey: target.queryKey(keys.settings.all()) });
      queryClient.invalidateQueries({ queryKey: target.queryKey(keys.settings.defaults()) });
    },
  });

  const saveAll = useCallback(async () => {
    const saved = new AllSetting(allSetting);
    return (await saveMut.mutateAsync({ payload: { ...saved }, saved })).msg;
  }, [allSetting, saveMut]);
  const savePayload = useCallback(
    async (payload: SettingSavePayload) => {
      const saved = new AllSetting(allSetting);
      Object.assign(saved, payload);
      return (await saveMut.mutateAsync({ payload, saved })).msg;
    },
    [allSetting, saveMut],
  );
  const saveDisabled = !isDirty;

  return {
    allSetting,
    updateSetting,
    fetched: query.data !== undefined || query.isError,
    fetchError: query.error ? (query.error as Error).message : '',
    refetch: query.refetch,
    spinning: extraSpinning || saveMut.isPending,
    setSpinning: setExtraSpinning,
    saveDisabled,
    saveAll,
    savePayload,
  };
}
