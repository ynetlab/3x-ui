import { useState } from 'react';
import { Alert, Modal, Button, Descriptions, Space, Typography } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import { HttpUtil } from '@/utils';
import { SettingListItem } from '@/components/ui';

const statusSchema = z.object({
  caFingerprint: z.string(),
  caExpiresAt: z.number(),
  identityExpiresAt: z.number(),
  lastError: z.string().optional(),
  status: z.string().optional(),
  total: z.number(),
  migrated: z.number(),
  recovery: z.number(),
  deadline: z.number().optional(),
});
type Status = z.infer<typeof statusSchema>;
async function request(rotate = false): Promise<Status> {
  const result = rotate
    ? await HttpUtil.post(
        '/panel/api/control-pki/rotate-ca',
        { confirm: true },
        { silent: true, headers: { 'Content-Type': 'application/json' } },
      )
    : await HttpUtil.get('/panel/api/control-pki/status', undefined, { silent: true });
  if (!result.success) throw new Error(result.msg || 'control_pki_request_failed');
  return statusSchema.parse(result.obj);
}

export default function ControlCertificates() {
  const { t } = useTranslation();
  const [modal, modalContextHolder] = Modal.useModal();
  const client = useQueryClient();
  const [started, setStarted] = useState(false);
  const query = useQuery({
    queryKey: ['control-pki'],
    queryFn: () => request(),
    retry: false,
    refetchInterval: (query) => (query.state.data?.status === 'migrating' ? 2000 : false),
  });
  const rotate = useMutation({
    mutationFn: () => request(true),
    retry: false,
    onSuccess: (status) => {
      client.setQueryData(['control-pki'], status);
      void client.invalidateQueries({ queryKey: ['nodes'] });
      setStarted(true);
    },
  });
  const error = rotate.error ?? query.error;
  const status = query.data;
  return (
    <SettingListItem
      paddings="small"
      title={t('controlPki.title')}
      description={t('controlPki.hint')}
    >
      <Space orientation="vertical" style={{ width: '100%' }}>
        {modalContextHolder}
        {status && (
          <Descriptions
            size="small"
            column={1}
            items={[
              {
                key: 'ca',
                label: t('controlPki.caExpiry'),
                children: new Date(status.caExpiresAt).toLocaleString(),
              },
              {
                key: 'identity',
                label: t('controlPki.identityExpiry'),
                children: new Date(status.identityExpiresAt).toLocaleString(),
              },
              {
                key: 'pin',
                label: t('controlPki.fingerprint'),
                children: (
                  <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>
                    {status.caFingerprint}
                  </Typography.Text>
                ),
              },
            ]}
          />
        )}
        {status?.status && (
          <Alert
            type={status.recovery ? 'warning' : 'info'}
            title={t(`controlPki.status.${status.status}`, { defaultValue: status.status })}
            description={t('controlPki.progress', {
              migrated: status.migrated,
              total: status.total,
              recovery: status.recovery,
            })}
          />
        )}
        {started && <Alert type="success" title={t('controlPki.revoked')} />}
        {error && (
          <Alert
            type="error"
            title={t('controlPki.requestFailed')}
            description={t(`controlPki.errors.${error.message}`, {
              defaultValue: t('controlPki.requestFailed'),
            })}
          />
        )}
        {status?.lastError && (
          <Alert
            type="warning"
            title={t('controlPki.renewalFailed')}
            description={t(`controlPki.errors.${status.lastError}`, {
              defaultValue: t('controlPki.retryHint'),
            })}
          />
        )}
        <Space wrap>
          <Button
            danger
            loading={rotate.isPending}
            disabled={!status || status.status === 'migrating'}
            onClick={() =>
              modal.confirm({
                title: t('controlPki.confirmTitle'),
                content: t('controlPki.confirmHint'),
                okText: t('controlPki.rotate'),
                okButtonProps: { danger: true },
                cancelText: t('cancel'),
                onOk: () => rotate.mutateAsync(),
              })
            }
          >
            {t('controlPki.rotate')}
          </Button>
          <Button onClick={() => void query.refetch()} loading={query.isFetching}>
            {t('controlPki.refresh')}
          </Button>
        </Space>
      </Space>
    </SettingListItem>
  );
}
