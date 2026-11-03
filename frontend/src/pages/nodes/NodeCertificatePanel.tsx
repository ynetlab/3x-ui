import { useState } from 'react';
import { Alert, Button, Modal, Select, Space, Tag, Typography } from 'antd';
import { SafetyCertificateOutlined, ReloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import dayjs from 'dayjs';
import type { NodeRecord } from '@/schemas/node';
import { useNodeCertificates } from '@/api/queries/useNodeCertificates';

export default function NodeCertificatePanel({
  node,
  domains,
  recordIds,
  disabled,
}: {
  node: NodeRecord;
  domains: string[];
  recordIds: string[];
  disabled: boolean;
}) {
  const { t } = useTranslation();
  const { query, mutation, enabled } = useNodeCertificates(node);
  const [primary, setPrimary] = useState('');
  const [modal, context] = Modal.useModal();
  const candidates = domains.filter((domain) => !domain.startsWith('*.'));
  const selectedPrimary = candidates.includes(primary)
    ? primary
    : candidates.includes(node.address ?? '')
      ? node.address
      : candidates[0];
  const pending =
    !!query.data &&
    ['queued', 'issuing', 'deploying', 'retrying', 'staged'].includes(query.data.status);
  const error = mutation.error ?? query.error;
  const errorText = (code: string) =>
    t(`nodeCertificate.errors.${code}`, { defaultValue: t('nodeCertificate.requestFailed') });
  return (
    <Space orientation="vertical" style={{ width: '100%', marginTop: 12 }}>
      {context}
      {!enabled && (
        <>
          <Alert type="info" title={t('nodeCertificate.pairedRequired')} />
          <Button disabled icon={<SafetyCertificateOutlined aria-hidden />}>
            {t('nodeDNS.requestCertificate')}
          </Button>
        </>
      )}
      {enabled && (
        <>
          <Space wrap>
            <Typography.Text>{t('nodeCertificate.primaryDomain')}</Typography.Text>
            <Select
              aria-label={t('nodeCertificate.primaryDomain')}
              value={selectedPrimary}
              options={candidates.map((value) => ({ value, label: value }))}
              style={{ minWidth: 220, maxWidth: '100%' }}
              disabled={disabled || mutation.isPending}
              onChange={setPrimary}
            />
            <Button
              icon={<SafetyCertificateOutlined aria-hidden />}
              loading={mutation.isPending}
              disabled={disabled || !selectedPrimary || pending || query.isLoading || query.isError}
              onClick={() =>
                modal.confirm({
                  title: t('nodeCertificate.confirmTitle'),
                  content: (
                    <>
                      <Typography.Paragraph>
                        {t('nodeCertificate.confirmHint')}
                      </Typography.Paragraph>
                      {domains.map((domain) => (
                        <Tag key={domain}>{domain}</Tag>
                      ))}
                    </>
                  ),
                  okText: t('nodeDNS.requestCertificate'),
                  cancelText: t('cancel'),
                  onOk: async () => {
                    try {
                      await mutation.mutateAsync({
                        action: 'request',
                        recordIds,
                        primaryDomain: selectedPrimary!,
                      });
                    } catch {
                      /* error remains visible */
                    }
                  },
                })
              }
            >
              {t('nodeDNS.requestCertificate')}
            </Button>
            <Button
              icon={<ReloadOutlined aria-hidden />}
              disabled={mutation.isPending || query.isFetching}
              onClick={() => {
                void query.refetch();
              }}
            >
              {t('refresh')}
            </Button>
          </Space>
          {query.data && query.data.status !== 'none' && (
            <Alert
              type={
                query.data.status === 'active'
                  ? 'success'
                  : query.data.lastError
                    ? 'warning'
                    : 'info'
              }
              title={t(`nodeCertificate.states.${query.data.status}`, {
                defaultValue: query.data.status,
              })}
              description={
                <Space orientation="vertical" size={4}>
                  <Typography.Text>{query.data.domains.join(', ')}</Typography.Text>
                  {query.data.activeExpiresAt > 0 && (
                    <Typography.Text>
                      {t('nodeCertificate.activeExpires', {
                        date: dayjs(query.data.activeExpiresAt).format('YYYY-MM-DD HH:mm'),
                      })}
                    </Typography.Text>
                  )}
                  {query.data.lastError && (
                    <Typography.Text>{errorText(query.data.lastError)}</Typography.Text>
                  )}
                  {query.data.nextAttemptAt > 0 && (
                    <Typography.Text>
                      {t('nodeCertificate.nextAttempt', {
                        date: dayjs(query.data.nextAttemptAt).format('YYYY-MM-DD HH:mm:ss'),
                      })}
                    </Typography.Text>
                  )}
                  {query.data.status === 'retrying' && (
                    <Button
                      loading={mutation.isPending}
                      onClick={() => {
                        void mutation.mutateAsync({ action: 'retry' }).catch(() => {});
                      }}
                    >
                      {t('nodeCertificate.retry')}
                    </Button>
                  )}
                </Space>
              }
            />
          )}
        </>
      )}
      {error && <Alert type="error" title={errorText(error.message)} />}
      <Typography.Text type="secondary">{t('nodeCertificate.renewHint')}</Typography.Text>
    </Space>
  );
}
