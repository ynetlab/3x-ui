import { useState } from 'react';
import { Alert, Button, Checkbox, Input, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useACMEConfig, type ACMEConfig } from '@/api/queries/useNodeCertificates';
import { SettingListItem } from '@/components/ui';

export default function ACMESettings() {
  const { t } = useTranslation();
  const { query, save } = useACMEConfig();
  const [draft, setDraft] = useState<ACMEConfig | null>(null);
  const config = draft ?? query.data ?? { email: '', acceptTos: false };
  const error = save.error ?? query.error;
  return (
    <SettingListItem
      paddings="small"
      title={t('nodeCertificate.settingsTitle')}
      description={t('nodeCertificate.settingsHint')}
    >
      <Space orientation="vertical" style={{ width: '100%' }}>
        <Input
          type="email"
          aria-label={t('nodeCertificate.email')}
          placeholder={t('nodeCertificate.email')}
          maxLength={254}
          value={config.email}
          disabled={query.isLoading || save.isPending}
          onChange={(event) => setDraft({ ...config, email: event.target.value })}
        />
        <Checkbox
          checked={config.acceptTos}
          disabled={query.isLoading || save.isPending}
          onChange={(event) => setDraft({ ...config, acceptTos: event.target.checked })}
        >
          {t('nodeCertificate.acceptTos')}{' '}
          <Typography.Link
            href="https://letsencrypt.org/repository/"
            target="_blank"
            rel="noreferrer"
          >
            {t('nodeCertificate.terms')}
          </Typography.Link>
        </Checkbox>
        {error && (
          <Alert
            type="error"
            title={t(`nodeCertificate.errors.${error.message}`, {
              defaultValue: t('nodeCertificate.requestFailed'),
            })}
          />
        )}
        {save.isSuccess && !draft && (
          <Typography.Text type="success">{t('nodeCertificate.settingsSaved')}</Typography.Text>
        )}
        <Button
          loading={save.isPending}
          disabled={!query.data || save.isPending || (config.acceptTos && !config.email.trim())}
          onClick={() => {
            void save
              .mutateAsync(config)
              .then(() => setDraft(null))
              .catch(() => {});
          }}
        >
          {t('nodeCertificate.saveSettings')}
        </Button>
      </Space>
    </SettingListItem>
  );
}
