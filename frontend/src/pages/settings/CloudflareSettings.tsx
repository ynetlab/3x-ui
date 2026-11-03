import { Input } from 'antd';
import { useTranslation } from 'react-i18next';

import type { AllSetting } from '@/models/setting';
import { SettingListItem } from '@/components/ui';
import SecretInput from './SecretInput';

export default function CloudflareSettings({
  allSetting,
  updateSetting,
}: {
  allSetting: AllSetting;
  updateSetting: (patch: Partial<AllSetting>) => void;
}) {
  const { t } = useTranslation();
  return (
    <>
      <SettingListItem
        paddings="small"
        title={t('cloudflare.zoneId')}
        description={t('cloudflare.zoneIdHint')}
      >
        <Input
          value={allSetting.cloudflareZoneId}
          maxLength={32}
          onChange={(e) => updateSetting({ cloudflareZoneId: e.target.value.trim() })}
        />
      </SettingListItem>
      <SettingListItem
        paddings="small"
        title={t('cloudflare.apiToken')}
        description={t('cloudflare.tokenHint')}
      >
        <SecretInput
          value={allSetting.cloudflareApiToken}
          configured={allSetting.hasCloudflareApiToken}
          clearArmed={allSetting.clearCloudflareApiToken}
          placeholder={t('cloudflare.tokenConfigured')}
          onChange={(value) => updateSetting({ cloudflareApiToken: value })}
          onClearArmedChange={(value) => updateSetting({ clearCloudflareApiToken: value })}
        />
      </SettingListItem>
    </>
  );
}
