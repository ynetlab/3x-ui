import { useTranslation } from 'react-i18next';
import { Input, InputNumber } from 'antd';

import { FormField, rhfZodValidate } from '@/components/form/rhf';
import { AnyTLSOutboundFormSettingsSchema } from '@/schemas/forms/outbound-form';

export default function AnyTLSFields() {
  const { t } = useTranslation();
  return (
    <>
      <FormField
        label={t('password')}
        name={['settings', 'password']}
        tooltip={t('anytls.uuidHint')}
        rules={{ validate: rhfZodValidate(AnyTLSOutboundFormSettingsSchema.shape.password) }}
      >
        <Input />
      </FormField>
      <FormField label={t('pages.clients.email')} name={['settings', 'email']}>
        <Input />
      </FormField>
      {(['level', 'idleSessionCheckInterval', 'idleSessionTimeout', 'minIdleSession'] as const).map(
        (key) => (
          <FormField
            key={key}
            label={t(`anytls.${key}`)}
            name={['settings', key]}
            rules={{ validate: rhfZodValidate(AnyTLSOutboundFormSettingsSchema.shape[key]) }}
          >
            <InputNumber min={0} max={4294967295} precision={0} style={{ width: '100%' }} />
          </FormField>
        ),
      )}
    </>
  );
}
