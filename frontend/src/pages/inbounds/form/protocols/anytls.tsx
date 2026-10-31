import { useTranslation } from 'react-i18next';
import { Form, Input } from 'antd';
import { Controller, useFormContext } from 'react-hook-form';

import type { InboundFormValues } from '@/schemas/forms/inbound-form';

export default function AnyTLSFields() {
  const { t } = useTranslation();
  const { control } = useFormContext<InboundFormValues>();
  return (
    <Controller
      control={control}
      name="settings.paddingScheme"
      render={({ field }) => (
        <Form.Item label={t('anytls.paddingScheme')} help={t('anytls.paddingSchemeHint')}>
          <Input.TextArea
            aria-label={t('anytls.paddingScheme')}
            rows={5}
            placeholder={'stop=8\n0=30-30\n1=100-400'}
            value={(field.value ?? []).join('\n')}
            onChange={(e) =>
              field.onChange(e.target.value === '' ? [] : e.target.value.split('\n'))
            }
            onBlur={field.onBlur}
            ref={field.ref}
          />
        </Form.Item>
      )}
    />
  );
}
