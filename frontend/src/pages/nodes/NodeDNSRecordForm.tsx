import { Button, Form, Input, InputNumber, Select, Space, Switch, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { NodeDNSInput, NodeDNSRecord } from '@/schemas/node-dns';
import { nodeDNSIP, nodeDNSName } from '@/lib/nodes/dns';

interface Values {
  name: string;
  type: 'A' | 'AAAA';
  content: string;
  ttl: number;
  proxied: boolean;
}
export default function NodeDNSRecordForm({
  record,
  address,
  zone,
  busy,
  disabled = false,
  onSave,
  onCancel,
}: {
  record?: NodeDNSRecord;
  address: string;
  zone: string;
  busy: boolean;
  disabled?: boolean;
  onSave: (input: NodeDNSInput) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [form] = Form.useForm<Values>();
  const type = Form.useWatch('type', form) ?? 'A';
  const proxied = Form.useWatch('proxied', form);
  const rawAddress = address.replace(/^\[|\]$/g, '');
  const initialType =
    record?.type === 'AAAA' || (!record && nodeDNSIP(rawAddress, 'AAAA')) ? 'AAAA' : 'A';
  async function submit(values: Values) {
    const next: NodeDNSInput = {
      name: nodeDNSName(values.name, zone)!,
      type: values.type,
      content: values.content.trim(),
      ttl: values.proxied ? 1 : values.ttl,
      proxied: values.proxied,
    };
    if (record) {
      for (const key of ['name', 'type', 'content', 'ttl', 'proxied'] as const) {
        if (next[key] === record[key]) delete next[key];
      }
    }
    await onSave(next);
  }
  return (
    <section
      className="node-dns-editor"
      aria-label={t(record ? 'nodeDNS.editRecord' : 'nodeDNS.addRecord')}
    >
      <Typography.Title level={5}>
        {t(record ? 'nodeDNS.editRecord' : 'nodeDNS.addRecord')}
      </Typography.Title>
      <Form
        form={form}
        layout="vertical"
        disabled={busy || disabled}
        onFinish={submit}
        initialValues={{
          name: record?.name ?? '',
          type: initialType,
          content: record?.content ?? (nodeDNSIP(rawAddress, initialType) ? rawAddress : ''),
          ttl: record?.ttl ?? 1,
          proxied: record?.proxied ?? false,
        }}
        onValuesChange={(changed) => {
          if (changed.proxied === true) form.setFieldValue('ttl', 1);
        }}
      >
        <div className="node-dns-form-grid">
          <Form.Item
            name="name"
            label={t('nodeDNS.domain')}
            rules={[
              { required: true, whitespace: true, message: t('nodeDNS.required') },
              {
                validator: (_, value: string) =>
                  !value || nodeDNSName(value, zone)
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('nodeDNS.invalidDomain', { zone }))),
              },
            ]}
          >
            <Input maxLength={253} placeholder={`node.${zone}`} />
          </Form.Item>
          <Form.Item name="type" label={t('nodeDNS.type')}>
            <Select
              options={[
                { label: 'A · IPv4', value: 'A' },
                { label: 'AAAA · IPv6', value: 'AAAA' },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="content"
            label={t('nodeDNS.targetIP')}
            dependencies={['type']}
            rules={[
              { required: true, whitespace: true, message: t('nodeDNS.required') },
              {
                validator: (_, value: string) =>
                  !value || nodeDNSIP(value.trim(), type)
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('nodeDNS.invalidIP', { type }))),
              },
            ]}
          >
            <Input placeholder={type === 'A' ? '203.0.113.20' : '2001:db8::20'} />
          </Form.Item>
          <Form.Item
            name="ttl"
            label={t('nodeDNS.ttl')}
            rules={[
              {
                validator: (_, value: number) =>
                  Number.isInteger(value) && (value === 1 || (value >= 30 && value <= 86400))
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('nodeDNS.invalidTTL'))),
              },
            ]}
            extra={t('nodeDNS.ttlHint')}
          >
            <InputNumber
              disabled={busy || disabled || proxied}
              min={1}
              max={86400}
              style={{ width: '100%' }}
            />
          </Form.Item>
          <Form.Item name="proxied" label={t('nodeDNS.proxy')} valuePropName="checked">
            <Switch
              checkedChildren={t('nodeDNS.proxied')}
              unCheckedChildren={t('nodeDNS.dnsOnly')}
            />
          </Form.Item>
        </div>
        <Space>
          <Button type="primary" htmlType="submit" loading={busy} disabled={disabled}>
            {t('save')}
          </Button>
          <Button disabled={busy} onClick={onCancel}>
            {t('cancel')}
          </Button>
        </Space>
      </Form>
    </section>
  );
}
