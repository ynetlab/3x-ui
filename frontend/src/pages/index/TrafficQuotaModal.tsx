import { useState } from 'react';
import { Form, InputNumber, Modal } from 'antd';
import { useTranslation } from 'react-i18next';
import type { StatusInput } from '@/schemas/status';
import { HttpUtil } from '@/utils';

export default function TrafficQuotaModal({
  quota,
  onClose,
  onSaved,
}: {
  quota?: StatusInput['trafficQuota'];
  onClose: () => void;
  onSaved: () => Promise<unknown>;
}) {
  const { t } = useTranslation();
  const [limit, setLimit] = useState((quota?.trafficLimit ?? 0) / 1024 ** 3);
  const [day, setDay] = useState(quota?.trafficResetDay ?? 1);
  const [saving, setSaving] = useState(false);
  async function save() {
    setSaving(true);
    try {
      const response = await HttpUtil.post(
        '/panel/api/server/trafficQuota',
        {
          trafficLimit: Math.round(limit * 1024 ** 3),
          trafficResetDay: day,
        },
        { headers: { 'Content-Type': 'application/json' } },
      );
      if (response?.success) {
        await onSaved();
        onClose();
      }
    } finally {
      setSaving(false);
    }
  }
  return (
    <Modal
      open
      title={t('nodeStatus.trafficSettings')}
      onCancel={onClose}
      onOk={save}
      confirmLoading={saving}
      okText={t('save')}
      cancelText={t('cancel')}
      width={400}
    >
      <Form layout="vertical">
        <Form.Item label={t('pages.nodes.trafficLimit')} htmlFor="master-traffic-limit">
          <InputNumber
            id="master-traffic-limit"
            min={0}
            max={8388607}
            value={limit}
            onChange={(value) => setLimit(value ?? 0)}
            style={{ width: '100%' }}
          />
        </Form.Item>
        <Form.Item label={t('pages.nodes.trafficResetDay')} htmlFor="master-traffic-reset-day">
          <InputNumber
            id="master-traffic-reset-day"
            min={1}
            max={31}
            precision={0}
            value={day}
            onChange={(value) => setDay(value ?? 1)}
            style={{ width: '100%' }}
          />
        </Form.Item>
      </Form>
    </Modal>
  );
}
