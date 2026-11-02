import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router';
import { Alert, Modal, Select, Space } from 'antd';

import { useNodesQuery } from '@/api/queries/useNodesQuery';
import { useNodeTarget } from '@/api/nodeTarget';

export default function NodeXrayTarget({ dirty, busy }: { dirty: boolean; busy: boolean }) {
  const { t } = useTranslation();
  const { nodeId } = useNodeTarget();
  const { nodes, loading, fetchError } = useNodesQuery();
  const location = useLocation();
  const navigate = useNavigate();
  const [modal, contextHolder] = Modal.useModal();
  const selected = nodes.find((node) => node.id === nodeId && !node.transitive);

  function selectNode(id: number) {
    if (id === (nodeId ?? 0)) return;
    const change = () => {
      const search = new URLSearchParams(location.search);
      if (id === 0) search.delete('nodeId');
      else search.set('nodeId', String(id));
      navigate({ pathname: location.pathname, search: search.toString(), hash: location.hash });
    };
    if (dirty) {
      modal.confirm({
        title: t('nodeXray.discardTitle'),
        content: t('nodeXray.discardContent'),
        onOk: change,
      });
    } else change();
  }

  return (
    <Space orientation="vertical" style={{ width: '100%', marginBottom: 16 }}>
      {contextHolder}
      <Space wrap>
        <span>{t('nodeXray.target')}</span>
        <Select
          aria-label={t('nodeXray.target')}
          value={nodeId ?? 0}
          loading={loading}
          disabled={busy}
          showSearch={{ optionFilterProp: 'label' }}
          style={{ minWidth: 240 }}
          onChange={selectNode}
          options={[
            { value: 0, label: t('nodeXray.local') },
            ...nodes
              .filter((node) => node.id > 0 && !node.transitive)
              .map((node) => ({
                value: node.id,
                label: node.name || node.address || String(node.id),
                disabled: node.enable === false,
              })),
            ...(nodeId !== undefined && !selected
              ? [{ value: nodeId, label: `#${nodeId}`, disabled: true }]
              : []),
          ]}
        />
      </Space>
      {fetchError && <Alert type="error" showIcon title={fetchError} />}
      {nodeId !== undefined && (
        <Alert
          type="info"
          showIcon
          title={t('nodeXray.editing', { name: selected?.name || `#${nodeId}` })}
        />
      )}
    </Space>
  );
}
