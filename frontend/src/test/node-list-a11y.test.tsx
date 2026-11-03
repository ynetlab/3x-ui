import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import NodeList from '@/pages/nodes/NodeList';
import type { NodeRecord } from '@/schemas/node';

import { renderWithProviders } from './test-utils';

const noop = () => {};

vi.mock('@/pages/nodes/NodeHistoryPanel', () => ({ default: () => null }));

const failing: NodeRecord = {
  id: 1,
  name: 'edge',
  guid: 'e1',
  transitive: false,
  enable: true,
  status: 'offline',
  lastError: 'dial tcp 10.0.0.2:2053: i/o timeout',
};

function renderList(isMobile: boolean) {
  renderWithProviders(
    <NodeList
      nodes={[failing]}
      isMobile={isMobile}
      selectedIds={[]}
      onSelectionChange={noop}
      onAdd={noop}
      onMtls={noop}
      onEdit={noop}
      onDelete={noop}
      onProbe={noop}
      onToggleEnable={noop}
      onUpdateNode={noop}
      onUpdateSelected={noop}
    />,
  );
}

// The error lived only in a hover tooltip and the enable switch had no name, so a
// screen reader heard "exclamation-circle" and "switch" (s-ui#1293).
describe('NodeList screen-reader names', () => {
  it.each([false, true])(
    'offers migration only for direct unpaired nodes (mobile=%s)',
    async (isMobile) => {
      const onMigrate = vi.fn();
      renderWithProviders(
        <NodeList
          nodes={[failing, { ...failing, id: 2, name: 'paired', controlConnection: true }]}
          isMobile={isMobile}
          selectedIds={[]}
          onSelectionChange={noop}
          onAdd={noop}
          onMtls={noop}
          onEdit={noop}
          onDelete={noop}
          onProbe={noop}
          onToggleEnable={noop}
          onUpdateNode={noop}
          onUpdateSelected={noop}
          onMigrate={onMigrate}
        />,
      );
      if (isMobile) fireEvent.click(screen.getAllByRole('button', { name: /^more$/i })[0]);
      const action = await screen.findByRole(isMobile ? 'menuitem' : 'button', {
        name: 'Migrate to slave',
      });
      fireEvent.click(action);
      expect(onMigrate).toHaveBeenCalledWith(expect.objectContaining({ id: failing.id }));
      expect(onMigrate).toHaveBeenCalledTimes(1);
    },
  );
  it('announces the node error from the status column', () => {
    renderList(false);

    expect(screen.getByRole('img', { name: failing.lastError }).tagName).toBe('SPAN');
  });

  it.each([false, true])('names the enable switch (mobile=%s)', (isMobile) => {
    renderList(isMobile);

    expect(screen.getByRole('switch', { name: 'Enabled' }).getAttribute('aria-checked')).toBe(
      'true',
    );
  });
});
