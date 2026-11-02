import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router';
import i18next from 'i18next';
import { NodeTargetContext } from '@/api/nodeTarget';
import { afterEach, expect, test, vi } from 'vitest';

import AppSidebar from '@/layouts/AppSidebar';
import { renderWithProviders } from './test-utils';

vi.mock('@/api/queries/useAllSettings', () => ({
  useAllSettings: () => ({ allSetting: {} }),
}));

afterEach(() => {
  localStorage.clear();
});

// rc-menu registers its items in a microtask after render; settle it inside act().
async function renderSidebar() {
  const view = renderWithProviders(
    <MemoryRouter>
      <AppSidebar />
    </MemoryRouter>,
  );
  await act(async () => {});
  return view;
}

test('keeps the sidebar expanded after pinning it from the header and restores the choice', async () => {
  const first = await renderSidebar();
  const sidebar = first.container.querySelector('.ant-layout-sider');
  const sidebarRoot = first.container.querySelector('.ant-sidebar');

  expect(sidebar?.classList.contains('ant-layout-sider-collapsed')).toBe(true);

  fireEvent.mouseEnter(sidebarRoot!);

  const pinButton = screen.getByRole('button', { name: 'Pin sidebar' });
  expect(pinButton.closest('.brand-actions')).not.toBeNull();

  fireEvent.click(pinButton);
  fireEvent.mouseLeave(sidebarRoot!);

  expect(sidebar?.classList.contains('ant-layout-sider-collapsed')).toBe(false);
  expect(sidebarRoot?.getAttribute('style')).toContain('--sider-rail: 220px');
  expect(localStorage.getItem('sidebar-pinned')).toBe('true');

  first.unmount();

  const second = await renderSidebar();
  const restoredSidebar = second.container.querySelector('.ant-layout-sider');
  const restoredSidebarRoot = second.container.querySelector('.ant-sidebar');

  expect(restoredSidebar?.classList.contains('ant-layout-sider-collapsed')).toBe(false);
  expect(restoredSidebarRoot?.getAttribute('style')).toContain('--sider-rail: 220px');
  expect(screen.getByRole('button', { name: 'Pin sidebar' })).not.toBeNull();
});

test('returns to the compact rail after unpinning', async () => {
  const view = await renderSidebar();
  const sidebar = view.container.querySelector('.ant-layout-sider');
  const sidebarRoot = view.container.querySelector('.ant-sidebar');

  fireEvent.mouseEnter(sidebarRoot!);
  fireEvent.click(screen.getByRole('button', { name: 'Pin sidebar' }));
  fireEvent.click(screen.getByRole('button', { name: 'Pin sidebar' }));
  fireEvent.mouseLeave(sidebarRoot!);

  expect(sidebar?.classList.contains('ant-layout-sider-collapsed')).toBe(true);
  expect(sidebarRoot?.getAttribute('style')).toContain('--sider-rail: 72px');
  expect(localStorage.getItem('sidebar-pinned')).toBe('false');
});

test('labels the palette shortcut with the modifier the platform actually uses', async () => {
  const view = await renderSidebar();
  const chip = view.container.querySelector('.sidebar-command-kbd');
  expect(chip?.textContent).toBe('CtrlK');
});

function CurrentLocation() {
  const location = useLocation();
  return (
    <output data-testid="current-location">
      {location.pathname + location.search + location.hash}
    </output>
  );
}

test('keeps the selected node between full Xray settings, general settings and routing', async () => {
  renderWithProviders(
    <MemoryRouter initialEntries={['/xray?nodeId=2#dns']}>
      <NodeTargetContext.Provider value={2}>
        <AppSidebar />
        <CurrentLocation />
      </NodeTargetContext.Provider>
    </MemoryRouter>,
  );
  await act(async () => {});
  fireEvent.mouseEnter(document.querySelector('.ant-sidebar')!);
  fireEvent.click(await screen.findByText(i18next.t('pages.xray.Balancers')));
  await waitFor(() =>
    expect(screen.getByTestId('current-location').textContent).toBe('/xray?nodeId=2#balancer'),
  );
  fireEvent.click(screen.getByText(i18next.t('menu.settings')));
  fireEvent.click(await screen.findByText(i18next.t('pages.settings.panelSettings')));
  await waitFor(() =>
    expect(screen.getByTestId('current-location').textContent).toBe('/settings?nodeId=2#general'),
  );
  expect(screen.queryByText(i18next.t('pages.settings.securitySettings'))).toBeNull();
  expect(screen.queryByText(i18next.t('pages.settings.TGBotSettings'))).toBeNull();
  fireEvent.click(screen.getByText(i18next.t('menu.routing')));
  await waitFor(() =>
    expect(screen.getByTestId('current-location').textContent).toBe('/routing?nodeId=2'),
  );
});
