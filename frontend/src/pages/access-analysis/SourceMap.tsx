import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Skeleton } from 'antd';
import * as echarts from 'echarts/core';
import { MapChart, ScatterChart } from 'echarts/charts';
import { GeoComponent, TooltipComponent, VisualMapComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import type { AnalysisItem } from '@/schemas/access-analysis';
import mapURL from './world-admin1.geojson?url';
type World = {
  type: 'FeatureCollection';
  features: {
    type: 'Feature';
    properties: { name: string; country: string; label: string | null; aliases: string[] };
    geometry: { type: string; coordinates: unknown };
  }[];
};

echarts.use([
  MapChart,
  ScatterChart,
  GeoComponent,
  TooltipComponent,
  VisualMapComponent,
  CanvasRenderer,
]);
let pending: Promise<void> | undefined;
const normalized = (value: string) =>
  value
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]/gu, '');
const aliases = new Map<string, string>();
const labels = new Map<string, string>();
function loadMap(): Promise<void> {
  pending ??= fetch(mapURL)
    .then(async (response) => {
      if (!response.ok) throw new Error('map');
      const world = (await response.json()) as World;
      echarts.registerMap('access-provinces', world as Parameters<typeof echarts.registerMap>[1]);
      for (const feature of world.features) {
        const p = feature.properties;
        labels.set(p.name, p.label || p.name);
        aliases.set(p.name, p.name);
        for (const name of [p.label, ...p.aliases]) {
          if (!name) continue;
          for (const alias of name.split('|'))
            aliases.set(`${p.country}:${normalized(alias)}`, p.name);
        }
      }
    })
    .catch((error) => {
      pending = undefined;
      throw error;
    });
  return pending;
}

export function regionLabel(row: AnalysisItem): string {
  return [row.country, labels.get(row.subdivision) || row.subdivision].filter(Boolean).join(' · ');
}

export default function SourceMap({ rows, dark }: { rows: AnalysisItem[]; dark: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const { t } = useTranslation();
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    void loadMap()
      .then(() => {
        if (active) setReady(true);
      })
      .catch(() => {
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, [retry]);
  useEffect(() => {
    if (!ref.current || !ready) return;
    const chart = echarts.init(ref.current);
    const values = new Map<string, number>();
    const fallback: { name: string; value: number[] }[] = [];
    for (const row of rows) {
      const key =
        aliases.get(row.subdivision) ||
        aliases.get(`${row.country}:${normalized(row.subdivision)}`);
      if (key) values.set(key, (values.get(key) ?? 0) + row.count);
      else if (row.country)
        fallback.push({ name: regionLabel(row), value: [row.longitude, row.latitude, row.count] });
    }
    chart.setOption({
      animation: false,
      tooltip: {
        trigger: 'item',
        renderMode: 'richText',
        formatter: (params: { name: string; value: number | number[] }) =>
          `${labels.get(params.name) || params.name}\n${t('accessAnalysis.count')}: ${Array.isArray(params.value) ? params.value[2] : Number.isFinite(params.value) ? params.value : 0}`,
      },
      geo: {
        map: 'access-provinces',
        roam: true,
        boundingCoords: [
          [-180, 85],
          [180, -60],
        ],
        center: [0, 25],
        zoom: 1.15,
        scaleLimit: { min: 1, max: 30 },
        itemStyle: {
          areaColor: dark ? '#233343' : '#edf2f7',
          borderColor: dark ? '#586778' : '#bdc8d4',
          borderWidth: 0.35,
        },
        emphasis: { label: { show: false }, itemStyle: { areaColor: '#91caff' } },
      },
      visualMap: {
        show: false,
        min: 0,
        max: Math.max(1, ...values.values()),
        calculable: false,
        left: 12,
        bottom: 10,
        inRange: { color: ['#e6f4ff', '#4096ff', '#003eb3'] },
        textStyle: { color: dark ? '#bbc8d4' : '#596777' },
        seriesIndex: 0,
      },
      series: [
        { type: 'map', geoIndex: 0, data: [...values].map(([name, value]) => ({ name, value })) },
        {
          type: 'scatter',
          coordinateSystem: 'geo',
          symbolSize: 8,
          itemStyle: { color: '#1677ff' },
          data: fallback,
        },
      ],
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(ref.current);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [rows, dark, t, ready]);
  return (
    <>
      {failed && (
        <Alert
          type="error"
          showIcon
          title={t('accessAnalysis.mapLoadError')}
          action={
            <Button
              onClick={() => {
                setFailed(false);
                setRetry((value) => value + 1);
              }}
            >
              {t('refresh')}
            </Button>
          }
        />
      )}
      {!ready && !failed && <Skeleton active />}
      <div
        ref={ref}
        className="access-source-map"
        role="img"
        aria-label={t('accessAnalysis.sourceMap')}
      />
    </>
  );
}
