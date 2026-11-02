import { createContext, useContext, useMemo } from 'react';

// The provider is keyed by node in XrayPage, so drafts and in-flight UI state
// cannot move from one panel to another when the selection changes.
export const NodeTargetContext = createContext<number | undefined>(undefined);

export function nodeTargetUrl(path: string, nodeId?: number): string {
  if (nodeId === undefined) return path;
  return `${path}${path.includes('?') ? '&' : '?'}nodeId=${nodeId}`;
}

export function useNodeTarget() {
  const nodeId = useContext(NodeTargetContext);
  return useMemo(
    () => ({
      nodeId,
      url: (path: string) => nodeTargetUrl(path, nodeId),
      queryKey: (key: readonly unknown[]) =>
        nodeId === undefined ? key : ['node', nodeId, ...key],
    }),
    [nodeId],
  );
}
