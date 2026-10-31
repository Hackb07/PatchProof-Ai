async function req(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) throw new Error(`${opts.method || 'GET'} ${path}: ${res.status}`)
  return res.json()
}

export const api = {
  health: () => req('/api/health'),
  listScans: () => req('/api/scans'),
  getScan: (id) => req(`/api/scans/${id}`),
  createScan: (repo_url, branch) =>
    req('/api/scans', { method: 'POST', body: JSON.stringify({ repo_url, branch: branch || 'HEAD' }) }),
  rerun: (id) => req(`/api/scans/${id}/rerun`, { method: 'POST' }),
  file: (scan_id, path) =>
    req(`/api/github/file?scan_id=${encodeURIComponent(scan_id)}&path=${encodeURIComponent(path)}`),
}
