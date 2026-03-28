const fs = require('fs');
const path = require('path');

function buildTree(dir, base = '') {
  const items = [];
  if (!fs.existsSync(dir)) return items;

  fs.readdirSync(dir).forEach((name) => {
    const full = path.join(dir, name);
    const rel = path.join(base, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      items.push({
        name,
        path: rel,
        type: 'dir',
        children: buildTree(full, rel),
      });
    } else {
      items.push({
        name,
        path: rel,
        type: 'file',
        size: stat.size,
      });
    }
  });

  return items;
}

function fmtUptime(secs) {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  return d > 0
    ? `${d}d ${h}h ${m}m`
    : h > 0
      ? `${h}h ${m}m ${s}s`
      : `${m}m ${s}s`;
}

module.exports = { buildTree, fmtUptime };