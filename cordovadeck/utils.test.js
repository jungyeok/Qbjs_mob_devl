const fs = require('fs');
const path = require('path');
const os = require('os');
const { buildTree, fmtUptime } = require('./utils');

describe('utils buildTree', () => {
  const tmpDir = path.join(os.tmpdir(), `cordovadeck-test-${Date.now()}`);
  beforeAll(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'sub'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'a.txt'), 'a');
    fs.writeFileSync(path.join(tmpDir, 'sub', 'b.txt'), 'b');
  });
  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('returns directory tree', () => {
    const tree = buildTree(tmpDir);
    expect(tree).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'a.txt', type: 'file' }),
      expect.objectContaining({ name: 'sub', type: 'dir' }),
    ]));
  });
});

describe('utils fmtUptime', () => {
  test('formats seconds properly', () => {
    expect(fmtUptime(5)).toBe('0m 5s');
    expect(fmtUptime(125)).toBe('2m 5s');
    expect(fmtUptime(3700)).toBe('1h 1m 40s');
    expect(fmtUptime(90000)).toBe('1d 1h 0m');
  });
});