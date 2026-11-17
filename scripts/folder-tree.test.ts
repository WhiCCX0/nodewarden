import assert from 'node:assert/strict';
import test from 'node:test';

import { buildFolderTree, flattenFolderTree } from '../webapp/src/lib/folder-tree';
import type { Folder } from '../webapp/src/lib/types';

function folder(id: string, name: string, decName = name): Folder {
  return { id, name, decName };
}

test('buildFolderTree nests folders only under an existing exact parent', () => {
  const roots = buildFolderTree([
    folder('work', 'Work'),
    folder('email', 'Work/Email'),
    folder('archive', 'Work/Email/Archive'),
    folder('personal', 'Personal'),
  ]);

  assert.deepEqual(roots.map((node) => node.folder.id), ['work', 'personal']);
  assert.equal(roots[0].label, 'Work');
  assert.equal(roots[0].children[0].label, 'Email');
  assert.equal(roots[0].children[0].children[0].label, 'Archive');
});

test('buildFolderTree keeps a path as a root when its parent is missing', () => {
  const roots = buildFolderTree([
    folder('email', 'Work/Email'),
    folder('archive', 'Work/Email/Archive'),
  ]);

  assert.equal(roots.length, 1);
  assert.equal(roots[0].folder.id, 'email');
  assert.equal(roots[0].label, 'Work/Email');
  assert.equal(roots[0].children[0].folder.id, 'archive');
  assert.equal(roots[0].children[0].label, 'Archive');
});

test('buildFolderTree preserves duplicate folder IDs and uses the first exact parent', () => {
  const roots = buildFolderTree([
    folder('work-first', 'Work'),
    folder('work-second', 'Work'),
    folder('email', 'Work/Email'),
  ]);

  assert.deepEqual(roots.map((node) => node.folder.id), ['work-first', 'work-second']);
  assert.deepEqual(roots[0].children.map((node) => node.folder.id), ['email']);
  assert.equal(roots[1].children.length, 0);
});

test('flattenFolderTree returns depth-first rows and respects collapsed IDs', () => {
  const roots = buildFolderTree([
    folder('work', 'Work'),
    folder('email', 'Work/Email'),
    folder('archive', 'Work/Email/Archive'),
    folder('personal', 'Personal'),
  ]);

  const expanded = flattenFolderTree(roots, new Set());
  assert.deepEqual(
    expanded.map((row) => [row.folder.id, row.depth]),
    [['work', 0], ['email', 1], ['archive', 2], ['personal', 0]]
  );

  const collapsed = flattenFolderTree(roots, new Set(['work']));
  assert.deepEqual(
    collapsed.map((row) => [row.folder.id, row.depth]),
    [['work', 0], ['personal', 0]]
  );
});
