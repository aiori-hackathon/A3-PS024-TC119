// One controller per Compose project (plan section 5.5). The lock file is created exclusively and is NEVER removed on
// the strength of its contents: a stale file is not proof that the old controller, or the run it supervised, is gone.
// A replacement controller must fence and confirm the old roles itself, then an operator clears the file deliberately.
import { closeSync, openSync, readFileSync, rmSync, writeSync } from 'node:fs';

export class LockHeldError extends Error {
  constructor() { super('project-lock-held'); this.name = 'LockHeldError'; }
}
export type ProjectLock = { release(): void };

export function acquireProjectLock(path: string): ProjectLock {
  let fd: number;
  try { fd = openSync(path, 'wx', 0o600); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === 'EEXIST') throw new LockHeldError(); throw e; }
  const owner = JSON.stringify({ pid: process.pid, acquired_at_utc: new Date().toISOString().replace(/\.\d+Z$/, 'Z') });
  writeSync(fd, owner); closeSync(fd);
  let released = false;
  return {
    release() {
      if (released) return;
      released = true;
      // Only remove a lock this process created.
      try { if ((JSON.parse(readFileSync(path, 'utf8')) as { pid?: number }).pid === process.pid) rmSync(path); } catch { /* already gone */ }
    },
  };
}
