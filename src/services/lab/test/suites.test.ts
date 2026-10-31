import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SUITES, type RunPlan } from '../src/controller/suites.ts';
import { REDIS_FAULT_SCENARIOS } from '../src/controller/orchestrated.ts';

const protocol = JSON.parse(readFileSync(new URL('../../../contracts/protocol-v1.json', import.meta.url), 'utf8')) as { suite_required_scenarios: Record<string, string[]>; scenario_ids: string[] };

/** The scenario ids a plan's steps produce, derived from the plan alone. */
function ids(plan: RunPlan): string[] {
  return plan.steps.flatMap((s) => {
    if ('scenario' in s) return [s.scenario];
    if ('orchestrated' in s) return [REDIS_FAULT_SCENARIOS[s.orchestrated]?.id ?? s.orchestrated];
    return ['restart-and-reset']; // the captured half belongs to the same scenario as the new-generation run that consumes it
  });
}

for (const [kind, name] of [['demo', 'demo'], ['security', 'security'], ['benchmark', 'performance']] as const) {
  test(`the ${name} suite covers exactly the scenarios the frozen protocol requires for ${kind}`, () => {
    assert.equal(SUITES[name]!.kind, kind);
    const covered = new Set(SUITES[name]!.plans.flatMap(ids));
    const required = new Set(protocol.suite_required_scenarios[kind]!);
    assert.deepEqual([...required].filter((r) => !covered.has(r)), [], 'missing');
    assert.deepEqual([...covered].filter((c) => !required.has(c)), [], 'extra');
  });
}

test('every scenario a suite names is a frozen scenario id; every plan stays inside the security client inventory', () => {
  for (const [name, def] of Object.entries(SUITES)) for (const plan of def.plans) {
    for (const id of ids(plan)) assert.ok(protocol.scenario_ids.includes(id), `${name}/${plan.name}: ${id}`);
    const limit = { demo: 10, security: 128, benchmark: 16384 }[plan.clientProfile];
    assert.ok(plan.perClient <= limit && plan.perClient * 5 + (plan.harnessVouchers ?? 0) <= 128 * 5, `${name}/${plan.name} vouchers`);
    if (plan.clientProfile === 'security') assert.ok(plan.perClient * 5 + (plan.harnessVouchers ?? 0) <= 128, `${name}/${plan.name} total inventory`);
  }
});
