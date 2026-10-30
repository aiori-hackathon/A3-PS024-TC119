# Reset safety utility

Public controller import: `src/security/reset-barrier.ts`. This Node 24 TypeScript module uses only Node built-ins and the frozen shared contract; it does not import gateway or lab private source. Krish owns the utility and its tests. Mihir owns the controller's Docker/control adapters, exclusive project lock, monitoring and fresh setup.

```ts
const barrier = ResetBarrier.prepare(oldGeneration, adapters);
const receipt = await barrier.fenceAll();
await barrier.discardOldRedis(receipt);
```

This sequence prevents the utility from invoking its Redis-discard adapter until all expected old participants are proven stopped. It does not create a new run, manage Docker, establish controller exclusivity or authorize enabling new services. See the [integration contract](../../docs/implementation/RESET_RECOVERY.md) for required target identities, adapter evidence and failure handling.

Run `node --test src/security/test/reset-barrier.test.ts` from the repository root. `npm run check:g0` includes these tests and the gateway compiler checks this module. No new package dependencies or root workspace are required.
