# TokenForge regional handover

The local three-profile comparison, separate holder scene, ARC quota/copy diagnostics and lifecycle checks are complete. [Aggregate evidence and retained partial trials](../../implementation/REGIONAL_FINAL_EVIDENCE.md) describe the measured scope. The application code checkpoint is `628c371`, and the ARC binary source identity is `05fbb2a`.

## Presentation material

- [Regional presentation](TokenForge-Regional-2026.pptx) has eight editable slides and speaker notes. It was rendered and structurally checked with Artifact Tool. Native PowerPoint review remains a human rehearsal task.
- [Recorded ARC access and reset](RECORDED-ARC-access-reset.webm) is a 25-second silent fallback made from actual screen frames at one frame per second. It shows allowance acquisition, protected-resource delivery, independent evidence and reset. The complete comparison and holder evidence are documented separately. Label it recorded evidence when presenting.
- [Seven-minute narration](../../demo/REGIONAL_NARRATION.md) covers the evaluator sequence and explicit trust/privacy limits.
- [Laptop runbook](../../lab/REGIONAL_RUNBOOK.md) covers setup, preflight, launch, expiry, reset, shutdown, certificate rotation and retained uncertainty.

Original submission PDFs and original video links remain preserved.

## Artifact integrity

| Artifact | SHA-256 |
| --- | --- |
| Regional PPTX | `b7ee4178c49770a632fbf4a1b84dc88b45dea100aeff57643730c3699ac3e099` |
| Recorded WebM | `5e05cc582a9d78b89bff88568ce76a893919f7f0e060d1605d1fb78430036194` |

## Laptop state and launch

The handover leaves a fresh idle loopback portal at `http://127.0.0.1:4174/`. Test generations are fenced/reset, Redis has been discarded and the Compose test project is cleaned. Images and ignored local secrets remain available for the next demonstration. The first selected experiment recreates the private services.

To launch again from a clean terminal, use Node 24.22.1 and Docker Desktop Linux containers.

```powershell
node src/services/lab/src/controller/cli.ts regional --port 4174
```

If port 4174 is occupied, reuse the existing idle portal or close its controller after confirmed reset. The runbook documents normal Ctrl+C shutdown from an interactive launch. Keep all control, Redis, origin and ARC sockets private.

## Remaining human work

- Rehearse live narration and team handoffs.
- Review the deck in the intended presentation application and confirm projector scaling.
- Record participant voice/video if required by the organizers.
- Confirm venue power, warmed Docker images and laptop readiness.
- Complete physical second-device rehearsal if required, and attend the venue.

The original heartbeat-20 receiver-time cause remains historically unconfirmed. Its sender-expiry dependency has been removed and the new receiver-owned lease has focused and deployed evidence. The controlled prototype retains the documented admission, clock/state trust, joint ARC operator and complete signed-request/private-key theft limitations.
