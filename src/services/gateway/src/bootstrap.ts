// G0 build/runtime smoke entry only. No listener or authorization service exists yet.
import { CONTRACT_VERSION, configurationDigest, gatewayLimits } from '../../../contracts/lib/index.ts';
console.log(JSON.stringify({
  component: 'gateway-contract-bootstrap',
  contract_version: CONTRACT_VERSION,
  node_major: Number(process.versions.node.split('.')[0]),
  profiles_digest: configurationDigest({ B0: gatewayLimits('B0'), B1: gatewayLimits('B1') }),
}));
