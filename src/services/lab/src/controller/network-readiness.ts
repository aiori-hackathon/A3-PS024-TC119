import { networkInterfaces } from 'node:os';
import type { DockerProject, DockerCli } from './docker.ts';
import type { ReadinessCheck } from './preflight.ts';
const baselineNetworks: Record<string,string> = { client_proxy:'172.28.10.0/24',proxy_issuer:'172.28.20.0/24',proxy_gateway:'172.28.30.0/24',gateway_replay:'172.28.40.0/24',gateway_origin:'172.28.50.0/24' };
const baselineMembership: Record<string,Record<string,string>> = {
  proxy: { client_proxy:'172.28.10.2', proxy_issuer:'172.28.20.2', proxy_gateway:'172.28.30.2' },
  issuer: { proxy_issuer:'172.28.20.10' },
  gateway: { proxy_gateway:'172.28.30.10', gateway_replay:'172.28.40.20', gateway_origin:'172.28.50.20' },
  redis: { gateway_replay:'172.28.40.10' },
  'protected-origin': { gateway_origin:'172.28.50.10' },
  'client-a': { client_proxy:'172.28.10.11' },
  'client-b': { client_proxy:'172.28.10.12' },
  'client-c': { client_proxy:'172.28.10.13' },
  'client-d': { client_proxy:'172.28.10.14' },
  'client-e': { client_proxy:'172.28.10.15' },
};
const sameKeys = (actual:object, expected:object) => Object.keys(actual).sort().join(',') === Object.keys(expected).sort().join(',');
function range(cidr:string): [number,number] | null {
  const m=/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(cidr); if(!m)return null;
  const octets=m.slice(1,5).map(Number), bits=Number(m[5]);
  if(octets.some(n=>n>255)||bits>32)return null;
  const value=octets.reduce((n,b)=>n*256+b,0), size=2**(32-bits), start=Math.floor(value/size)*size;
  return [start,start+size-1];
}
export function overlaps(a:string,b:string):boolean {
  const x=range(a),y=range(b);return !!x&&!!y&&x[0]<=y[1]&&y[0]<=x[1];
}
export function checkNetworkConfiguration(config: any, deployed: readonly any[], hostCidrs: readonly string[]):ReadinessCheck[] {
  const regional = Object.hasOwn(config.networks ?? {}, 'arc_private');
  const expected = { ...baselineNetworks, ...(regional ? { arc_private:'172.28.60.0/24' } : {}) };
  const membership = {
    ...baselineMembership,
    ...(regional ? {
      issuer: { ...baselineMembership.issuer, arc_private:'172.28.60.20' },
      gateway: { ...baselineMembership.gateway, arc_private:'172.28.60.30' },
      arc: { arc_private:'172.28.60.10' },
    } : {}),
  };
  const configured = sameKeys(config.networks ?? {}, expected) && Object.entries(expected).every(([name,subnet]) => {
    const network = config.networks[name];
    return network.internal === true && network.enable_ipv6 === false && network.driver === 'bridge'
      && network.ipam?.config?.length === 1 && network.ipam.config[0].subnet === subnet;
  }) && sameKeys(config.services ?? {}, membership) && Object.entries(membership).every(([name, networks]) => {
    const service = config.services[name];
    const profiles = service.profiles ?? [];
    return (!service.ports || Array.isArray(service.ports) && service.ports.length === 0)
      && service.network_mode === undefined
      && sameKeys(service.networks ?? {}, networks)
      && Object.entries(networks).every(([network, address]) => service.networks[network]?.ipv4_address === address)
      && Array.isArray(profiles) && (name === 'arc' ? profiles.length === 1 && profiles[0] === 'regional' : profiles.length === 0);
  });
  const foreign=deployed.filter(n=>n.Labels?.['com.docker.compose.project']!=='tokenforge').flatMap(n=>n.IPAM?.Config??[]).map(n=>n.Subnet).filter((s:unknown):s is string=>typeof s==='string');
  const conflicts=[...foreign,...hostCidrs].some(c=>Object.values(expected).some(e=>overlaps(c,e)));
  return [
    {check:'expected-private-topology',ok:configured,...(configured?{}:{action:'Restore the fixed baseline topology and its private ARC addition, including the regional service profile and no published ports'})},
    {check:'obvious-subnet-conflicts',ok:!conflicts,...(!conflicts?{}:{action:'Resolve overlapping host interfaces or foreign Docker networks before deployment'})},
  ];
}
export async function networkReadiness(project:DockerProject,cli:DockerCli):Promise<ReadinessCheck[]> {
  try {
    const config=await project.compose(['--profile','*','config','--format','json'],{timeoutMs:30_000});
    const listing=await cli.run(['network','ls','-q'],{timeoutMs:10_000});
    if(config.status!==0||listing.status!==0)throw Error();
    const ids=listing.stdout.trim().split(/\s+/).filter(Boolean);
    if(ids.length>128||ids.some(id=>!/^[0-9a-f]{12,64}$/.test(id)))throw Error();
    const inventory=ids.length?await cli.run(['network','inspect',...ids],{timeoutMs:20_000}):{status:0,stdout:'[]'};
    if(inventory.status!==0)throw Error();
    const host=Object.values(networkInterfaces()).flatMap(v=>v??[]).filter(v=>!v.internal&&v.family==='IPv4').map(v=>v.cidr).filter((v):v is string=>!!v);
    return checkNetworkConfiguration(JSON.parse(config.stdout),JSON.parse(inventory.stdout),host);
  } catch {return [{check:'network-inventory',ok:false,action:'Restore Docker network inspection and Compose JSON access; run the deeper deployed network checker'}];}
}
