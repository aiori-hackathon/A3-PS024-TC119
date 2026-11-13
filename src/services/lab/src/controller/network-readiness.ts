import { networkInterfaces } from 'node:os';
import type { DockerProject, DockerCli } from './docker.ts';
import type { ReadinessCheck } from './preflight.ts';
const expected: Record<string,string> = { client_proxy:'172.28.10.0/24',proxy_issuer:'172.28.20.0/24',proxy_gateway:'172.28.30.0/24',gateway_replay:'172.28.40.0/24',gateway_origin:'172.28.50.0/24' };
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
  const configured=Object.keys(config.networks??{}).length===5 && Object.entries(expected).every(([name,subnet])=>{
    const n=config.networks?.[name];return n?.internal===true && n.enable_ipv6!==true && n.ipam?.config?.length===1 && n.ipam.config[0].subnet===subnet;
  }) && Object.values(config.services??{}).length===10 && Object.values(config.services??{}).every((s:any)=>!s.ports?.length && !['host','service:gateway'].includes(s.network_mode));
  const foreign=deployed.filter(n=>n.Labels?.['com.docker.compose.project']!=='tokenforge').flatMap(n=>n.IPAM?.Config??[]).map(n=>n.Subnet).filter((s:unknown):s is string=>typeof s==='string');
  const conflicts=[...foreign,...hostCidrs].some(c=>Object.values(expected).some(e=>overlaps(c,e)));
  return [
    {check:'expected-private-topology',ok:configured,...(configured?{}:{action:'Restore the five internal fixed subnets, ten services and no published ports in infra/compose.yaml'})},
    {check:'obvious-subnet-conflicts',ok:!conflicts,...(!conflicts?{}:{action:'Resolve overlapping host interfaces or foreign Docker networks before deployment'})},
  ];
}
export async function networkReadiness(project:DockerProject,cli:DockerCli):Promise<ReadinessCheck[]> {
  try {
    const config=await project.compose(['config','--format','json'],{timeoutMs:30_000});
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
