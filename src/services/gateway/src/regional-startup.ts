import { isIP } from 'node:net';
import { ContractError } from '../../../contracts/lib/index.ts';
import { validateRegionalPolicy, type RegionalPolicy } from '../../../contracts/lib/regional.ts';
import { validateArcBootstrap } from '../../../contracts/lib/regional-wire.ts';

// JSON-safe private stdin/IPC representation. Never include this object in status or reports.
export type RegionalStartup={policy:RegionalPolicy;auth:
  {profile:'arc';bootstrap:unknown;endpoint:{host:string;port:number};verify_key:string}|
  {profile:'type2-holder';context_key:string;nonce_key:string}|
  {profile:'type2-bearer'}|{profile:'ip';source_key:string}};
const record=(v:unknown):Record<string,unknown>=>{
  if(!v||typeof v!=='object'||Array.isArray(v))throw Error();return v as Record<string,unknown>;
};
const exact=(v:Record<string,unknown>,keys:string)=>{if(Object.keys(v).sort().join(',')!==keys)throw Error();};
const key=(v:unknown)=>{if(typeof v!=='string'||!/^[0-9a-f]{64}$/.test(v))throw Error();};
export function validateRegionalStartup(value:unknown):RegionalStartup{
  try{
    const r=record(structuredClone(value));exact(r,'auth,policy');
    const policy=validateRegionalPolicy(r['policy']),auth=record(r['auth']);
    if(auth['profile']!==policy.profile)throw Error();
    switch(policy.profile){
      case 'arc':{
        exact(auth,'bootstrap,endpoint,profile,verify_key');key(auth['verify_key']);
        const e=record(auth['endpoint']);exact(e,'host,port');
        if(typeof e['host']!=='string'||!(isIP(e['host'])||/^[a-z][a-z0-9-]{0,62}$/.test(e['host']))
          ||['0.0.0.0','::'].includes(e['host'])||!Number.isInteger(e['port'])||(e['port'] as number)<1||(e['port'] as number)>65535)throw Error();
        validateArcBootstrap(auth['bootstrap'],{run_id:policy.run_id,arc_implementation_revision:policy.arc_implementation_revision!});break;
      }
      case 'type2-holder':exact(auth,'context_key,nonce_key,profile');key(auth['context_key']);key(auth['nonce_key']);
        if(auth['context_key']===auth['nonce_key'])throw Error();break;
      case 'type2-bearer':exact(auth,'profile');break;
      case 'ip':exact(auth,'profile,source_key');key(auth['source_key']);break;
    }
    return {policy,auth} as RegionalStartup;
  }catch{throw new ContractError('regional-startup-invalid');}
}
