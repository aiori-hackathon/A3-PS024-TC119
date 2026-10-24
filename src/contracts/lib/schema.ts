// Dependency-free validator for our explicitly bounded JSON Schema subset.
// Not a general JSON Schema implementation; generation + Ajv parity tests are required.
export type Schema = {
  $schema?: string; $id?: string; type?: string; const?: unknown; enum?: unknown[];
  oneOf?: Schema[]; properties?: Record<string, Schema>; required?: string[];
  additionalProperties?: false; items?: Schema; minItems?: number; maxItems?: number;
  minLength?: number; maxLength?: number; pattern?: string; minimum?: number; maximum?: number;
};
export class ContractError extends Error {
  readonly code:string;
  constructor(code: string) { super(code); this.code=code; this.name = 'ContractError'; }
}
const plain = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)
  && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const checked=new WeakSet<object>();
export function deepFreeze<T>(value:T):T {
  if(value && typeof value==='object' && !Object.isFrozen(value)) {
    for(const child of Object.values(value))deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
const keywords=new Set(['$schema','$id','type','const','enum','oneOf','properties','required','additionalProperties','items','minItems','maxItems','minLength','maxLength','pattern','minimum','maximum']);
export function assertSupportedSchema(schema:Schema):void {
  if(checked.has(schema))return;
  if(Object.keys(schema).some(k=>!keywords.has(k)))throw new ContractError('unsupported-schema-keyword');
  if(schema.oneOf && Object.keys(schema).some(k=>!['$schema','$id','oneOf'].includes(k)))throw new ContractError('unsupported-schema-composition');
  if(Object.hasOwn(schema,'const') && schema.const!==null && typeof schema.const==='object')throw new ContractError('unsupported-schema-const');
  for(const child of schema.oneOf??[])assertSupportedSchema(child);
  for(const child of Object.values(schema.properties??{}))assertSupportedSchema(child);
  if(schema.items)assertSupportedSchema(schema.items);
  deepFreeze(schema);
  checked.add(schema);
}
export function conforms(schema: Schema, value: unknown, depth = 0): boolean {
  if (depth > 40) return false;
  if (schema.oneOf) return schema.oneOf.filter((s) => conforms(s,value,depth+1)).length === 1;
  if (Object.hasOwn(schema,'const') && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  switch (schema.type) {
    case 'object':
      if (!plain(value)) return false;
      if (schema.required?.some((k)=>!Object.hasOwn(value,k))) return false;
      if (schema.additionalProperties === false && Object.keys(value).some((k)=>!Object.hasOwn(schema.properties ?? {},k))) return false;
      return Object.entries(schema.properties ?? {}).every(([k,s])=>!Object.hasOwn(value,k)||conforms(s,value[k],depth+1));
    case 'array':
      return Array.isArray(value) && value.length >= (schema.minItems ?? 0) && value.length <= (schema.maxItems ?? Infinity)
        && value.every(v=>conforms(schema.items ?? {},v,depth+1));
    case 'string':
      return typeof value === 'string' && value.length >= (schema.minLength ?? 0) && value.length <= (schema.maxLength ?? Infinity)
        && (!schema.pattern || new RegExp(schema.pattern).test(value));
    case 'number': case 'integer':
      return typeof value === 'number' && Number.isFinite(value) && (schema.type !== 'integer' || Number.isSafeInteger(value))
        && value >= (schema.minimum ?? -Infinity) && value <= (schema.maximum ?? Infinity);
    case 'boolean': return typeof value === 'boolean';
    case undefined: return true;
    default: throw new ContractError('unsupported-schema-type');
  }
}
export function assertSchema(schema: Schema, value: unknown): void {
  assertSupportedSchema(schema);
  if (!conforms(schema,value)) throw new ContractError('schema-invalid');
}
