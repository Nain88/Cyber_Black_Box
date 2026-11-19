import {describe,it,expect,vi,afterEach} from 'vitest';
import {api,bytes,utc,routeQuery,parseJson,caseLabel,statusTone} from './lib';
describe('evidence display helpers',()=>{
 it('distinguishes cases with the same title and version',()=>{const first={id:'case-one',title:'Failed login',version:7,created_at:'2026-11-14T10:00:00Z'};const second={...first,id:'case-two'};expect(caseLabel(first)).not.toBe(caseLabel(second));expect(caseLabel(first)).toContain('case-one');expect(caseLabel(first)).toContain('UTC');});
 it('does not confuse missing values with zero measurements',()=>{expect(bytes(null)).toBe('Unknown');expect(bytes(0)).toBe('0 B');expect(utc(null)).toBe('Unknown');expect(utc('invalid')).toBe('Unknown');});
 it('retains timezone information and safe filter encoding',()=>{expect(utc('2026-10-29T00:00:00Z')).toContain('UTC');expect(routeQuery('/evidence',{q:'a&b',source:''})).toBe('/evidence?q=a%26b');});
 it('handles absent optional JSON without crashing a screen',()=>{expect(parseJson(undefined,[])).toEqual([]);expect(parseJson('{bad',[])).toEqual([]);expect(parseJson('{"n":1}')).toEqual({n:1});});
});

describe('status presentation',()=>{
 it('does not mistake negative or incomplete states for success',()=>{
  for(const status of ['INACTIVE','INCOMPLETE','NOT_VALID','NOT_SEALED']) expect(statusTone(status)).not.toBe('green');
  expect(statusTone('INVALID')).toBe('red');
 });
 it('recognizes mixed-case pending and valid results',()=>{
  expect(statusTone('Unanchored')).toBe('amber');
  expect(statusTone('PARTIAL')).toBe('amber');
  expect(statusTone('Valid')).toBe('green');
 });
});


describe('cancelled workspace requests',()=>{
 afterEach(()=>vi.unstubAllGlobals());
 it('passes cancellation to fetch and preserves the abort error',async()=>{
  const controller=new AbortController();
  const fetchMock=vi.fn((_url:string,options:RequestInit)=>new Promise((_resolve,reject)=>{
   options.signal?.addEventListener('abort',()=>reject(new DOMException('Request cancelled','AbortError')),{once:true});
  }));
  vi.stubGlobal('fetch',fetchMock);
  const request=api('/cases/first','GET',undefined,controller.signal);
  const rejected=expect(request).rejects.toMatchObject({name:'AbortError'});
  controller.abort();
  await rejected;
  expect(fetchMock).toHaveBeenCalledWith('/api/v1/cases/first',expect.objectContaining({signal:controller.signal,credentials:'same-origin'}));
 });
});
