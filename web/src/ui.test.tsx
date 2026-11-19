import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,it,expect} from 'vitest';
import {CopyButton,Ctx,Tabs,type Context} from './ui';

describe('shared keyboard and form controls',()=>{
 it('copying a value does not submit the surrounding form',()=>{
  const context={notify:()=>{}} as unknown as Context;
  const html=renderToStaticMarkup(<Ctx.Provider value={context}><form><CopyButton value="example"/></form></Ctx.Provider>);
  expect(html).toContain('type="button"');
  expect(html).not.toContain('type="submit"');
 });
 it('provides one keyboard tab stop for the selected tab',()=>{
  const html=renderToStaticMarkup(<Tabs items={['Evidence','Notes','Reports']} value="Notes" onChange={()=>{}}/>);
  expect(html.match(/tabindex="0"/g)).toHaveLength(1);
  expect(html.match(/tabindex="-1"/g)).toHaveLength(2);
  expect(html).toMatch(/aria-selected="true" tabindex="0"[^>]*>Notes/);
 });
});
