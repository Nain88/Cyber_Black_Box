import React from 'react';
import {PageHead, Panel, Notice} from './ui';

export function AttackLab() {
  const local = ['localhost', '127.0.0.1'].includes(window.location.hostname);
  return <>
    <PageHead eyebrow="WORKSPACE / PRIVATE LAB" title="Attack simulation lab" description="Start a bounded exercise, stop further requests, then investigate the observations captured on Kali."/>
    <Notice>Recommended first exercise: Failed sign-ins. Six invalid decoy logins produce a clear authentication trail. These are labelled lab observations; they do not prove a real intrusion.</Notice>
    <Panel><div className="panel-content">
      <h2>Simulation control room</h2>
      <p>The separate local controller provides Start simulation, Stop simulation, target connectivity and run history. Stop cancels remaining requests; a request already in progress may take four seconds to finish.</p>
      {local ? <a className="primary" href="http://127.0.0.1:8844" target="_blank" rel="noopener noreferrer">Open Start / Stop controls ↗</a> : <p>Open the controller on the Windows lab host at http://127.0.0.1:8844.</p>}
      <h3>Evidence workflow</h3>
      <ol><li>Start the instrumented Kali target and the Windows relay.</li><li>Open the controller and sign in with its separate operator password.</li><li>Start one scenario, or stop it before its remaining requests are sent.</li><li>Review lab.fixture records in Evidence explorer and the Kali Attack Lab case.</li></ol>
      <p>Controller request completion is separate from confirmed ingestion. Verify received evidence in Cloud Box. Setup instructions are in LAB-SETUP.md.</p>
    </div></Panel>
  </>;
}
