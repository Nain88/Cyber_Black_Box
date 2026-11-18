import React, {useEffect, useState} from 'react';
import {Pause, Play} from 'lucide-react';

// Decorative only: a fixed number of CSS tracks, with no animation timers.
export function SignalLines(){
 return <div className="signal-lines" aria-hidden="true">{Array.from({length:6},(_,i)=><span key={i}/>)}</div>;
}

export function MotionControl(){
 const [enabled,setEnabled]=useState(()=>{
  try{return localStorage.getItem('cbb-motion')!=='off'}catch{return true}
 });
 useEffect(()=>{
  document.documentElement.dataset.motion=enabled?'on':'off';
  try{localStorage.setItem('cbb-motion',enabled?'on':'off')}catch{/* Storage is optional. */}
 },[enabled]);
 useEffect(()=>{
  const update=()=>{document.documentElement.dataset.pageHidden=String(document.hidden)};
  update();document.addEventListener('visibilitychange',update);
  return()=>document.removeEventListener('visibilitychange',update);
 },[]);
 return <button className="icon-button motion-control" aria-label="Decorative animations" aria-pressed={enabled} title={enabled?'Pause decorative animations':'Enable decorative animations'} onClick={()=>setEnabled(v=>!v)}>{enabled?<Pause size={16}/>:<Play size={16}/>}<span>Motion</span></button>;
}
