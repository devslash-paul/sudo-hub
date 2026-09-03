const content = document.querySelector('#content');
const message = document.querySelector('#message');
let approvalBusy = false;
let requestFingerprint = null;
const enc = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4-value.length%4)%4)), c => c.charCodeAt(0));
const dec = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const post = async (path, value) => {
  const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(value)});
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || 'Request failed');
  return body;
};

async function enroll() {
  try {
    approvalBusy = true;
    message.textContent = 'Waiting for your device…';
    const enrollmentToken = document.querySelector('#enrollment-token').value;
    const options = await post('/api/register/options', {enrollmentToken});
    const ceremonyId = options.ceremonyId; delete options.ceremonyId;
    options.challenge = enc(options.challenge); options.user.id = enc(options.user.id);
    const credential = await navigator.credentials.create({publicKey: options});
    await post('/api/register/verify', {ceremonyId, credential:{
      id: credential.id,
      clientDataJSON: dec(credential.response.clientDataJSON),
      attestationObject: dec(credential.response.attestationObject)
    }});
    message.textContent = 'Passkey enrolled.'; await render();
  } catch (error) { message.textContent = error.message; }
  finally { approvalBusy = false; }
}

const setDisabled = (buttons, disabled) => buttons.forEach(button => { button.disabled = disabled; });

async function decide(id, decision, buttons) {
  try {
    approvalBusy = true;
    setDisabled(buttons, true);
    message.textContent = `Confirm ${decision === 'approve' ? 'approval' : 'denial'} with Face ID or your device unlock…`;
    const options = await post(`/api/${decision}/options`, {requestId:id});
    const ceremonyId = options.ceremonyId; delete options.ceremonyId;
    options.challenge = enc(options.challenge);
    options.allowCredentials = options.allowCredentials.map(c => ({...c, id:enc(c.id)}));
    const credential = await navigator.credentials.get({publicKey:options});
    await post(`/api/${decision}/verify`, {requestId:id, ceremonyId, assertion:{
      id:credential.id,
      clientDataJSON:dec(credential.response.clientDataJSON),
      authenticatorData:dec(credential.response.authenticatorData),
      signature:dec(credential.response.signature)
    }});
    message.textContent = decision === 'approve' ? 'Approved and completed.' : 'Request denied.';
    await render();
  } catch (error) { setDisabled(buttons, false); message.textContent = error.message; }
  finally { approvalBusy = false; }
}

async function enableNotifications(button) {
  try {
    approvalBusy=true;
    button.disabled=true; message.textContent='Confirm notification access and your passkey…';
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) throw new Error('Add this site to the iPhone Home Screen, then open it from its icon.');
    const registration=await navigator.serviceWorker.register('/sw.js');
    const permission=await Notification.requestPermission();
    if (permission !== 'granted') throw new Error('Notification permission was not granted.');
    const key=await (await fetch('/api/push/key')).json();
    let subscription=await registration.pushManager.getSubscription();
    if (!subscription) subscription=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:enc(key.publicKey)});
    const options=await post('/api/push/options',{});
    const ceremonyId=options.ceremonyId; delete options.ceremonyId;
    options.challenge=enc(options.challenge);
    options.allowCredentials=options.allowCredentials.map(c=>({...c,id:enc(c.id)}));
    const credential=await navigator.credentials.get({publicKey:options});
    await post('/api/push/subscribe',{ceremonyId,subscription:subscription.toJSON(),assertion:{
      id:credential.id, clientDataJSON:dec(credential.response.clientDataJSON),
      authenticatorData:dec(credential.response.authenticatorData), signature:dec(credential.response.signature)
    }});
    message.textContent='Mobile notifications enabled.'; button.textContent='Notifications enabled';
  } catch(error) { button.disabled=false; message.textContent=error.message; }
  finally { approvalBusy=false; }
}

function card(request) {
  const section = document.createElement('section'); section.className = 'card';
  const head=document.createElement('div'); head.className='card-head';
  const title = document.createElement('h2'); title.textContent = request.operation.split('.').map(word=>word[0].toUpperCase()+word.slice(1)).join(' ');
  const target=document.createElement('span'); target.className='target'; target.textContent=request.target;
  head.append(title,target); section.append(head);
  const isLease=['container.command.lease','command.lease','approval.batch'].includes(request.operation);
  if (request.operation === 'admin.command' || request.operation === 'container.admin.command') {
    section.classList.add('high-risk');
    const warning=document.createElement('p'); warning.className='warning';
    warning.textContent='HIGH RISK — this exact command will run as root. Verify every argument.';
    section.append(warning);
  }
  if (isLease) {
    section.classList.add('lease-card');
    const warning=document.createElement('p'); warning.className='lease-note';
    const count=request.operation === 'approval.batch' ? request.parameters.requests.length : request.parameters.max_commands;
    warning.textContent=`Temporary allowance: ${count} ${request.operation === 'approval.batch' ? 'exact listed operations' : 'root commands whose arguments are not pre-listed'} for ${request.parameters.duration} seconds. It applies only to this task on ${request.target}.`;
    section.append(warning);
  }
  const details = document.createElement('dl');
  for (const [label, value] of [['Target',request.target],['Task',request.task_id],['Request source',request.host],['Requester',request.requester],['Created',new Date(request.created_at*1000).toLocaleString()]]) {
    if (!value) continue;
    const dt=document.createElement('dt'), dd=document.createElement('dd'); dt.textContent=label; dd.textContent=value; details.append(dt,dd);
  }
  const pre=document.createElement('pre'); pre.textContent=JSON.stringify(request.parameters,null,2);
  const actions=document.createElement('div'); actions.className='actions';
  const approve=document.createElement('button'); approve.className='approve'; approve.textContent=isLease ? '✓  Allow this task temporarily' : '✓  Approve with Face ID';
  const deny=document.createElement('button'); deny.className='deny'; deny.textContent='×  Deny request';
  const buttons=[approve,deny]; approve.onclick=()=>decide(request.id,'approve',buttons); deny.onclick=()=>decide(request.id,'deny',buttons);
  actions.append(approve,deny); section.append(details,pre,actions); return section;
}

async function render() {
  try {
    const status = await (await fetch('/api/status')).json(); content.replaceChildren();
    if (!status.enrolled) {
      const section=document.createElement('section'); section.className='card';
      section.innerHTML='<h2>Enroll this device</h2><p>Enter the one-time code shown by the broker.</p><input id="enrollment-token" autocomplete="one-time-code" placeholder="Enrollment code" style="box-sizing:border-box;width:100%;padding:1rem;margin:.6rem 0 1rem;border-radius:.8rem;border:1px solid #52665a;background:#0c110e;color:#fff;font-size:1rem">';
      const button=document.createElement('button'); button.textContent='Create passkey'; button.onclick=enroll; section.append(button); content.append(section); return;
    }
    const requests=await (await fetch('/api/requests')).json();
    requestFingerprint=JSON.stringify(requests.map(request=>[request.id,request.state]));
    if (!requests.length) { const p=document.createElement('p'); p.className='card muted empty'; p.textContent='✓ No operations are waiting for approval.'; content.append(p); }
    else requests.forEach(request => content.append(card(request)));
    const notify=document.createElement('button'); notify.className='secondary';
    notify.textContent=status.pushSubscriptions ? 'Enable notifications on this device' : 'Enable mobile notifications';
    notify.onclick=()=>enableNotifications(notify); content.append(notify);
  } catch (error) { message.textContent=error.message; }
}

async function refreshIfChanged() {
  if (approvalBusy || document.visibilityState !== 'visible') return;
  try {
    const requests=await (await fetch('/api/requests',{cache:'no-store'})).json();
    const next=JSON.stringify(requests.map(request=>[request.id,request.state]));
    if (next !== requestFingerprint) await render();
  } catch(error) { /* The next poll retries without disrupting an approval. */ }
}

document.addEventListener('visibilitychange',()=>{ if(document.visibilityState==='visible') refreshIfChanged(); });
window.addEventListener('focus',refreshIfChanged);
setInterval(refreshIfChanged,2000);
render();
