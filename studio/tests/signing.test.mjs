import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {compileDraftRequest} from '../app/deployment.mjs';
import {signApproval,canonicalStatement} from '../app/signing.mjs';

test('browser WebCrypto approval matches Python canonical bytes and Ed25519 verifier', async()=>{
  const statement={purpose:'studio-architecture-deploy',targetId:'test-deployment',tenantId:'tenant-local',architectureId:'local-transform',bundleDigest:'sha256:'+'a'.repeat(64),fromDigest:null,toMode:'ENFORCE'};
  const approver={approverId:'reviewer-é',keyId:'reviewer-1',publicKeyHex:'d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'};
  const seed=Uint8Array.from(Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60','hex'));
  const signed=await signApproval(seed,statement,approver);
  assert.ok(seed.every(b=>b===0));
  const python=spawnSync('../.venv/bin/python',['-c',`import json,sys\nfrom agent_interlock.canonical import canonical_json\nfrom agent_interlock.studio_deploy import DeploymentBundle,approval_signature_statement\nfrom cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey\nv=json.load(sys.stdin)\ns=v['statement']\nexpected=approval_signature_statement(DeploymentBundle(s['architectureId'],'1',s['bundleDigest'],{}),from_digest=s['fromDigest'],to_mode=s['toMode'],target_id=s['targetId'],tenant_id=s['tenantId'],approver_id=s['approverId'],key_id=s['keyId'])\nassert expected==s\npayload=canonical_json(expected)\nEd25519PublicKey.from_public_bytes(bytes.fromhex(v['publicKey'])).verify(bytes.fromhex(v['signature'].split(':')[1]),payload)\nprint(payload.decode())`],{input:JSON.stringify({statement:{...statement,approverId:approver.approverId,keyId:approver.keyId},publicKey:approver.publicKeyHex,signature:signed.signature}),encoding:'utf8'});
  assert.equal(python.status,0,python.stderr);
  assert.equal(python.stdout.trim(),canonicalStatement({...statement,approverId:approver.approverId,keyId:approver.keyId}));
  assert.equal(canonicalStatement({'\u{10000}':'e\u0301\r\nx','\uE000':'z'}),' {"":"z","𐀀":"é\\nx"}'.trim());
  await assert.rejects(signApproval(new Uint8Array(32),statement,approver),/does not match/);
});

test('local Studio starter compiles with configured runtime digest pins and no lint findings', async()=>{
  const {localTransformStarter}=await import('../app/architecture-model.ts');
  const manifest=localTransformStarter('browser-starter','message');
  const python=spawnSync('../.venv/bin/python',['-c',`import json,sys\nfrom agent_interlock.architecture import ArchitectureGraph,ArchitectureLinter\nfrom agent_interlock.configurable_runtime import prepare_runtime_graph\ng=prepare_runtime_graph(ArchitectureGraph.from_dict(json.load(sys.stdin)))\nassert not ArchitectureLinter().lint(g), ArchitectureLinter().lint(g)\nassert g.node_map['transform'].actor.definition_digest`],{input:JSON.stringify(manifest),encoding:'utf8'});
  assert.equal(python.status,0,python.stderr);
});


test('Studio compile request crosses the real HTTP API with the raw Architecture body', async()=>{
  const {localTransformStarter}=await import('../app/architecture-model.ts');
  const raw=JSON.stringify(localTransformStarter('http-starter','message'));
  await compileDraftRequest(async (path,init)=>{
    const python=spawnSync('../.venv/bin/python',['-c',`import json,sys,tempfile\nfrom pathlib import Path\nsys.path.insert(0,str(Path('../tests').resolve()))\nfrom test_control_plane import RunningControlPlane\nrequest=json.load(sys.stdin)\nwith tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:\n status,body=plane.request(request['method'],request['path'],body=json.loads(request['body']))\n assert status==200,(status,body)\n assert body['deployable'] is True,body\n assert json.loads(body['rawBundle'])['bundleDigest']==body['bundleDigest']\n print(json.dumps(body))`],{input:JSON.stringify({path,...init}),encoding:'utf8'});
    assert.equal(python.status,0,python.stderr);
    const response=JSON.parse(python.stdout);
    assert.equal(response.architectureId,'http-starter');
    return response;
  },raw);
});
