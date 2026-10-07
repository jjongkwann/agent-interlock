import assert from 'node:assert/strict';
import test from 'node:test';
import {compareBundleRequest} from '../app/deployment.mjs';

test('comparison sends the same exact input and rejects mismatched review contexts', async () => {
  const input = {name:'Ada\r\n', nested:{value:3}};
  const response = {kind:'LOCAL_JSON_COMPARISON',mode:'ENFORCE',input,targetId:'target',tenantId:'tenant',candidate:{bundleDigest:'sha256:candidate'},baseline:{bundleDigest:'sha256:base'}};
  let requests = 0;
  const call = async (path, init) => {
    requests += 1;
    assert.equal(path,'/v1/bundles/sha256%3Acandidate/compare');
    assert.equal(init.method,'POST');
    assert.deepEqual(JSON.parse(init.body),{input,baseDigest:'sha256:base'});
    return response;
  };
  assert.equal(await compareBundleRequest(call,'sha256:candidate','sha256:base',JSON.stringify(input),'target','tenant'),response);
  for (const text of ['null','[]','true','invalid']) {
    await assert.rejects(compareBundleRequest(call,'sha256:candidate','sha256:base',text,'target','tenant'));
  }
  assert.equal(requests,1);
  for (const patch of [{targetId:'other'},{tenantId:'other'},{candidate:{bundleDigest:'other'}},{baseline:null},{mode:'SHADOW'}]) {
    await assert.rejects(compareBundleRequest(async()=>({...response,...patch}),'sha256:candidate','sha256:base',JSON.stringify(input),'target','tenant'),/context changed/);
  }
  const first = {...response,baseline:null};
  assert.equal(await compareBundleRequest(async()=>first,'sha256:candidate',null,'{}','target','tenant'),first);
  await assert.rejects(compareBundleRequest(async()=>{throw new Error('COMPARISON-UNSUPPORTED: task http requires LOCAL JSON_TRANSFORM');},'sha256:candidate',null,'{}','target','tenant'),/requires LOCAL JSON_TRANSFORM/);
});
