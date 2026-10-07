export function compileDraftRequest(call, rawArchitecture) {
  return call('/v1/architectures/compile', {method: 'POST', body: rawArchitecture});
}

export async function compareBundleRequest(call, bundleDigest, baseDigest, inputText, targetId, tenantId) {
  const input = JSON.parse(inputText);
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Comparison input must be a JSON object");
  const body = await call(`/v1/bundles/${encodeURIComponent(bundleDigest)}/compare`, {
    method: "POST", body: JSON.stringify({input, baseDigest}),
  });
  if (body.kind !== "LOCAL_JSON_COMPARISON" || body.mode !== "ENFORCE" || body.candidate?.bundleDigest !== bundleDigest ||
      (body.baseline?.bundleDigest ?? null) !== baseDigest || body.targetId !== targetId || body.tenantId !== tenantId) {
    throw new Error("Comparison context changed. Refresh deployment status before comparing again.");
  }
  return body;
}
