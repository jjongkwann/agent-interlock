import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { after, before, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";
import { LANGUAGE_STORAGE_KEY, korean, message, resolveLanguage, translate } from "../app/i18n.ts";

const usedMessages = new Set();

let directory, Home, LanguageProvider, useLanguage, panels, builder, comparison, hostReadiness;
before(async () => {
  // Node's type stripping does not handle JSX; compile the real components with the existing compiler.
  directory = await mkdtemp(fileURLToPath(new URL("../.localization-", import.meta.url)));
  const components = (await readdir(new URL("../app/", import.meta.url))).filter(name => name.endsWith(".tsx") && name !== "layout.tsx").map(name => name.slice(0, -4));
  for (const name of components) {
    const source = await readFile(new URL(`../app/${name}.tsx`, import.meta.url), "utf8");
    const ast = ts.createSourceFile(`${name}.tsx`, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    function collect(node) {
      if (ts.isCallExpression(node) && ["t", "message"].includes(node.expression.getText(ast)) && ts.isStringLiteral(node.arguments[0])) usedMessages.add(node.arguments[0].text);
      ts.forEachChild(node, collect);
    }
    collect(ast);
    const { outputText } = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } });
    const code = outputText.replace(/import "[^"\n]+\.css";/g, "").replace(/from "([^"]+)"/g, (_, specifier) => {
      const component = components.find((name) => specifier === `./${name}`);
      let url;
      if (component) url = pathToFileURL(`${directory}/${component}.mjs`).href;
      else if (specifier.startsWith(".")) {
        url = new URL(`../app/${specifier}`, import.meta.url);
        if (!existsSync(url)) url = new URL(`${url}.ts`);
        url = url.href;
      } else url = import.meta.resolve(specifier);
      return `from ${JSON.stringify(url)}`;
    });
    await writeFile(`${directory}/${name}.mjs`, code);
  }
  ({ default: Home } = await import(pathToFileURL(`${directory}/page.mjs`)));
  ({ LanguageProvider, useLanguage } = await import(pathToFileURL(`${directory}/language.mjs`)));
  panels = await import(pathToFileURL(`${directory}/panels.mjs`));
  builder = await import(pathToFileURL(`${directory}/builder.mjs`));
  comparison = await import(pathToFileURL(`${directory}/comparison.mjs`));
  hostReadiness = await import(pathToFileURL(`${directory}/host-readiness.mjs`));
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

function render(language, component, props = {}) {
  return renderToStaticMarkup(createElement(LanguageProvider, { initialLanguage: language }, createElement(component, props)));
}

test("language preference overrides browser language and messages keep raw user values", () => {
  assert.equal(resolveLanguage(null, "ko-KR"), "ko");
  assert.equal(resolveLanguage("en", "ko-KR"), "en");
  assert.equal(resolveLanguage("ko", "en-US"), "ko");
  assert.equal(resolveLanguage("invalid", "fr-FR"), "en");
  const notice = message("{0} saved locally · v{1}", "Projects", "1.2.0");
  assert.equal(translate("ko", notice), "Projects 로컬 저장됨 · v1.2.0");
  assert.equal(translate("en", notice), "Projects saved locally · v1.2.0");
  for (const raw of ["CUSTOM-SERVER-CODE", "constructor", "__proto__"]) assert.equal(translate("ko", raw), raw);
  assert.equal(translate("ko", message("{0} observed relationships", 0)), "관측된 관계 0개");
  for (const [key, value] of Object.entries(korean)) {
    assert.ok(value.trim(), `Missing translation: ${key}`);
    for (const placeholder of value.match(/\{\d+\}/g) ?? []) assert.ok(key.includes(placeholder), `Unexpected placeholder: ${key}`);
  }
  for (const key of usedMessages) assert.ok(Object.hasOwn(korean, key), `Missing translation: ${key}`);
});

test("renders both languages without translating project values or policy option values", () => {
  const english = render("en", Home);
  const korean = render("ko", Home);
  assert.match(english, /Security Architecture Studio/);
  assert.match(korean, /보안 아키텍처 스튜디오/);
  for (const text of ["설계 그래프", "배포", "실행", "런타임 그래프", "드리프트", "통계", "매니페스트 내보내기", "정적 설계 준비 상태"]) assert.ok(korean.includes(text), text);
  assert.match(korean, /aria-label="언어"/);
  assert.match(korean, /value="ko"[^>]*selected/);
  assert.match(korean, /value="ENFORCE"[^>]*selected[^>]*>강제 적용 \(ENFORCE\)/);
  assert.match(korean, /value="FAIL_CLOSED"[^>]*selected[^>]*>실패 시 차단/);
  assert.match(korean, /title="도구 호출 인수"/);
  assert.match(korean, /Support Agent/);
  assert.match(korean, /value="customer-support-multi-agent"/);
  assert.match(korean, /마지막으로 불러온 번들: 불러오지 않음/);
  assert.doesNotMatch(korean, /Run security check|Export manifest|Static design readiness/);
});

test("localizes statistics, deployments, runs, and the actor runtime editor", () => {
  const noop = () => {};
  const common = { notify: noop, onContext: noop, apiUrl: "http://localhost:8792", token: "", onApiUrlChange: noop, onTokenChange: noop };
  assert.match(render("ko", panels.StatsPanel, { ...common, rawLedgerEvents: null, importedFormat: null, onImportTelemetry: noop, initialTraceId: "", ledgerConnection: { apiUrl: "", token: "", tenantId: "", rangeFrom: "", rangeTo: "" }, onLedgerConnection: noop }), /상호작용 조사/);
  assert.match(render("ko", panels.DeployPanel, { ...common, draftProject: { id: "my-agent", version: "1" }, rawArchitecture: "{}", onBackToDesign: noop }), /승인 컨텍스트 서명/);
  assert.match(render("ko", panels.RunsPanel, { ...common, onOpenStatisticsTrace: noop, onOpenRuntimeTelemetry: noop }), /실행 시작/);
  assert.match(render("ko", builder.RuntimeEditor, { node: { id: "tool.custom", type: "TOOL" }, update: noop }), /런타임 동작/);
  assert.match(render("ko", builder.Readiness, { value: { ready: false } }), /런타임 설정 필요/);
});

test("language selection saves only its preference and still works if storage is blocked", () => {
  let select;
  function Capture() { select = useLanguage().setLanguage; return null; }
  render("en", Capture);
  const previousWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const previousStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const values = new Map([["project", "untouched"]]);
  const window = new EventTarget();
  let changes = 0;
  window.addEventListener("interlock-language-change", () => changes++);
  Object.defineProperty(globalThis, "window", { configurable: true, value: window });
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { setItem: (key, value) => values.set(key, value) } });
  try {
    select("ko");
    assert.equal(values.get(LANGUAGE_STORAGE_KEY), "ko");
    select("en");
    assert.equal(values.get(LANGUAGE_STORAGE_KEY), "en");
    assert.equal(values.get("project"), "untouched");
    globalThis.localStorage.setItem = () => { throw new Error("Storage denied"); };
    assert.doesNotThrow(() => select("ko"));
    assert.equal(changes, 3);
  } finally {
    if (previousWindow) Object.defineProperty(globalThis, "window", previousWindow); else delete globalThis.window;
    if (previousStorage) Object.defineProperty(globalThis, "localStorage", previousStorage); else delete globalThis.localStorage;
  }
});


test("new tool, comparison, and host controls localize labels and retain reviewed identifiers", () => {
  const tool = {id:"tool.raw-id",label:"My tool",type:"TOOL",annotations:{"interlock.runtime":{kind:"JSON_TRANSFORM"}}};
  const model = {id:"agent.raw-id",type:"AGENT",annotations:{"interlock.runtime":{kind:"ANTHROPIC",toolActorIds:[tool.id]}}};
  const editor = render("ko",builder.RuntimeEditor,{node:model,nodes:[tool],update:()=>{}});
  assert.ok(editor.includes(korean["Available model tools"]));
  assert.doesNotMatch(editor,/Available model tools/);
  assert.ok(editor.includes(korean["Choose tools explicitly"]));
  assert.match(editor,/<input type="checkbox" checked=""/);
  assert.match(editor,/My tool/);
  assert.match(editor,/tool.raw-id/);
  const implicit = render("en",builder.RuntimeEditor,{node:{...model,annotations:{"interlock.runtime":{kind:"ANTHROPIC"}}},nodes:[tool],update:()=>{}});
  assert.doesNotMatch(implicit,/<input type="checkbox" checked=""/);
  assert.match(implicit,/each task exposes its primary target tool/);
  const host = render("ko",hostReadiness.HostReadiness,{value:{targetId:"target.raw",tenantId:"tenant.raw",credentialSetup:[{reference:"model-key",environmentVariable:"MODEL_SECRET",loaded:false}]},apiUrl:"http://localhost:8792",requiredRefs:["model-key"]});
  assert.match(host,/호스트 준비 상태/);
  assert.match(host,/누락/);
  assert.match(host,/MODEL_SECRET/);
  assert.match(host,/model-key/);
  assert.match(host,/target.raw/);
  assert.match(host,/credentialEnv/);
  assert.match(host,/config.json/);
  assert.doesNotMatch(host,/<input|<textarea/);
  const remote = render("ko",hostReadiness.HostReadiness,{value:{capabilities:{scheduler:"REMOTE_WORKERS"},distributed:{queue:{pending:3,leased:1},workers:[{workerId:"worker-a",online:true,projects:["my-project"],credentialRefs:["provider-ref"]}]}},apiUrl:"https://control.example",requiredRefs:["provider-ref"]});
  assert.match(remote,/원격 실행 서버/);
  assert.match(remote,/배정 대기 실행<\/dt><dd>3/);
  assert.match(remote,/worker-a/);
  assert.match(remote,/provider-ref/);
  assert.match(remote,/RUN-EFFECT-UNCERTAIN/);
  assert.doesNotMatch(remote,/config.json|credentialEnv|누락/);
  const panel = render("ko",comparison.CandidateComparison,{bundle:{bundleDigest:"sha256:candidate"},baseDigest:null,hostStatus:{targetId:"target.raw",tenantId:"tenant.raw"},readiness:{runInputExample:{name:"Raw Name"}},call:()=>{throw new Error("Render must not execute a comparison");}});
  assert.ok(panel.includes(korean["Compare runtime outcomes"]));
  assert.match(panel,/Raw Name/);
  assert.match(panel,/LOCAL JSON_TRANSFORM/);
  assert.doesNotMatch(panel,/HTTP and model tasks are rejected/);
  assert.ok(panel.includes(`<label>${korean["Input for both bundles"]}<textarea`));
});
