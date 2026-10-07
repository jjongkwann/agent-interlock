import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL("../", import.meta.url));
const patchedSource = "https://codeload.github.com/micromatch/braces/tar.gz/97308a01d091b211cf015314a2d0696da28a5392";
const lock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
const copies = Object.entries(lock.packages).filter(([path]) => path.endsWith("/braces"));

test("every installed braces copy uses the reviewed immutable patch", () => {
  assert.ok(copies.length > 0);
  for (const [path, metadata] of copies) {
    assert.equal(metadata.resolved, patchedSource, path);
    assert.match(metadata.integrity, /^sha512-/);
    assert.equal(require(resolve(root, path, "package.json")).version, "3.0.3");
  }
});

test("deep patterns and direct ASTs are rejected before stack exhaustion", () => {
  for (const [path] of copies) {
    // A small stack reproduces the original failure reliably. The child also
    // bounds execution if a future dependency change reintroduces recursion.
    execFileSync(process.execPath, ["--stack_size=512", "-e", `
      const assert = require("node:assert/strict");
      const braces = require(process.argv[1]);
      const depthError = error => error instanceof SyntaxError && /nesting depth exceeds/.test(error.message);
      for (const [open, close] of [["{", "}"], ["(", ")"]]) {
        const pattern = open.repeat(4000) + "x" + close.repeat(4000);
        for (const operation of [braces, braces.parse, braces.compile, braces.expand, braces.stringify]) {
          assert.throws(() => operation(pattern), depthError);
        }
      }
      function ast(depth) {
        let node = { type: "root", nodes: [] };
        for (let i = 0; i < depth; i++) node = { type: "root", nodes: [node] };
        return node;
      }
      for (const operation of [braces.compile, braces.expand, braces.stringify]) {
        assert.doesNotThrow(() => operation(ast(100)));
        assert.throws(() => operation(ast(101)), depthError);
        assert.throws(() => operation(ast(4000)), depthError);
      }
    `, resolve(root, path)], { timeout: 10000, stdio: "pipe" });
  }
});

test("patched braces preserves normal patterns through micromatch", () => {
  const micromatch = require("micromatch");
  assert.deepEqual(micromatch.braces("app/{reading,writing}/**/*.{js,jsx}"), ["app/(reading|writing)/**/*.(js|jsx)"]);
  assert.deepEqual(micromatch.braceExpand("page-{1..3}.js"), ["page-1.js", "page-2.js", "page-3.js"]);
  assert.deepEqual(micromatch.braceExpand("a\\{b,c\\}"), ["a{b,c}"]);
  const pattern = "{".repeat(99) + "x" + "}".repeat(99);
  assert.deepEqual(micromatch.braceExpand(pattern), [pattern]);
  assert.throws(() => micromatch.braceExpand("{".repeat(4000) + "x" + "}".repeat(4000)), SyntaxError);
});
