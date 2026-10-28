// Bundles the extension into dist/ (load that folder as an unpacked extension).
//   node build.mjs           one-off build
//   node build.mjs --watch   rebuild on change
//   node build.mjs --serve   also serve test/ fixture pages on http://localhost:8765
import * as esbuild from "esbuild";
import { cpSync, mkdirSync, rmSync } from "node:fs";

const watch = process.argv.includes("--watch");
const serve = process.argv.includes("--serve");

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist", { recursive: true });
cpSync("static", "dist", { recursive: true });

const common = { bundle: true, format: "iife", target: "chrome116", logLevel: "info", legalComments: "none" };

const extension = await esbuild.context({
  ...common,
  entryPoints: { background: "src/background.ts", content: "src/content.ts", page: "src/page.ts", popup: "src/popup.ts" },
  outdir: "dist",
});

if (serve) {
  // Fixture pages load a fake `chrome` API (test/stub.ts) followed by the real content script.
  const fixtures = await esbuild.context({ ...common, entryPoints: { stub: "test/stub.ts" }, outdir: "test/build" });
  await Promise.all([extension.watch(), fixtures.watch()]);
  const { port } = await fixtures.serve({ servedir: ".", port: 8765 });
  console.log(`Fixtures: http://localhost:${port}/test/`);
} else if (watch) {
  await extension.watch();
} else {
  await extension.rebuild();
  await extension.dispose();
}
