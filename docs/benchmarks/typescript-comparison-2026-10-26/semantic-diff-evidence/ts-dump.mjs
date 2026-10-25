import { readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { performance } from "node:perf_hooks";
const distRoot = process.env.REA_TS_DIST ?? "/Users/tihan-nico/Developer/rea-rust-ghidra-prism/dist/domain/javascript";
const load = (name) => import(new URL(`file://${distRoot}/${name}`, import.meta.url));
const { parseJavaScriptSource } = await load("javascriptSourceParser.js");
const { analyzeParsedJavaScriptSemantics } = await load("javascriptSemanticAnalysis.js");
const dump = (source, path) => {
  const file = parseJavaScriptSource(source, path);
  if (file === null) return null;
  return analyzeParsedJavaScriptSemantics(file, process.env.SEM_MODE ?? "import");
};
if (process.argv[2] === "-e") {
  console.log(JSON.stringify(dump(process.argv[3], process.argv[4] ?? "probe.js")));
} else {
  const manifest = JSON.parse(readFileSync(process.argv[2], "utf8"));
  const manifestDirectory = dirname(resolve(process.argv[2]));
  const lines = manifest.map((entry) => {
    const started = performance.now();
    try {
      const ir = dump(readFileSync(resolve(manifestDirectory, entry.file), "utf8"), entry.path);
      return JSON.stringify({ id: entry.id, status: ir === null ? "fatal" : "parsed", micros: Math.round((performance.now() - started) * 1000), ir });
    } catch (error) {
      return JSON.stringify({ id: entry.id, status: "error", error: String(error?.stack ?? error), micros: Math.round((performance.now() - started) * 1000) });
    }
  });
  writeFileSync(process.argv[3], lines.join("\n") + "\n");
}
