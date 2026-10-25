import { readFileSync, writeFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
const [tsPath, rustPath, reportPath = "report.json"] = process.argv.slice(2);
const ts = new Map(readFileSync(tsPath, "utf8").trim().split("\n").filter(Boolean).map(line => { const value = JSON.parse(line); return [value.id, value]; }));
const rust = new Map(readFileSync(rustPath, "utf8").trim().split("\n").filter(Boolean).map(line => { const value = JSON.parse(line); return [value.id, value]; }));
const report = [];
const comparable = (value) => {
  const { micros: _micros, ...withoutTiming } = value;
  return withoutTiming;
};

const differencePaths = (expected, actual, path = "$", paths = []) => {
  if (paths.length >= 8 || isDeepStrictEqual(expected, actual)) return paths;
  if (expected === null || actual === null || typeof expected !== typeof actual) {
    paths.push(path);
    return paths;
  }
  if (Array.isArray(expected) || Array.isArray(actual)) {
    if (!Array.isArray(expected) || !Array.isArray(actual) || expected.length !== actual.length) {
      paths.push(`${path}.length`);
      return paths;
    }
    for (let index = 0; index < expected.length && paths.length < 8; index += 1) {
      differencePaths(expected[index], actual[index], `${path}[${index}]`, paths);
    }
    return paths;
  }
  if (typeof expected === "object") {
    const keys = new Set([...Object.keys(expected), ...Object.keys(actual)]);
    for (const key of [...keys].sort()) {
      if (!(key in expected) || !(key in actual)) {
        paths.push(`${path}.${key}`);
      } else {
        differencePaths(expected[key], actual[key], `${path}.${key}`, paths);
      }
      if (paths.length >= 8) break;
    }
  } else {
    paths.push(path);
  }
  return paths;
};
for (const [id, expected] of ts) {
  const actual = rust.get(id);
  if (!actual) { report.push({ id, kind: "missing-rust" }); continue; }
  const expectedComparable = comparable(expected);
  const actualComparable = comparable(actual);
  if (!isDeepStrictEqual(expectedComparable, actualComparable)) {
    report.push({
      id,
      kind: "ir-diff",
      expectedStatus: expected.status,
      actualStatus: actual.status,
      firstDifferencePaths: differencePaths(expectedComparable, actualComparable),
    });
  }
}
for (const id of rust.keys()) if (!ts.has(id)) report.push({ id, kind: "missing-ts" });
writeFileSync(reportPath, JSON.stringify({ compared: ts.size, differences: report }, null, 2) + "\n");
console.log(JSON.stringify({ compared: ts.size, differences: report.length }));
process.exitCode = report.length ? 1 : 0;
