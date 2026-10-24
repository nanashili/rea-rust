// Estimate one pass over the complete raw MCP exchange after timing finishes.
// tokenx is a heuristic, not a model tokenizer or actual model usage counter.
import { readFile, writeFile } from "node:fs/promises";
import { estimateTokenCount } from "tokenx";

const [receiptPath, ...extra] = process.argv.slice(2);
if (!receiptPath || extra.length) {
  throw new Error("Usage: node estimate-tokens.mjs ABSOLUTE_RESULTS_JSON");
}

const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
for (const row of receipt.rows) {
  if (row.status !== "success" || !row.transcript) continue;
  const transcript = JSON.parse(await readFile(row.transcript, "utf8"));
  const costs = {
    input_heuristic_tokens: 0,
    output_heuristic_tokens: 0,
    catalog_heuristic_tokens: 0,
    input_utf8_bytes: 0,
    output_utf8_bytes: 0,
  };
  const catalogIds = new Set();
  for (const entry of transcript) {
    const message = entry.message;
    const serialized = JSON.stringify(message);
    const tokens = estimateTokenCount(serialized);
    const direction = entry.direction;
    costs[`${direction}_heuristic_tokens`] += tokens;
    costs[`${direction}_utf8_bytes`] += Buffer.byteLength(serialized);
    if (direction === "input" && message.method === "tools/list") {
      catalogIds.add(message.id);
    }
    if (direction === "output" && catalogIds.has(message.id)) {
      costs.catalog_heuristic_tokens += tokens;
    }
  }
  row.transport_estimate = costs;
}
receipt.token_method = {
  estimator: "tokenx@1.3.0 estimateTokenCount default heuristic",
  serialization:
    "JSON.stringify of every request, notification and reply, once",
  actual_model_usage: "unmeasured",
  limitations:
    "Not a model tokenizer. Client schema filtering, prompts, conversation replay, cache billing and model continuations are unmeasured. Catalog cost is included in output, not added twice.",
};
await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
