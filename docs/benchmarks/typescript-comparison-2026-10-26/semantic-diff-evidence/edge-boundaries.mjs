import "\uD800";
import { "\uD800" as replacement } from "\uDC00";

const settings = { "\uD800": replacement };
settings["\uDC00"] = "\uD800";

setTimeout(() => settings["\uD800"], 1);
setInterval(() => settings["\uDC00"], 2);
queueMicrotask(() => settings["\uD800"]);
child_process.spawn("worker", [settings["\uDC00"]]);
child_process.execFile("worker", ["\uD800"]);

export { settings };
