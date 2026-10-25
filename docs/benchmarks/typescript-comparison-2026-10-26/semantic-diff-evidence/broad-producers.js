const source = { value: 1, nested: { ready: true } };
source.value = 2;
source.nested.extra = "x";

function defaults(value = source.value, { mode = "safe" } = {}) {
  return `${mode}:${value}`;
}

async function work(input) {
  const promise = Promise.resolve(input);
  const child = promise.then((value) => ({ value }));
  await child;
  return Promise.all([promise, child]);
}

function launch(command) {
  return child_process.spawn(command, ["--safe"], { cwd: "/tmp" });
}

const result = defaults();
const read = source.nested.ready;
module.exports.result = result;
exports.read = read;
export { defaults, work, launch };
