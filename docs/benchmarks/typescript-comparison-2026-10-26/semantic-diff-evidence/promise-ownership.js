async function run(value) { return await Promise.resolve(value); }
function aggregate(values) { return Promise.all(values).then(items => items.length); }
