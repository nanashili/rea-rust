
function outer() {
  let a = 1;
  function mid() { a = 2; return function () { return a; }; }
  const arrow = () => a++;
  return { mid, arrow, *gen() { yield a; yield* mid(); return; }, async am() { await a; return a; } };
}
function noReturn() { if (x) return 1; else throw new Error(); }
function nested() { return () => { return 1; }; }
