
for (const x of []) y = x;
for (const [a, ...b] of [[1, 2]]) z = a;
for (let { p, ...q } of list) { p++; }
for (k in {}) {}
for (var j = 0; j < 3; j++) { if (j) var w = j; else w ||= 2; }
while (c) var u = 1;
do { var dw = 1; } while (0);
try { var t1 = 1; } catch ({ message, ...e2 }) { var t2 = message; } finally { var t3 = 3; }
switch (s) { case 1: let sw = 1; break; case 2: sw = 2; var sv = 1; default: sv ??= 3; }
label: { var lb = 1; break label; }
a ??= b; a ||= c; a &&= d; [m, n = 1, ...r] = arr; ({ x: xx, [key]: yy, ...zz } = obj);
for (const i of [...it]) {}
for (const i of [1, , 2]) {}
for (const i of "abc") {}
for (const i of ``) {}
for (const i in "") {}
