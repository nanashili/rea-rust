
var require = 1;
with (obj) { require("a"); x = 1; var v = 2; function inner() { return x; } }
with ({ require: 1 }) { require("b"); }
with ({ __proto__: null }) { require("c"); }
with ({ require: 1, [Symbol.unscopables]: { require: true } }) { require("d"); }
with ({ require: 1, [Symbol.unscopables]: { require: 0 } }) { require("e"); }
with ({ ...spread }) { require("f"); }
with ({ [dyn]: 1 }) { require("g"); }
with ({ require: 1, [Symbol.unscopables]: null }) { require("h"); }
with ({ require: 1, [Symbol.unscopables]: { __proto__: null } }) { require("i"); }
for (const k in obj) {}
