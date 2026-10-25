
Object.prototype.require = function () {};
with ({}) { require("a"); }
for (var key of [1, 2]) {}
for (var key2 in { a: 1 }) {}
Object.defineProperty(Object.prototype, "x", {});
Object.setPrototypeOf(other, Array.prototype);
String.prototype.at = null;
