
function a(x = y, y) { var x; var z = x; return z; }
function b({ [k]: v } = {}, ...rest) { var v = v; var rest; let w = rest; }
function c(p) { var p; p = 2; return p; }
function d(p = 1) { var p = p; function p() {} }
function e(this_, [q, , ...r] = [], { s, t: { u = 1 } = {}, ...o }) { q = 1; ({ s, ...o } = o); }
const f = function named(n = named) { var named = 1; return named; };
const g = function self() { self = 1; return self; };
const h = (a, b = a) => { var a; return b; };
class K { [m]() {} static [k2] = 1; static { var s1; let s2; } static { let s2; } }
const o = { [comp]() { return comp; }, get x() { return this; }, set x(v) {} };
