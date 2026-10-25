function makeCallable() {
  const callable = () => "value";
  callable.ready = true;
  return callable;
}
const result = makeCallable();
result.extra = 42;
export { makeCallable, result };
