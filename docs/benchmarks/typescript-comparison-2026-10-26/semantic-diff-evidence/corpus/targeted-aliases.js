const source = { value: 1 };
const alias = source;
alias.value = 2;
source.extra = alias.value;
export { source, alias };
