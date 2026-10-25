let state = { phase: "initial" };
const first = state;
state = { phase: "reassigned" };
first.previous = state.phase;
export { state, first };
