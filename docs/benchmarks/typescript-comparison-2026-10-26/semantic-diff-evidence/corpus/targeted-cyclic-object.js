const node = {};
node.self = node;
const wrapper = { node };
wrapper.root = node;
export { node, wrapper };
