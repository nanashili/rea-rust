const values = { "\uD800": "high", "\uDC00": "low" };

function selectSurrogate() {
  return values["\uD800"];
}

export { selectSurrogate };
