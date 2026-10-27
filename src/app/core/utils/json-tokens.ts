export type JsonTokenType = 'key' | 'string' | 'number' | 'boolean' | 'null' | 'punct' | 'space';

export interface JsonToken {
  type: JsonTokenType;
  text: string;
}

const TOKEN_PATTERN =
  /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}[\],:]|\s+/g;

/**
 * Tokenizes pretty-printed JSON into typed fragments so templates can render
 * syntax highlighting with text bindings only (never innerHTML).
 */
export function tokenizeJson(json: string, maxLength = 200_000): JsonToken[] {
  const source = json.length > maxLength ? json.slice(0, maxLength) : json;
  const tokens: JsonToken[] = [];
  let lastIndex = 0;
  for (const match of source.matchAll(TOKEN_PATTERN)) {
    const index = match.index ?? 0;
    if (index > lastIndex) {
      tokens.push({ type: 'punct', text: source.slice(lastIndex, index) });
    }
    const [text, str, colon, bool] = match;
    if (str !== undefined) {
      if (colon !== undefined) {
        tokens.push({ type: 'key', text: str });
        tokens.push({ type: 'punct', text: colon });
      } else {
        tokens.push({ type: 'string', text: str });
      }
    } else if (bool !== undefined) {
      tokens.push({ type: 'boolean', text });
    } else if (text === 'null') {
      tokens.push({ type: 'null', text });
    } else if (/^\s+$/.test(text)) {
      tokens.push({ type: 'space', text });
    } else if (/^[{}[\],:]$/.test(text)) {
      tokens.push({ type: 'punct', text });
    } else {
      tokens.push({ type: 'number', text });
    }
    lastIndex = index + text.length;
  }
  if (lastIndex < source.length) {
    tokens.push({ type: 'punct', text: source.slice(lastIndex) });
  }
  if (source.length < json.length) {
    tokens.push({ type: 'null', text: '\n… (truncated for display)' });
  }
  return tokens;
}
