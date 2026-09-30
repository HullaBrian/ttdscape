// Small DOM builders for feature panels.
import { element } from './inspector.js';
import { load, save } from './app/prefs.js';

export { element };

// <label>text<select id=...>...</select></label>; options: [[value, text], ...]. A stored
// preference (prefKey) wins over the default when it is still one of the options.
export function selectField(id, text, options, value, { prefKey = null, title = '' } = {}) {
  const label = element('label', text);
  const select = element('select');
  select.id = id;
  for (const [v, t] of options) {
    const o = element('option', t);
    o.value = String(v);
    select.append(o);
  }
  const stored = prefKey ? load(prefKey) : null;
  select.value = stored !== null && options.some(([v]) => String(v) === stored) ? stored : String(value);
  if (prefKey) select.addEventListener('change', () => save(prefKey, select.value));
  if (title) label.title = title;
  label.append(select);
  return { label, input: select };
}

export function checkField(id, text, checked = false, { prefKey = null, title = '' } = {}) {
  const label = element('label', '', 'check');
  const input = element('input');
  input.type = 'checkbox';
  input.id = id;
  const stored = prefKey ? load(prefKey) : null;
  input.checked = stored !== null ? stored === '1' : checked;
  if (prefKey) input.addEventListener('change', () => save(prefKey, input.checked ? '1' : '0'));
  if (title) label.title = title;
  label.append(input, document.createTextNode(` ${text}`));
  return { label, input };
}

export function textField(id, text, placeholder = '', type = 'search') {
  const label = element('label', text);
  const input = element('input');
  input.type = type; input.id = id; input.placeholder = placeholder; input.autocomplete = 'off';
  label.append(input);
  return { label, input };
}

export function heading(text) { return element('h2', text); }

export function swatch(text, color, title = '') {
  const s = element('span', text, 'sw');
  s.style.background = color;
  if (title) s.title = title;
  return s;
}
