// REA browser scenario page helper, evaluated only in REA's isolated world.
//
// It reproduces the observable rules of Playwright 1.58.2's injected script
// that affect capture_browser_scenario output: locator matching (test id,
// ARIA role + exact accessible name, CSS with open-shadow piercing),
// actionability states, hit-target checks, fill/select/check semantics,
// element previews used in error text, `Frame.content()` and the default
// `ariaSnapshot()` rendering. The rules follow HTML-AAM/accname as Playwright
// implements them; nothing here is caller-supplied code.
(() => {
  if (globalThis.__reaScenario) return;

  // ---- DOM utilities -------------------------------------------------------
  const tagOf = (element) => {
    const tagName = element.tagName;
    if (typeof tagName === "string") return tagName.toUpperCase();
    if (element instanceof HTMLFormElement) return "FORM";
    return String(element.tagName).toUpperCase();
  };
  const parentOrHost = (element) => {
    if (element.parentElement) return element.parentElement;
    if (!element.parentNode) return undefined;
    if (element.parentNode.nodeType === 11 && element.parentNode.host) return element.parentNode.host;
    return undefined;
  };
  const rootOf = (element) => {
    let node = element;
    while (node.parentNode) node = node.parentNode;
    return node.nodeType === 11 || node.nodeType === 9 ? node : undefined;
  };
  const shadowHostOf = (element) => {
    while (element.parentElement) element = element.parentElement;
    return parentOrHost(element);
  };
  const closestCrossShadow = (element, css) => {
    while (element) {
      const closest = element.closest(css);
      if (closest) return closest;
      element = shadowHostOf(element);
    }
    return undefined;
  };
  let styleCache;
  const styleOf = (element, pseudo) => {
    const key = pseudo || "";
    if (styleCache) {
      let entry = styleCache.get(element);
      if (!entry) styleCache.set(element, (entry = {}));
      if (key in entry) return entry[key];
      const style = element.ownerDocument && element.ownerDocument.defaultView
        ? element.ownerDocument.defaultView.getComputedStyle(element, pseudo) : undefined;
      entry[key] = style;
      return style;
    }
    return element.ownerDocument && element.ownerDocument.defaultView
      ? element.ownerDocument.defaultView.getComputedStyle(element, pseudo) : undefined;
  };
  const withCaches = (work) => {
    const outer = styleCache;
    styleCache = styleCache || new Map();
    const outerHidden = hiddenCache;
    hiddenCache = hiddenCache || new Map();
    const outerNames = nameCache;
    nameCache = nameCache || new Map();
    try { return work(); } finally { styleCache = outer; hiddenCache = outerHidden; nameCache = outerNames; }
  };
  const styleVisibilityVisible = (element, style) => {
    style = style || styleOf(element);
    if (!style) return true;
    if (Element.prototype.checkVisibility) {
      if (!element.checkVisibility()) return false;
    }
    return style.visibility === "visible";
  };
  const visibleTextNode = (node) => {
    const range = node.ownerDocument.createRange();
    range.selectNode(node);
    const rect = range.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  const computeBox = (element) => {
    const style = styleOf(element);
    if (!style) return { visible: true, inline: false };
    if (style.display === "contents") {
      for (let child = element.firstChild; child; child = child.nextSibling) {
        if (child.nodeType === 1 && isVisible(child)) return { visible: true, inline: false };
        if (child.nodeType === 3 && visibleTextNode(child)) return { visible: true, inline: true };
      }
      return { visible: false, inline: false };
    }
    if (!styleVisibilityVisible(element, style)) return { visible: false, inline: false };
    const rect = element.getBoundingClientRect();
    return { visible: rect.width > 0 && rect.height > 0, inline: style.display === "inline" };
  };
  const isVisible = (element) => computeBox(element).visible;
  const normalizeWhiteSpace = (text) => text.replace(/[\u200b\u00ad]/g, "").trim().replace(/\s+/g, " ");
  const oneLine = (s) => s.replace(/\n/g, "\u21B5").replace(/\t/g, "\u21C6");
  const trimEllipsis = (input, cap) => {
    if (input.length <= cap) return input;
    const chars = [...input];
    if (chars.length > cap) return chars.slice(0, cap - 1).join("") + "\u2026";
    return chars.join("");
  };
  const autoClosing = new Set(["AREA", "BASE", "BR", "COL", "COMMAND", "EMBED", "HR", "IMG", "INPUT", "KEYGEN", "LINK", "MENUITEM", "META", "PARAM", "SOURCE", "TRACK", "WBR"]);
  const booleanAttributes = new Set(["checked", "selected", "disabled", "readonly", "multiple"]);
  const preview = (node) => {
    if (node.nodeType === Node.TEXT_NODE) return oneLine(`#text=${node.nodeValue || ""}`);
    if (node.nodeType !== Node.ELEMENT_NODE) return oneLine(`<${node.nodeName.toLowerCase()} />`);
    const attrs = [];
    for (let i = 0; i < node.attributes.length; i++) {
      const { name, value } = node.attributes[i];
      if (name === "style") continue;
      if (!value && booleanAttributes.has(name)) attrs.push(` ${name}`);
      else attrs.push(` ${name}="${value}"`);
    }
    attrs.sort((a, b) => a.length - b.length);
    const attrText = trimEllipsis(attrs.join(""), 500);
    const tag = node.nodeName.toLowerCase();
    if (autoClosing.has(node.nodeName)) return oneLine(`<${tag}${attrText}/>`);
    const children = node.childNodes;
    let onlyText = false;
    if (children.length <= 5) {
      onlyText = true;
      for (let i = 0; i < children.length; i++) onlyText = onlyText && children[i].nodeType === Node.TEXT_NODE;
    }
    const text = onlyText ? node.textContent || "" : children.length ? "\u2026" : "";
    return oneLine(`<${tag}${attrText}>${trimEllipsis(text, 50)}</${tag}>`);
  };

  // Every element in deep (open shadow piercing) document order.
  const deepElements = (root) => {
    const result = [];
    const walk = (scope) => {
      const walker = document.createTreeWalker(scope, NodeFilter.SHOW_ELEMENT);
      let node = walker.nextNode();
      while (node) {
        result.push(node);
        if (node.shadowRoot) walk(node.shadowRoot);
        node = walker.nextNode();
      }
    };
    walk(root);
    return result;
  };
  const shadowRoots = (root) => {
    const roots = [root];
    for (const element of deepElements(root)) if (element.shadowRoot) roots.push(element.shadowRoot);
    return roots;
  };

  // ---- ARIA roles (HTML-AAM, as Playwright computes them) ------------------
  const ancestorPreventingLandmark = "article:not([role]), aside:not([role]), main:not([role]), nav:not([role]), section:not([role]), [role=article], [role=complementary], [role=main], [role=navigation], [role=region]";
  const globalAria = [
    ["aria-atomic"], ["aria-busy"], ["aria-controls"], ["aria-current"], ["aria-describedby"],
    ["aria-details"], ["aria-dropeffect"], ["aria-flowto"], ["aria-grabbed"], ["aria-hidden"],
    ["aria-keyshortcuts"],
    ["aria-label", ["caption", "code", "deletion", "emphasis", "generic", "insertion", "paragraph", "presentation", "strong", "subscript", "superscript"]],
    ["aria-labelledby", ["caption", "code", "deletion", "emphasis", "generic", "insertion", "paragraph", "presentation", "strong", "subscript", "superscript"]],
    ["aria-live"], ["aria-owns"], ["aria-relevant"], ["aria-roledescription", ["generic"]],
  ];
  const hasGlobalAria = (element, role) =>
    globalAria.some(([attribute, prohibited]) => !(prohibited && prohibited.includes(role || "")) && element.hasAttribute(attribute));
  const hasTabIndex = (element) => !Number.isNaN(Number(String(element.getAttribute("tabindex"))));
  const nativelyFocusable = (element) => {
    const tag = tagOf(element);
    if (["BUTTON", "DETAILS", "SELECT", "TEXTAREA"].includes(tag)) return true;
    if (tag === "A" || tag === "AREA") return element.hasAttribute("href");
    if (tag === "INPUT") return !element.hidden;
    return false;
  };
  const focusable = (element) => !nativelyDisabled(element) && (nativelyFocusable(element) || hasTabIndex(element));
  const hasExplicitName = (e) => e.hasAttribute("aria-label") || e.hasAttribute("aria-labelledby");
  const idRefs = (element, ref) => {
    if (!ref) return [];
    const root = rootOf(element);
    if (!root) return [];
    try {
      const result = [];
      for (const id of ref.split(" ").filter((id) => !!id)) {
        const found = root.querySelector("#" + CSS.escape(id));
        if (found && !result.includes(found)) result.push(found);
      }
      return result;
    } catch (error) {
      return [];
    }
  };
  const inputTypeRole = { button: "button", checkbox: "checkbox", image: "button", number: "spinbutton", radio: "radio", range: "slider", reset: "button", submit: "button" };
  const headerCell = (e) => !!e && tagOf(e) === "TH";
  const nonEmptyDataCell = (e) => !!e && tagOf(e) === "TD" && !!((e.textContent || "").trim() || e.children.length > 0);
  const implicitByTag = {
    A: (e) => (e.hasAttribute("href") ? "link" : null),
    AREA: (e) => (e.hasAttribute("href") ? "link" : null),
    ARTICLE: () => "article", ASIDE: () => "complementary", BLOCKQUOTE: () => "blockquote",
    BUTTON: () => "button", CAPTION: () => "caption", CODE: () => "code", DATALIST: () => "listbox",
    DD: () => "definition", DEL: () => "deletion", DETAILS: () => "group", DFN: () => "term",
    DIALOG: () => "dialog", DT: () => "term", EM: () => "emphasis", FIELDSET: () => "group",
    FIGURE: () => "figure",
    FOOTER: (e) => (closestCrossShadow(e, ancestorPreventingLandmark) ? null : "contentinfo"),
    FORM: (e) => (hasExplicitName(e) ? "form" : null),
    H1: () => "heading", H2: () => "heading", H3: () => "heading", H4: () => "heading", H5: () => "heading", H6: () => "heading",
    HEADER: (e) => (closestCrossShadow(e, ancestorPreventingLandmark) ? null : "banner"),
    HR: () => "separator", HTML: () => "document",
    IMG: (e) => (e.getAttribute("alt") === "" && !e.getAttribute("title") && !hasGlobalAria(e) && !hasTabIndex(e) ? "presentation" : "img"),
    INPUT: (e) => {
      const type = e.type.toLowerCase();
      if (type === "search") return e.hasAttribute("list") ? "combobox" : "searchbox";
      if (["email", "tel", "text", "url", ""].includes(type)) {
        const list = idRefs(e, e.getAttribute("list"))[0];
        return list && tagOf(list) === "DATALIST" ? "combobox" : "textbox";
      }
      if (type === "hidden") return null;
      if (type === "file") return "button";
      return inputTypeRole[type] || "textbox";
    },
    INS: () => "insertion", LI: () => "listitem", MAIN: () => "main", MARK: () => "mark", MATH: () => "math",
    MENU: () => "list", METER: () => "meter", NAV: () => "navigation", OL: () => "list",
    OPTGROUP: () => "group", OPTION: () => "option", OUTPUT: () => "status", P: () => "paragraph",
    PROGRESS: () => "progressbar", SEARCH: () => "search",
    SECTION: (e) => (hasExplicitName(e) ? "region" : null),
    SELECT: (e) => (e.hasAttribute("multiple") || e.size > 1 ? "listbox" : "combobox"),
    STRONG: () => "strong", SUB: () => "subscript", SUP: () => "superscript", SVG: () => "img",
    TABLE: () => "table", TBODY: () => "rowgroup",
    TD: (e) => {
      const table = closestCrossShadow(e, "table");
      const role = table ? explicitRole(table) : "";
      return role === "grid" || role === "treegrid" ? "gridcell" : "cell";
    },
    TEXTAREA: () => "textbox", TFOOT: () => "rowgroup",
    TH: (e) => {
      const scope = e.getAttribute("scope");
      if (scope === "col" || scope === "colgroup") return "columnheader";
      if (scope === "row" || scope === "rowgroup") return "rowheader";
      const next = e.nextElementSibling;
      const previous = e.previousElementSibling;
      const row = !!e.parentElement && tagOf(e.parentElement) === "TR" ? e.parentElement : undefined;
      if (!next && !previous) {
        if (row) {
          const table = closestCrossShadow(row, "table");
          if (table && table.rows.length <= 1) return null;
        }
        return "columnheader";
      }
      if (headerCell(next) && headerCell(previous)) return "columnheader";
      if (nonEmptyDataCell(next) || nonEmptyDataCell(previous)) return "rowheader";
      return "columnheader";
    },
    THEAD: () => "rowgroup", TIME: () => "time", TR: () => "row", UL: () => "list",
  };
  const presentationParents = { DD: ["DL", "DIV"], DIV: ["DL"], DT: ["DL", "DIV"], LI: ["OL", "UL"], TBODY: ["TABLE"], TD: ["TR"], TFOOT: ["TABLE"], TH: ["TR"], THEAD: ["TABLE"], TR: ["THEAD", "TBODY", "TFOOT", "TABLE"] };
  const validRoles = new Set("alert alertdialog application article banner blockquote button caption cell checkbox code columnheader combobox complementary contentinfo definition deletion dialog directory document emphasis feed figure form generic grid gridcell group heading img insertion link list listbox listitem log main mark marquee math meter menu menubar menuitem menuitemcheckbox menuitemradio navigation none note option paragraph presentation progressbar radio radiogroup region row rowgroup rowheader scrollbar search searchbox separator slider spinbutton status strong subscript superscript switch tab table tablist tabpanel term textbox time timer toolbar tooltip tree treegrid treeitem".split(" "));
  const explicitRole = (element) => {
    const roles = (element.getAttribute("role") || "").split(" ").map((role) => role.trim());
    return roles.find((role) => validRoles.has(role)) || null;
  };
  const presentationConflict = (element, role) => hasGlobalAria(element, role) || focusable(element);
  const implicitRole = (element) => {
    const handler = implicitByTag[tagOf(element)];
    const role = (handler && handler(element)) || "";
    if (!role) return null;
    let ancestor = element;
    while (ancestor) {
      const parent = parentOrHost(ancestor);
      const parents = presentationParents[tagOf(ancestor)];
      if (!parents || !parent || !parents.includes(tagOf(parent))) break;
      const parentRole = explicitRole(parent);
      if ((parentRole === "none" || parentRole === "presentation") && !presentationConflict(parent, parentRole)) return parentRole;
      ancestor = parent;
    }
    return role;
  };
  const roleOf = (element) => {
    const explicit = explicitRole(element);
    if (!explicit) return implicitRole(element);
    if (explicit === "none" || explicit === "presentation") {
      const implicit = implicitRole(element);
      if (presentationConflict(element, implicit)) return implicit;
    }
    return explicit;
  };
  const ignoredForAria = (element) => ["STYLE", "SCRIPT", "NOSCRIPT", "TEMPLATE"].includes(tagOf(element));
  let hiddenCache;
  const belongsToHidden = (element) => {
    let hidden = hiddenCache && hiddenCache.get(element);
    if (hidden === undefined) {
      hidden = false;
      if (element.parentElement && element.parentElement.shadowRoot && !element.assignedSlot) hidden = true;
      if (!hidden) {
        const style = styleOf(element);
        hidden = !style || style.display === "none" || (element.getAttribute("aria-hidden") || "").toLowerCase() === "true";
      }
      if (!hidden) {
        const parent = parentOrHost(element);
        if (parent) hidden = belongsToHidden(parent);
      }
      if (hiddenCache) hiddenCache.set(element, hidden);
    }
    return hidden;
  };
  const hiddenForAria = (element) => {
    if (ignoredForAria(element)) return true;
    const style = styleOf(element);
    const isSlot = element.nodeName === "SLOT";
    if (style && style.display === "contents" && !isSlot) {
      for (let child = element.firstChild; child; child = child.nextSibling) {
        if (child.nodeType === 1 && !hiddenForAria(child)) return false;
        if (child.nodeType === 3 && visibleTextNode(child)) return false;
      }
      return true;
    }
    const optionInSelect = element.nodeName === "OPTION" && !!element.closest("select");
    if (!optionInSelect && !isSlot && !styleVisibilityVisible(element, style)) return true;
    return belongsToHidden(element);
  };

  // ---- Accessible names (accname as Playwright computes it) ----------------
  const asFlat = (s) => s.split("\u00A0").map((chunk) => chunk.replace(/\r\n/g, "\n").replace(/[\u200b\u00ad]/g, "").replace(/\s\s*/g, " ")).join("\u00A0").trim();
  const cssContent = (element, pseudo) => {
    const style = styleOf(element, pseudo);
    if (!style) return undefined;
    const value = style.content;
    if (!value || value === "none" || value === "normal") return undefined;
    if (style.display === "none" || style.visibility === "hidden") return undefined;
    // Only quoted string sequences (optionally after "/" alt text) are text.
    let text = value;
    const slash = text.lastIndexOf("/");
    if (slash >= 0) text = text.slice(slash + 1).trim();
    else if (!pseudo) return undefined;
    const parts = [];
    const pattern = /\s*"((?:[^"\\]|\\.)*)"|\s*'((?:[^'\\]|\\.)*)'|\s*attr\(\s*([A-Za-z_-][\w-]*)\s*\)/gy;
    let match;
    let consumed = 0;
    while ((match = pattern.exec(text))) {
      consumed = pattern.lastIndex;
      if (match[3] !== undefined) parts.push(element.getAttribute(match[3]) || "");
      else parts.push((match[1] !== undefined ? match[1] : match[2]).replace(/\\(.)/g, "$1"));
    }
    if (text.slice(consumed).trim()) return undefined;
    let content = parts.join("");
    if (pseudo && (style.display || "inline") !== "inline") content = " " + content + " ";
    return content;
  };
  const labelledByElements = (element) => {
    const ref = element.getAttribute("aria-labelledby");
    if (ref === null) return null;
    const refs = idRefs(element, ref);
    return refs.length ? refs : null;
  };
  const queryOwned = (element, selector) => {
    const result = [...element.querySelectorAll(selector)];
    for (const owned of idRefs(element, element.getAttribute("aria-owns"))) {
      if (owned.matches(selector)) result.push(owned);
      result.push(...owned.querySelectorAll(selector));
    }
    return result;
  };
  const nameFromContent = (role, descendant) =>
    ["button", "cell", "checkbox", "columnheader", "gridcell", "heading", "link", "menuitem", "menuitemcheckbox", "menuitemradio", "option", "radio", "row", "rowheader", "switch", "tab", "tooltip", "treeitem"].includes(role) ||
    (descendant && ["", "caption", "code", "contentinfo", "definition", "deletion", "emphasis", "insertion", "list", "listitem", "mark", "none", "paragraph", "presentation", "region", "row", "rowgroup", "section", "strong", "subscript", "superscript", "table", "term", "time"].includes(role));
  const fromLabels = (labels, options) =>
    [...labels].map((label) => textAlternative(label, { ...options, inLabel: { hidden: hiddenForAria(label) }, inNative: undefined, inLabelledBy: undefined, inDescribedBy: undefined, target: undefined }))
      .filter((name) => !!name).join(" ");
  const textAlternative = (element, options) => {
    if (options.visited.has(element)) return "";
    const child = { ...options, target: options.target === "self" ? "descendant" : options.target };
    const hiddenTraversal = !!(options.inLabelledBy && options.inLabelledBy.hidden) || !!(options.inNative && options.inNative.hidden) || !!(options.inLabel && options.inLabel.hidden);
    if (ignoredForAria(element) || (!hiddenTraversal && hiddenForAria(element))) {
      options.visited.add(element);
      return "";
    }
    const labelledBy = labelledByElements(element);
    if (!options.inLabelledBy) {
      const name = (labelledBy || []).map((ref) => textAlternative(ref, { ...options, inLabelledBy: { hidden: hiddenForAria(ref) }, target: undefined, inLabel: undefined, inNative: undefined })).join(" ");
      if (name) return name;
    }
    const role = roleOf(element) || "";
    const tag = tagOf(element);
    if (!!options.inLabel || !!options.inLabelledBy || options.target === "descendant") {
      const ownLabel = [...(element.labels || [])].includes(element);
      const ownLabelledBy = (labelledBy || []).includes(element);
      if (!ownLabel && !ownLabelledBy) {
        if (role === "textbox") {
          options.visited.add(element);
          return tag === "INPUT" || tag === "TEXTAREA" ? element.value : element.textContent || "";
        }
        if (["combobox", "listbox"].includes(role)) {
          options.visited.add(element);
          let selected;
          if (tag === "SELECT") {
            selected = [...element.selectedOptions];
            if (!selected.length && element.options.length) selected.push(element.options[0]);
          } else {
            const listbox = role === "combobox" ? queryOwned(element, "*").find((e) => roleOf(e) === "listbox") : element;
            selected = listbox ? queryOwned(listbox, '[aria-selected="true"]').filter((e) => roleOf(e) === "option") : [];
          }
          if (!selected.length && tag === "INPUT") return element.value;
          return selected.map((option) => textAlternative(option, child)).join(" ");
        }
        if (["progressbar", "scrollbar", "slider", "spinbutton", "meter"].includes(role)) {
          options.visited.add(element);
          if (element.hasAttribute("aria-valuetext")) return element.getAttribute("aria-valuetext") || "";
          if (element.hasAttribute("aria-valuenow")) return element.getAttribute("aria-valuenow") || "";
          return element.getAttribute("value") || "";
        }
        if (role === "menu") {
          options.visited.add(element);
          return "";
        }
      }
    }
    const ariaLabel = element.getAttribute("aria-label") || "";
    if (ariaLabel.trim()) {
      options.visited.add(element);
      return ariaLabel;
    }
    if (!["presentation", "none"].includes(role)) {
      if (tag === "INPUT" && ["button", "submit", "reset"].includes(element.type)) {
        options.visited.add(element);
        const value = element.value || "";
        if (value.trim()) return value;
        if (element.type === "submit") return "Submit";
        if (element.type === "reset") return "Reset";
        return element.getAttribute("title") || "";
      }
      if (tag === "INPUT" && element.type === "file") {
        options.visited.add(element);
        const labels = element.labels || [];
        if (labels.length && !options.inLabelledBy) return fromLabels(labels, options);
        return "Choose File";
      }
      if (tag === "INPUT" && element.type === "image") {
        options.visited.add(element);
        const labels = element.labels || [];
        if (labels.length && !options.inLabelledBy) return fromLabels(labels, options);
        const alt = element.getAttribute("alt") || "";
        if (alt.trim()) return alt;
        const title = element.getAttribute("title") || "";
        if (title.trim()) return title;
        return "Submit";
      }
      if (!labelledBy && tag === "BUTTON") {
        options.visited.add(element);
        const labels = element.labels || [];
        if (labels.length) return fromLabels(labels, options);
      }
      if (!labelledBy && tag === "OUTPUT") {
        options.visited.add(element);
        const labels = element.labels || [];
        if (labels.length) return fromLabels(labels, options);
        return element.getAttribute("title") || "";
      }
      if (!labelledBy && (tag === "TEXTAREA" || tag === "SELECT" || tag === "INPUT")) {
        options.visited.add(element);
        const labels = element.labels || [];
        if (labels.length) return fromLabels(labels, options);
        const usePlaceholder = (tag === "INPUT" && ["text", "password", "search", "tel", "email", "url"].includes(element.type)) || tag === "TEXTAREA";
        const placeholder = element.getAttribute("placeholder") || "";
        const title = element.getAttribute("title") || "";
        if (!usePlaceholder || title) return title;
        return placeholder;
      }
      const captioned = (childTag) => {
        for (let item = element.firstElementChild; item; item = item.nextElementSibling)
          if (tagOf(item) === childTag) return textAlternative(item, { ...child, inNative: { hidden: hiddenForAria(item) } });
        return undefined;
      };
      if (!labelledBy && tag === "FIELDSET") {
        options.visited.add(element);
        const legend = captioned("LEGEND");
        return legend !== undefined ? legend : element.getAttribute("title") || "";
      }
      if (!labelledBy && tag === "FIGURE") {
        options.visited.add(element);
        const caption = captioned("FIGCAPTION");
        return caption !== undefined ? caption : element.getAttribute("title") || "";
      }
      if (tag === "IMG" || tag === "AREA") {
        options.visited.add(element);
        const alt = element.getAttribute("alt") || "";
        if (alt.trim()) return alt;
        return element.getAttribute("title") || "";
      }
      if (tag === "TABLE") {
        options.visited.add(element);
        const caption = captioned("CAPTION");
        if (caption !== undefined) return caption;
        const summary = element.getAttribute("summary") || "";
        if (summary) return summary;
      }
      if (tag === "SVG" || element.ownerSVGElement) {
        options.visited.add(element);
        for (let item = element.firstElementChild; item; item = item.nextElementSibling)
          if (tagOf(item) === "TITLE" && item.ownerSVGElement)
            return textAlternative(item, { ...child, inLabelledBy: { hidden: hiddenForAria(item) } });
      }
      if (element.ownerSVGElement && tag === "A") {
        const title = element.getAttribute("xlink:title") || "";
        if (title.trim()) {
          options.visited.add(element);
          return title;
        }
      }
    }
    const summary = tag === "SUMMARY" && !["presentation", "none"].includes(role);
    if (nameFromContent(role, options.target === "descendant") || summary || !!options.inLabelledBy || !!options.inLabel || !!options.inNative) {
      options.visited.add(element);
      const name = accumulatedText(element, child);
      const trimmed = options.target === "self" ? name.trim() : name;
      if (trimmed) return name;
    }
    if (!["presentation", "none"].includes(role) || tag === "IFRAME") {
      options.visited.add(element);
      const title = element.getAttribute("title") || "";
      if (title.trim()) return title;
    }
    options.visited.add(element);
    return "";
  };
  const accumulatedText = (element, options) => {
    const tokens = [];
    const visit = (node, skipSlotted) => {
      if (skipSlotted && node.assignedSlot) return;
      if (node.nodeType === 1) {
        const display = (styleOf(node) || {}).display || "inline";
        let token = textAlternative(node, options);
        if (display !== "inline" || node.nodeName === "BR") token = " " + token + " ";
        tokens.push(token);
      } else if (node.nodeType === 3) {
        tokens.push(node.textContent || "");
      }
    };
    tokens.push(cssContent(element, "::before") || "");
    const content = cssContent(element);
    if (content !== undefined) {
      tokens.push(content);
    } else {
      const assigned = element.nodeName === "SLOT" ? element.assignedNodes() : [];
      if (assigned.length) {
        for (const node of assigned) visit(node, false);
      } else {
        for (let node = element.firstChild; node; node = node.nextSibling) visit(node, true);
        if (element.shadowRoot) for (let node = element.shadowRoot.firstChild; node; node = node.nextSibling) visit(node, true);
        for (const owned of idRefs(element, element.getAttribute("aria-owns"))) visit(owned, true);
      }
    }
    tokens.push(cssContent(element, "::after") || "");
    return tokens.join("");
  };
  let nameCache;
  const accessibleName = (element) => {
    if (nameCache && nameCache.has(element)) return nameCache.get(element);
    let name = "";
    const prohibits = ["caption", "code", "definition", "deletion", "emphasis", "generic", "insertion", "mark", "paragraph", "presentation", "strong", "subscript", "suggestion", "superscript", "term", "time"].includes(roleOf(element) || "");
    if (!prohibits) name = asFlat(textAlternative(element, { visited: new Set(), target: "self" }));
    if (nameCache) nameCache.set(element, name);
    return name;
  };

  // ---- ARIA states ---------------------------------------------------------
  const checkedRoles = ["checkbox", "menuitemcheckbox", "option", "radio", "switch", "menuitemradio", "treeitem"];
  const selectedRoles = ["gridcell", "option", "row", "tab", "rowheader", "columnheader", "treeitem"];
  const pressedRoles = ["button"];
  const expandedRoles = ["application", "button", "checkbox", "combobox", "gridcell", "link", "listbox", "menuitem", "row", "rowheader", "tab", "treeitem", "columnheader", "menuitemcheckbox", "menuitemradio", "switch"];
  const levelRoles = ["heading", "listitem", "row", "treeitem"];
  const disabledRoles = ["application", "button", "composite", "gridcell", "group", "input", "link", "menuitem", "scrollbar", "separator", "tab", "checkbox", "columnheader", "combobox", "grid", "listbox", "menu", "menubar", "menuitemcheckbox", "menuitemradio", "option", "radio", "radiogroup", "row", "rowheader", "searchbox", "select", "slider", "spinbutton", "switch", "tablist", "textbox", "toolbar", "tree", "treegrid", "treeitem"];
  const readonlyRoles = ["checkbox", "combobox", "grid", "gridcell", "listbox", "radiogroup", "slider", "spinbutton", "textbox", "columnheader", "rowheader", "searchbox", "switch", "treegrid"];
  const checkedOf = (element, allowMixed) => {
    const tag = tagOf(element);
    if (allowMixed && tag === "INPUT" && element.indeterminate) return "mixed";
    if (tag === "INPUT" && ["checkbox", "radio"].includes(element.type)) return element.checked;
    if (checkedRoles.includes(roleOf(element) || "")) {
      const checked = element.getAttribute("aria-checked");
      if (checked === "true") return true;
      if (allowMixed && checked === "mixed") return "mixed";
      return false;
    }
    return "error";
  };
  const disabledFieldSet = (element) => {
    const fieldset = element && element.closest("FIELDSET[DISABLED]");
    if (!fieldset) return false;
    const legend = fieldset.querySelector(":scope > LEGEND");
    return !legend || !legend.contains(element);
  };
  const nativelyDisabled = (element) =>
    ["BUTTON", "INPUT", "SELECT", "TEXTAREA", "OPTION", "OPTGROUP"].includes(tagOf(element)) &&
    (element.hasAttribute("disabled") || (tagOf(element) === "OPTION" && !!element.closest("OPTGROUP[DISABLED]")) || disabledFieldSet(element));
  const explicitAriaDisabled = (element, ancestor) => {
    if (!element) return false;
    if (ancestor || disabledRoles.includes(roleOf(element) || "")) {
      const value = (element.getAttribute("aria-disabled") || "").toLowerCase();
      if (value === "true") return true;
      if (value === "false") return false;
      return explicitAriaDisabled(parentOrHost(element), true);
    }
    return false;
  };
  const disabledOf = (element) => nativelyDisabled(element) || explicitAriaDisabled(element);
  const readonlyOf = (element) => {
    const tag = tagOf(element);
    if (["INPUT", "TEXTAREA", "SELECT"].includes(tag)) return element.hasAttribute("readonly");
    if (readonlyRoles.includes(roleOf(element) || "")) return element.getAttribute("aria-readonly") === "true";
    if (element.isContentEditable) return false;
    return "error";
  };
  const levelOf = (element) => {
    const native = { H1: 1, H2: 2, H3: 3, H4: 4, H5: 5, H6: 6 }[tagOf(element)];
    if (native) return native;
    if (levelRoles.includes(roleOf(element) || "")) {
      const attribute = element.getAttribute("aria-level");
      const value = attribute === null ? Number.NaN : Number(attribute);
      if (Number.isInteger(value) && value >= 1) return value;
    }
    return 0;
  };
  const selectedOf = (element) => {
    if (tagOf(element) === "OPTION") return element.selected;
    if (selectedRoles.includes(roleOf(element) || "")) return (element.getAttribute("aria-selected") || "").toLowerCase() === "true";
    return false;
  };
  const pressedOf = (element) => {
    if (pressedRoles.includes(roleOf(element) || "")) {
      const pressed = element.getAttribute("aria-pressed");
      if (pressed === "true") return true;
      if (pressed === "mixed") return "mixed";
    }
    return false;
  };
  const expandedOf = (element) => {
    if (tagOf(element) === "DETAILS") return element.open;
    if (expandedRoles.includes(roleOf(element) || "")) {
      const expanded = element.getAttribute("aria-expanded");
      if (expanded === null) return undefined;
      return expanded === "true";
    }
    return undefined;
  };

  // ---- Aria snapshot (default mode) ----------------------------------------
  const yamlNeedsQuotes = (str) => {
    if (str.length === 0) return true;
    if (/^\s|\s$/.test(str)) return true;
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(str)) return true;
    if (/^-/.test(str)) return true;
    if (/[\n:](\s|$)/.test(str)) return true;
    if (/\s#/.test(str)) return true;
    if (/[\n\r]/.test(str)) return true;
    if (/^[&*\],?!>|@"'#%]/.test(str)) return true;
    if (/[{}`]/.test(str)) return true;
    if (/^\[/.test(str)) return true;
    if (!isNaN(Number(str)) || ["y", "n", "yes", "no", "true", "false", "on", "off", "null"].includes(str.toLowerCase())) return true;
    return false;
  };
  const yamlKey = (str) => (yamlNeedsQuotes(str) ? `'` + str.replace(/'/g, `''`) + `'` : str);
  const yamlValue = (str) => {
    if (!yamlNeedsQuotes(str)) return str;
    return '"' + str.replace(/[\\"\x00-\x1f\x7f-\x9f]/g, (c) => {
      switch (c) {
        case "\\": return "\\\\";
        case '"': return '\\"';
        case "\b": return "\\b";
        case "\f": return "\\f";
        case "\n": return "\\n";
        case "\r": return "\\r";
        case "\t": return "\\t";
        default: return "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0");
      }
    }) + '"';
  };
  const toAriaNode = (element) => {
    if (element.nodeName === "IFRAME") return { role: "iframe", name: "", children: [], props: {} };
    const role = roleOf(element);
    if (!role || role === "presentation" || role === "none") return null;
    const name = normalizeWhiteSpace(accessibleName(element) || "");
    const box = computeBox(element);
    if (role === "generic" && box.inline && element.childNodes.length === 1 && element.childNodes[0].nodeType === Node.TEXT_NODE) return null;
    const node = { role, name, children: [], props: {} };
    if (checkedRoles.includes(role)) { const checked = checkedOf(element, true); node.checked = checked === "error" ? false : checked; }
    if (disabledRoles.includes(role)) node.disabled = disabledOf(element);
    if (expandedRoles.includes(role)) node.expanded = expandedOf(element);
    if (levelRoles.includes(role)) node.level = levelOf(element);
    if (pressedRoles.includes(role)) node.pressed = pressedOf(element);
    if (selectedRoles.includes(role)) node.selected = selectedOf(element);
    if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement)
      if (element.type !== "checkbox" && element.type !== "radio" && element.type !== "file") node.children = [element.value];
    return node;
  };
  const ariaTree = (rootElement) => {
    const visited = new Set();
    const root = { role: "fragment", name: "", children: [], props: {} };
    const visit = (ariaNode, node, parentVisible) => {
      if (visited.has(node)) return;
      visited.add(node);
      if (node.nodeType === Node.TEXT_NODE && node.nodeValue) {
        if (!parentVisible) return;
        if (ariaNode.role !== "textbox" && node.nodeValue) ariaNode.children.push(node.nodeValue || "");
        return;
      }
      if (node.nodeType !== Node.ELEMENT_NODE) return;
      const element = node;
      const visible = !hiddenForAria(element);
      if (!visible) return;
      const owned = [];
      if (element.hasAttribute("aria-owns")) {
        for (const id of element.getAttribute("aria-owns").split(/\s+/)) {
          const found = rootElement.ownerDocument.getElementById(id);
          if (found) owned.push(found);
        }
      }
      const childNode = toAriaNode(element);
      if (childNode) ariaNode.children.push(childNode);
      processElement(childNode || ariaNode, element, owned, visible);
    };
    const processElement = (ariaNode, element, owned, parentVisible) => {
      const display = (styleOf(element) || {}).display || "inline";
      const block = display !== "inline" || element.nodeName === "BR" ? " " : "";
      if (block) ariaNode.children.push(block);
      ariaNode.children.push(cssContent(element, "::before") || "");
      const assigned = element.nodeName === "SLOT" ? element.assignedNodes() : [];
      if (assigned.length) {
        for (const child of assigned) visit(ariaNode, child, parentVisible);
      } else {
        for (let child = element.firstChild; child; child = child.nextSibling) if (!child.assignedSlot) visit(ariaNode, child, parentVisible);
        if (element.shadowRoot) for (let child = element.shadowRoot.firstChild; child; child = child.nextSibling) visit(ariaNode, child, parentVisible);
      }
      for (const child of owned) visit(ariaNode, child, parentVisible);
      ariaNode.children.push(cssContent(element, "::after") || "");
      if (block) ariaNode.children.push(block);
      if (ariaNode.children.length === 1 && ariaNode.name === ariaNode.children[0]) ariaNode.children = [];
      if (ariaNode.role === "link" && element.hasAttribute("href")) ariaNode.props.url = element.getAttribute("href");
      if (ariaNode.role === "textbox" && element.hasAttribute("placeholder") && element.getAttribute("placeholder") !== ariaNode.name)
        ariaNode.props.placeholder = element.getAttribute("placeholder");
    };
    visit(root, rootElement, true);
    const normalizeStrings = (ariaNode) => {
      const normalized = [];
      const buffer = [];
      const flush = () => {
        if (!buffer.length) return;
        const text = normalizeWhiteSpace(buffer.join(""));
        if (text) normalized.push(text);
        buffer.length = 0;
      };
      for (const child of ariaNode.children || []) {
        if (typeof child === "string") buffer.push(child);
        else { flush(); normalizeStrings(child); normalized.push(child); }
      }
      flush();
      ariaNode.children = normalized.length ? normalized : [];
      if (ariaNode.children.length === 1 && ariaNode.children[0] === ariaNode.name) ariaNode.children = [];
    };
    normalizeStrings(root);
    return root;
  };
  const renderAria = (root) => {
    const lines = [];
    const key = (node) => {
      let text = node.role;
      if (node.name && node.name.length <= 900) text += " " + JSON.stringify(node.name);
      if (node.checked === "mixed") text += " [checked=mixed]";
      if (node.checked === true) text += " [checked]";
      if (node.disabled) text += " [disabled]";
      if (node.expanded) text += " [expanded]";
      if (node.level) text += ` [level=${node.level}]`;
      if (node.pressed === "mixed") text += " [pressed=mixed]";
      if (node.pressed === true) text += " [pressed]";
      if (node.selected === true) text += " [selected]";
      return text;
    };
    const visitText = (text, indent) => {
      const escaped = yamlValue(text);
      if (escaped) lines.push(indent + "- text: " + escaped);
    };
    const visit = (node, indent) => {
      const escapedKey = indent + "- " + yamlKey(key(node));
      const single = node.children.length === 1 && typeof node.children[0] === "string" && !Object.keys(node.props).length ? node.children[0] : undefined;
      if (!node.children.length && !Object.keys(node.props).length) lines.push(escapedKey);
      else if (single !== undefined) lines.push(escapedKey + ": " + yamlValue(single));
      else {
        lines.push(escapedKey + ":");
        for (const [name, value] of Object.entries(node.props)) lines.push(indent + "  - /" + name + ": " + yamlValue(value));
        for (const child of node.children) {
          if (typeof child === "string") visitText(child, indent + "  ");
          else visit(child, indent + "  ");
        }
      }
    };
    for (const node of root.children) {
      if (typeof node === "string") visitText(node, "");
      else visit(node, "");
    }
    return lines.join("\n");
  };

  // ---- Locators ------------------------------------------------------------
  const describe = (locator) => {
    const quote = (value) => `'${value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
    if (locator.kind === "test_id") return `getByTestId(${quote(locator.value)})`;
    if (locator.kind === "role") return `getByRole(${quote(locator.role)}, { name: ${quote(locator.name)}, exact: true })`;
    return `locator(${quote(locator.selector)})`;
  };
  const resolveAll = (locator) => withCaches(() => {
    if (locator.kind === "test_id") return deepElements(document).filter((element) => element.getAttribute("data-testid") === locator.value);
    if (locator.kind === "role") {
      const name = normalizeWhiteSpace(locator.name);
      return deepElements(document).filter((element) =>
        roleOf(element) === locator.role && !hiddenForAria(element) && normalizeWhiteSpace(accessibleName(element)) === name);
    }
    const found = new Set();
    for (const root of shadowRoots(document)) for (const element of root.querySelectorAll(locator.selector)) found.add(element);
    return deepElements(document).filter((element) => found.has(element));
  });
  const stableRect = (element) => new Promise((resolve) => {
    // Chromium's stable RAF count is one: two equal consecutive frames.
    let last;
    let count = 0;
    const step = () => {
      if (!element.isConnected) return resolve("error:notconnected");
      const rect = element.getBoundingClientRect();
      const current = [rect.top, rect.left, rect.width, rect.height].join(",");
      if (last !== undefined) {
        if (current !== last) return resolve(false);
        if (++count >= 1) return resolve(true);
      }
      last = current;
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
  const retarget = (node, behavior) => {
    let element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    if (!element) return null;
    if (behavior === "none") return element;
    if (!element.matches("input, textarea, select") && !element.isContentEditable)
      element = element.closest("button, [role=button], [role=checkbox], [role=radio]") || element;
    if (behavior === "follow-label") {
      if (!element.matches("a, input, textarea, button, select, [role=link], [role=button], [role=checkbox], [role=radio]") && !element.isContentEditable) {
        const label = element.closest("label");
        if (label && label.control) element = label.control;
      }
    }
    return element;
  };
  const stackless = (message) => {
    const error = new Error(message);
    error.stack = "";
    return error;
  };

  // A reduced form of Playwright's strict-violation "aka" locator
  // suggestion: the first unique candidate among test id, role + name
  // (case-insensitive substring, then exact) and element id.
  const quoted = (value) => `'${value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
  const suggest = (element) => withCaches(() => {
    const all = deepElements(document);
    const testId = element.getAttribute("data-testid");
    if (testId && all.filter((other) => other.getAttribute("data-testid") === testId).length === 1)
      return `getByTestId(${quoted(testId)})`;
    const role = roleOf(element);
    const name = role ? normalizeWhiteSpace(accessibleName(element)) : "";
    if (role && name && !hiddenForAria(element)) {
      const sameRole = all.filter((other) => roleOf(other) === role && !hiddenForAria(other));
      const lower = name.toLowerCase();
      if (sameRole.filter((other) => normalizeWhiteSpace(accessibleName(other)).toLowerCase().includes(lower)).length === 1)
        return `getByRole(${quoted(role)}, { name: ${quoted(name)} })`;
      if (sameRole.filter((other) => normalizeWhiteSpace(accessibleName(other)) === name).length === 1)
        return `getByRole(${quoted(role)}, { name: ${quoted(name)}, exact: true })`;
    }
    if (element.id && /^[A-Za-z][\w-]*$/.test(element.id) && document.querySelectorAll("#" + CSS.escape(element.id)).length === 1)
      return `locator(${quoted("#" + element.id)})`;
    return undefined;
  });
  const described = (element) => {
    const aka = suggest(element);
    return aka ? `${preview(element)} aka ${aka}` : preview(element);
  };

  globalThis.__reaScenario = {
    describe,
    // One element, or a plain summary of zero or several matches.
    resolve(locator) {
      const elements = resolveAll(locator);
      if (elements.length === 1) return elements[0];
      return { count: elements.length, previews: elements.slice(0, 10).map(described) };
    },
    count(locator) {
      const elements = resolveAll(locator);
      return { count: elements.length, visible: elements.length === 1 ? isVisible(elements[0]) : false, previews: elements.slice(0, 10).map(described) };
    },
    preview,
    async states(element, states) {
      if (states.includes("stable")) {
        const stable = await stableRect(retarget(element, "no-follow-label") || element);
        if (stable === false) return { missing: "stable" };
        if (stable === "error:notconnected") return { missing: "notconnected" };
      }
      return withCaches(() => {
        for (const state of states) {
          if (state === "stable") continue;
          const target = retarget(element, state === "visible" ? "none" : "follow-label");
          if (!target || !target.isConnected) return { missing: "notconnected" };
          if (state === "visible" && !isVisible(target)) return { missing: "visible" };
          if (state === "enabled" && disabledOf(target)) return { missing: "enabled" };
          if (state === "editable") {
            const readonly = readonlyOf(target);
            if (readonly === "error") throw stackless("Element is not an <input>, <textarea>, <select> or [contenteditable] and does not have a role allowing [aria-readonly]");
            if (disabledOf(target) || readonly) return { missing: "editable" };
          }
        }
        return "ok";
      });
    },
    hit(target, x, y) {
      const roots = [];
      let parent = target;
      while (parent) {
        const root = rootOf(parent);
        if (!root) break;
        roots.push(root);
        if (root.nodeType === 9) break;
        parent = root.host;
      }
      let hitElement;
      for (let index = roots.length - 1; index >= 0; index--) {
        const root = roots[index];
        const elements = root.elementsFromPoint(x, y);
        const single = root.elementFromPoint(x, y);
        if (single && elements[0] && parentOrHost(single) === elements[0]) {
          const style = window.getComputedStyle(single);
          if (style && style.display === "contents") elements.unshift(single);
        }
        if (elements[0] && elements[0].shadowRoot === root && elements[1] === single) elements.shift();
        const inner = elements[0];
        if (!inner) break;
        hitElement = inner;
        if (index && inner !== roots[index - 1].host) break;
      }
      const parents = [];
      while (hitElement && hitElement !== target) {
        parents.push(hitElement);
        hitElement = hitElement.assignedSlot || parentOrHost(hitElement);
      }
      if (hitElement === target) return "done";
      const description = preview(parents[0] || document.documentElement);
      let rootDescription;
      let element = target;
      while (element) {
        const index = parents.indexOf(element);
        if (index !== -1) {
          if (index > 1) rootDescription = preview(parents[index - 1]);
          break;
        }
        element = parentOrHost(element);
      }
      return { hit: rootDescription ? `${description} from ${rootDescription} subtree` : description };
    },
    fill(node, value) {
      const element = retarget(node, "follow-label");
      if (!element) return "error:notconnected";
      if (element.nodeName.toLowerCase() === "input") {
        const type = element.type.toLowerCase();
        const setValue = new Set(["color", "date", "time", "datetime-local", "month", "range", "week"]);
        const typeInto = new Set(["", "email", "number", "password", "search", "tel", "text", "url"]);
        if (!typeInto.has(type) && !setValue.has(type)) throw stackless(`Input of type "${type}" cannot be filled`);
        if (type === "number") {
          value = value.trim();
          if (isNaN(Number(value))) throw stackless("Cannot type text into input[type=number]");
        }
        if (type === "color") value = value.toLowerCase();
        if (setValue.has(type)) {
          value = value.trim();
          element.focus();
          element.value = value;
          if (element.value !== value) throw stackless("Malformed value");
          element.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
          element.dispatchEvent(new Event("change", { bubbles: true }));
          return "done";
        }
      } else if (element.nodeName.toLowerCase() === "textarea") {
        // Typed below.
      } else if (!element.isContentEditable) {
        throw stackless("Element is not an <input>, <textarea> or [contenteditable] element");
      }
      if (element.nodeName.toLowerCase() === "input") {
        element.select();
        element.focus();
      } else if (element.nodeName.toLowerCase() === "textarea") {
        element.selectionStart = 0;
        element.selectionEnd = element.value.length;
        element.focus();
      } else {
        const range = element.ownerDocument.createRange();
        range.selectNodeContents(element);
        const selection = element.ownerDocument.defaultView.getSelection();
        if (selection) {
          selection.removeAllRanges();
          selection.addRange(range);
        }
        element.focus();
      }
      return "needsinput";
    },
    focus(node) {
      if (!node.isConnected) return "error:notconnected";
      if (node.nodeType !== Node.ELEMENT_NODE) throw stackless("Node is not an element");
      const active = node.getRootNode().activeElement;
      const wasFocused = active === node && !!node.ownerDocument && node.ownerDocument.hasFocus();
      if (node.isContentEditable && !wasFocused && active && active.blur) active.blur();
      node.focus();
      node.focus();
      if (!wasFocused && node.nodeName.toLowerCase() === "input") {
        try { node.setSelectionRange(0, 0); } catch (error) { /* Not a text input. */ }
      }
      return "done";
    },
    select(node, valueOrLabel) {
      const element = retarget(node, "follow-label");
      if (!element) return "error:notconnected";
      if (element.nodeName.toLowerCase() !== "select") throw stackless("Element is not a <select> element");
      const selected = [];
      let remaining = [valueOrLabel];
      for (const option of [...element.options]) {
        const matches = (wanted) => wanted === option.value || wanted === option.label;
        if (!remaining.some(matches)) continue;
        if (disabledOf(option)) return "error:optionnotenabled";
        selected.push(option);
        if (element.multiple) remaining = remaining.filter((wanted) => !matches(wanted));
        else { remaining = []; break; }
      }
      if (remaining.length) return "error:optionsnotfound";
      element.value = undefined;
      selected.forEach((option) => (option.selected = true));
      element.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
      return selected.map((option) => option.value);
    },
    checked(node) {
      const element = retarget(node, "follow-label");
      if (!element || !element.isConnected) return { error: "error:notconnected" };
      const checked = withCaches(() => checkedOf(element, false));
      if (checked === "error") throw stackless("Not a checkbox or radio button");
      return { checked, radio: element.nodeName === "INPUT" && element.type === "radio" };
    },
    ariaSnapshot(element) {
      if (element.nodeType !== Node.ELEMENT_NODE) throw stackless("Can only capture aria snapshot of Element nodes.");
      return withCaches(() => renderAria(ariaTree(element)));
    },
    content() {
      let value = "";
      if (document.doctype) value = new XMLSerializer().serializeToString(document.doctype);
      if (document.documentElement) value += document.documentElement.outerHTML;
      return value;
    },
    viewport() {
      return { width: window.innerWidth, height: window.innerHeight };
    },
    // Screenshot preparation with caret hiding and finished/cancelled animations.
    prepareScreenshot() {
      const roots = [];
      const collect = (root) => {
        roots.push(root);
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
        do {
          const node = walker.currentNode;
          const shadow = node instanceof Element ? node.shadowRoot : null;
          if (shadow) collect(shadow);
        } while (walker.nextNode());
      };
      collect(document);
      const cleanups = [];
      const carets = new Map();
      for (const root of roots)
        root.querySelectorAll("input,textarea,[contenteditable]").forEach((element) => {
          carets.set(element, { value: element.style.getPropertyValue("caret-color"), priority: element.style.getPropertyPriority("caret-color") });
          element.style.setProperty("caret-color", "transparent", "important");
        });
      cleanups.push(() => { for (const [element, value] of carets) element.style.setProperty("caret-color", value.value, value.priority); });
      const resume = new Set();
      const handle = (root) => {
        for (const animation of root.getAnimations()) {
          if (!animation.effect || animation.playbackRate === 0 || resume.has(animation)) continue;
          const endTime = animation.effect.getComputedTiming().endTime;
          if (Number.isFinite(endTime)) { try { animation.finish(); } catch (error) { /* Ignore. */ } }
          else { try { animation.cancel(); resume.add(animation); } catch (error) { /* Ignore. */ } }
        }
      };
      for (const root of roots) {
        const listener = handle.bind(null, root);
        listener();
        root.addEventListener("transitionrun", listener);
        root.addEventListener("animationstart", listener);
        cleanups.push(() => {
          root.removeEventListener("transitionrun", listener);
          root.removeEventListener("animationstart", listener);
        });
      }
      cleanups.push(() => { for (const animation of resume) { try { animation.play(); } catch (error) { /* Ignore. */ } } });
      globalThis.__reaCleanupScreenshot = () => {
        for (const cleanup of cleanups) cleanup();
        delete globalThis.__reaCleanupScreenshot;
      };
    },
    cleanupScreenshot() {
      if (globalThis.__reaCleanupScreenshot) globalThis.__reaCleanupScreenshot();
    },
  };
})();
