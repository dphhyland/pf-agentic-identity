#!/usr/bin/env node
// Renders every tracked Markdown document into the showcase's DOCS_HTML, so the documents the page shows are the
// ones in the repository rather than a copy that drifts from them.
//
//   npm ci --prefix tools
//   node tools/build-showcase-docs.mjs          rewrites the DOCS_HTML line of showcase/index.html
//   node tools/build-showcase-docs.mjs --check  exits 1, naming each document, when that line is not current
//
// The page loads no libraries, so this renders the way it expects: headings carry ids (lower case, anything that
// isn't a letter or digit turned into one hyphen), a Mermaid block is shown as its source in pre.mermaid-src, a
// link to another tracked document becomes #doc:<path>, a link to any other file in the repository is made
// relative to showcase/, and "</" is escaped so no document can close the page's script. marked is pinned in
// tools/package.json: another version renders differently, and --check would fail on every document.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Marked } from 'marked';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PAGE = path.join(ROOT, 'showcase', 'index.html');
const PREFIX = 'const DOCS_HTML = ';
// Skills are instructions to an assistant, not documentation; the showcase's own README describes the page itself.
const EXCLUDED = [/(^|\/)\.claude\//, /^showcase\//];

function trackedDocuments() {
  const out = execFileSync('git', ['ls-files', '-z', '*.md'], { cwd: ROOT, encoding: 'utf8' });
  return out.split('\0').filter(p => p && !EXCLUDED.some(re => re.test(p))).sort();
}

const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'" };

function plain(html) {
  return html.replace(/<[^>]+>/g, '').replace(/&(amp|lt|gt|quot|#39);/g, e => ENTITIES[e]);
}

function slug(html) {
  return plain(html).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function escapeHtml(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeAttribute(text) {
  return escapeHtml(text).replace(/"/g, '&quot;');
}

/** Apostrophes as themselves in text, as the page has always carried them; left escaped only inside tags. */
function plainApostrophes(html) {
  return html.split(/(<[^>]*>)/).map(part => part.startsWith('<') ? part : part.replace(/&#39;/g, "'")).join('');
}

/** Where a link in {@code doc} goes on the showcase page. */
function rewrite(href, doc, documents) {
  if (!href || href.startsWith('#') || /^[a-z][a-z0-9+.-]*:/i.test(href)) {
    return href;
  }
  const hash = href.indexOf('#');
  const target = hash < 0 ? href : href.slice(0, hash);
  const fragment = hash < 0 ? '' : href.slice(hash);
  let resolved = path.posix.normalize(path.posix.join(path.posix.dirname(doc), decodeURI(target)));
  if (resolved.startsWith('..')) {
    return href;
  }
  resolved = resolved.replace(/\/$/, '');
  if (documents.has(resolved)) {
    return `#doc:${resolved}${fragment}`;
  }
  if (documents.has(`${resolved}/README.md`)) {
    return `#doc:${resolved}/README.md${fragment}`;
  }
  // Line anchors (#L42) mean something to a code host, not to a file opened from disk.
  return `../${resolved}${fragment.startsWith('#L') ? '' : fragment}`;
}

function render(doc, source, documents) {
  const seen = new Map();
  let title = null;
  const marked = new Marked({ gfm: true });
  marked.use({
    renderer: {
      heading(text, level) {
        let id = slug(text);
        const count = seen.get(id) || 0;
        seen.set(id, count + 1);
        if (count) {
          id = `${id}-${count}`;
        }
        if (level === 1 && title === null) {
          title = plain(text).trim();
        }
        return `<h${level} id="${id}">${text}</h${level}>\n`;
      },
      code(code, infostring) {
        if ((infostring || '').trim() === 'mermaid') {
          return `<pre class="mermaid-src"><code>${escapeHtml(code)}</code></pre>\n`;
        }
        return false;
      },
      link(href, linkTitle, text) {
        const to = rewrite(href, doc, documents);
        const titled = linkTitle ? ` title="${escapeAttribute(linkTitle)}"` : '';
        return `<a href="${escapeAttribute(to)}"${titled}>${text}</a>`;
      },
      hr() {
        return '<hr />\n';
      },
      // Tables sit in div.table-wrap, which the page scrolls sideways on a narrow screen.
      table(header, body) {
        return `<div class="table-wrap"><table><thead>${header}</thead><tbody>${body}</tbody></table></div>\n`;
      },
      tablerow(content) {
        return `<tr>${content}</tr>`;
      },
      tablecell(content, flags) {
        if (flags.header) {
          return flags.align ? `<th style="text-align:${flags.align}">${content}</th>` : `<th>${content}</th>`;
        }
        return `<td style="text-align:${flags.align || 'left'}">${content}</td>`;
      },
    },
  });
  const html = plainApostrophes(marked.parse(source));
  return { title: title || doc, html };
}

function renderAll() {
  const documents = trackedDocuments();
  const known = new Set(documents);
  const rendered = {};
  for (const doc of documents) {
    rendered[doc] = render(doc, readFileSync(path.join(ROOT, doc), 'utf8'), known);
  }
  return rendered;
}

function line(rendered) {
  return PREFIX + JSON.stringify(rendered).replace(/<\//g, '<\\/') + ';';
}

function currentLine(page) {
  const start = page.indexOf(PREFIX);
  if (start < 0) {
    throw new Error(`showcase/index.html has no line starting "${PREFIX}"`);
  }
  const end = page.indexOf('\n', start);
  return { start, end, text: page.slice(start, end) };
}

const page = readFileSync(PAGE, 'utf8');
const current = currentLine(page);
const rendered = renderAll();
const wanted = line(rendered);

if (process.argv.includes('--check')) {
  if (current.text === wanted) {
    console.log(`showcase/index.html carries every document as it is now (${Object.keys(rendered).length})`);
    process.exit(0);
  }
  const was = JSON.parse(current.text.slice(PREFIX.length, -1));
  const differ = [...new Set([...Object.keys(was), ...Object.keys(rendered)])].sort()
    .filter(doc => JSON.stringify(was[doc]) !== JSON.stringify(rendered[doc]));
  console.error('showcase/index.html is behind these documents - run node tools/build-showcase-docs.mjs:');
  differ.forEach(doc => console.error(`  ${doc}${!(doc in rendered) ? ' (no longer tracked)' : !(doc in was) ? ' (new)' : ''}`));
  process.exit(1);
}

writeFileSync(PAGE, page.slice(0, current.start) + wanted + page.slice(current.end));
console.log(`wrote ${Object.keys(rendered).length} documents into showcase/index.html`);
