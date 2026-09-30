#!/usr/bin/env node
// Renders every tracked Markdown document into showcase/docs.js, so the documents the page shows are the ones in
// the repository rather than a copy that drifts from them.
//
//   npm ci --prefix tools
//   node tools/build-showcase-docs.mjs          writes showcase/docs.js
//
// docs.js is generated and git-ignored (plan decision 18; the rendered documents were a line of index.html until
// 2026-09-27, which every documentation change regenerated and which conflicted whenever two met). It declares
// `const DOCS_HTML = {...}`, one entry per document, and index.html loads it with a script tag before its own
// script; when it is missing the page still works and its Documentation view says how to build it. CI builds it
// after the reactor and the dashboard on every Build run that gets that far, and uploads showcase/ as the
// `showcase` artefact. The coverage dashboard, which tools/coverage-report.py writes after `mvn verify` and which
// is not tracked either, is rendered too when the last build left one, so the artefact carries the dashboard of
// the run that built it.
//
// The page loads no libraries, so this renders the way it expects: headings carry ids (lower case, anything that
// isn't a letter or digit turned into one hyphen), a Mermaid block is shown as its source in pre.mermaid-src, a
// link to another rendered document becomes #doc:<path>, a link to any other file in the repository is made
// relative to showcase/, and "</" is escaped so no document can close a script. marked is pinned to 18.0.13 in
// tools/package.json (Node 20 or later): another version renders differently, and a page built elsewhere would
// differ. Moving from 12.0.2 to 18.0.13 left docs.js byte for byte the same for every document the repository had.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Marked } from 'marked';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'showcase', 'docs.js');
// Skills are instructions to an assistant, not documentation; the showcase's own README describes the page itself.
const EXCLUDED = [/(^|\/)\.claude\//, /^showcase\//];
// Documents the build writes rather than anyone tracks. Rendered when present, so a showcase built after
// `mvn verify` and tools/coverage-report.py carries that build's dashboard; the page's documentation index
// names it either way and says how to make it when it is absent.
const GENERATED = ['docs/coverage-dashboard.md'];

function trackedDocuments() {
  const out = execFileSync('git', ['ls-files', '-z', '*.md'], { cwd: ROOT, encoding: 'utf8' });
  return out.split('\0').filter(p => p && !EXCLUDED.some(re => re.test(p)));
}

function documents() {
  const built = GENERATED.filter(p => existsSync(path.join(ROOT, p)));
  return { all: [...trackedDocuments(), ...built].sort(), built };
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

/**
 * Puts the blank lines after a block of raw HTML (a generated file's "Do not edit" comment, say) back into its text.
 * marked 18 moved them into the space token that follows, which renders as nothing, so without this the next
 * element would sit on the comment's line - harmless in a browser, but a different page from the one marked 12 built.
 */
function keepBlankLinesAfterHtml(tokens) {
  tokens.forEach((token, i) => {
    const next = tokens[i + 1];
    if (token.type === 'html' && token.block && next && next.type === 'space') {
      token.text += next.raw;
    }
    if (token.tokens) {
      keepBlankLinesAfterHtml(token.tokens);
    }
    (token.items || []).forEach(item => keepBlankLinesAfterHtml(item.tokens));
  });
}

function render(doc, source, documents) {
  const seen = new Map();
  let title = null;
  const marked = new Marked({ gfm: true });
  // marked 13 and later hand each renderer its token; inline content is rendered with this.parser.parseInline.
  marked.use({
    hooks: {
      processAllTokens(tokens) {
        keepBlankLinesAfterHtml(tokens);
        return tokens;
      },
    },
    renderer: {
      heading({ tokens, depth }) {
        const text = this.parser.parseInline(tokens);
        let id = slug(text);
        const count = seen.get(id) || 0;
        seen.set(id, count + 1);
        if (count) {
          id = `${id}-${count}`;
        }
        if (depth === 1 && title === null) {
          title = plain(text).trim();
        }
        return `<h${depth} id="${id}">${text}</h${depth}>\n`;
      },
      code({ text, lang }) {
        if ((lang || '').trim() === 'mermaid') {
          return `<pre class="mermaid-src"><code>${escapeHtml(text)}</code></pre>\n`;
        }
        return false;
      },
      // marked 12 escaped a link's title, and an <angle-bracket> autolink's href, before this saw them, so a
      // title's & or " and an autolink's & came out escaped twice; marked 18 hands them over raw and they are
      // escaped once. No document had either when the pin moved.
      link({ href, title: linkTitle, tokens }) {
        const to = rewrite(href, doc, documents);
        const titled = linkTitle ? ` title="${escapeAttribute(linkTitle)}"` : '';
        return `<a href="${escapeAttribute(to)}"${titled}>${this.parser.parseInline(tokens)}</a>`;
      },
      hr() {
        return '<hr />\n';
      },
      // Tables sit in div.table-wrap, which the page scrolls sideways on a narrow screen.
      table({ header, rows }) {
        const head = this.tablerow({ text: header.map(cell => this.tablecell(cell)).join('') });
        const body = rows.map(row => this.tablerow({ text: row.map(cell => this.tablecell(cell)).join('') })).join('');
        return `<div class="table-wrap"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>\n`;
      },
      tablerow({ text }) {
        return `<tr>${text}</tr>`;
      },
      tablecell({ tokens, header, align }) {
        const content = this.parser.parseInline(tokens);
        if (header) {
          return align ? `<th style="text-align:${align}">${content}</th>` : `<th>${content}</th>`;
        }
        return `<td style="text-align:${align || 'left'}">${content}</td>`;
      },
    },
  });
  const html = plainApostrophes(marked.parse(source));
  return { title: title || doc, html };
}

function renderAll(documents) {
  const known = new Set(documents);
  const rendered = {};
  for (const doc of documents) {
    rendered[doc] = render(doc, readFileSync(path.join(ROOT, doc), 'utf8'), known);
  }
  return rendered;
}

if (process.argv.includes('--check')) {
  console.error('build-showcase-docs.mjs has no --check: showcase/docs.js is generated and not tracked, so there '
    + 'is nothing committed to compare it with. Build it, then run tools/check-showcase-links.py.');
  process.exit(2);
}

const { all, built } = documents();
const rendered = renderAll(all);
const file = '// Generated by tools/build-showcase-docs.mjs from the repository\'s Markdown; not tracked, do not edit.\n'
  + 'const DOCS_HTML = ' + JSON.stringify(rendered).replace(/<\//g, '<\\/') + ';\n';
writeFileSync(OUT, file);
const unbuilt = GENERATED.filter(p => !built.includes(p));
console.log(`wrote showcase/docs.js: ${all.length} documents`
  + (built.length ? `, including the generated ${built.join(', ')}` : '')
  + (unbuilt.length ? ` (without ${unbuilt.join(', ')}: not built here - python3 tools/coverage-report.py after mvn verify)` : ''));
