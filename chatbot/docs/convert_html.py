"""Convert HTML files to Markdown."""
import re
import html
from pathlib import Path


def html_to_md(html_content):
    """Convert HTML content to Markdown."""
    # Extract main content
    main_match = re.search(r'<main[^>]*>(.*?)</main>', html_content, re.DOTALL)
    if main_match:
        content = main_match.group(1)
    else:
        body_match = re.search(r'<body[^>]*>(.*?)</body>', html_content, re.DOTALL)
        content = body_match.group(1) if body_match else html_content

    # Remove nav, script, style, button, footer
    content = re.sub(r'<nav[^>]*>.*?</nav>', '', content, flags=re.DOTALL)
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL)
    content = re.sub(r'<style[^>]*>.*?</style>', '', content, flags=re.DOTALL)
    content = re.sub(r'<button[^>]*>.*?</button>', '', content, flags=re.DOTALL)
    content = re.sub(r'<footer[^>]*>.*?</footer>', '', content, flags=re.DOTALL)
    content = re.sub(r'<a[^>]*class="back-top"[^>]*>.*?</a>', '', content, flags=re.DOTALL)

    # Remove span classes but keep content
    content = re.sub(r'<span[^>]*class="[^"]*"[^>]*>(.*?)</span>', r'\1', content)

    # Remove step-num spans
    content = re.sub(r'<span class="step-num">\d+</span>', '', content)

    # Convert code blocks FIRST (before other processing)
    content = re.sub(r'<pre><code>(.*?)</code></pre>', lambda m: '\n```\n' + m.group(1).strip() + '\n```\n', content, flags=re.DOTALL)
    content = re.sub(r'<pre[^>]*>(.*?)</pre>', lambda m: '\n```\n' + m.group(1).strip() + '\n```\n', content, flags=re.DOTALL)

    # Convert inline code
    content = re.sub(r'<code>(.*?)</code>', r'`\1`', content)

    # Convert headings
    content = re.sub(r'<h1[^>]*>(.*?)</h1>', r'\n# \1\n', content, flags=re.DOTALL)
    content = re.sub(r'<h2[^>]*>(.*?)</h2>', r'\n## \1\n', content, flags=re.DOTALL)
    content = re.sub(r'<h3[^>]*>(.*?)</h3>', r'\n### \1\n', content, flags=re.DOTALL)
    content = re.sub(r'<h4[^>]*>(.*?)</h4>', r'\n#### \1\n', content, flags=re.DOTALL)

    # Convert images
    content = re.sub(r'<img[^>]*src="([^"]+)"[^>]*alt="([^"]*?)"[^>]*/?\s*>', r'![\2](\1)', content)
    content = re.sub(r'<img[^>]*src="([^"]+)"[^>]*/?\s*>', r'![](\1)', content)

    # Convert external links (keep href)
    content = re.sub(r'<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>', r'[\2](\1)', content)
    # Remove internal navigation links
    content = re.sub(r'<a[^>]*href="#[^"]*"[^>]*>(.*?)</a>', r'\1', content)

    # Convert tables
    def convert_table(match):
        table_html = match.group(0)
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', table_html, re.DOTALL)
        if not rows:
            return ''
        md_rows = []
        for i, row in enumerate(rows):
            cells = re.findall(r'<t[hd][^>]*>(.*?)</t[hd]>', row, re.DOTALL)
            cells = [re.sub(r'<[^>]+>', '', c).strip() for c in cells]
            md_rows.append('| ' + ' | '.join(cells) + ' |')
            if i == 0:
                md_rows.append('|' + '|'.join(['---' for _ in cells]) + '|')
        return '\n' + '\n'.join(md_rows) + '\n'

    content = re.sub(r'<table[^>]*>.*?</table>', convert_table, content, flags=re.DOTALL)

    # Convert callouts to blockquotes
    def convert_callout(match):
        inner = match.group(0)
        label_match = re.search(r'<div class="callout-label">(.*?)</div>', inner)
        label = label_match.group(1) if label_match else 'Note'
        inner = re.sub(r'<div class="callout-label">.*?</div>', '', inner)
        inner = re.sub(r'<[^>]+>', ' ', inner).strip()
        inner = re.sub(r'\s+', ' ', inner)
        return f'\n> **{label}:** {inner}\n'

    content = re.sub(r'<div class="callout[^"]*">.*?</div>\s*</div>', convert_callout, content, flags=re.DOTALL)

    # Convert prompt boxes
    def convert_prompt(match):
        inner = match.group(0)
        text = re.sub(r'<[^>]+>', '', inner).strip()
        return f'\n```\n{text}\n```\n'

    content = re.sub(r'<div class="prompt-box">.*?</div>', convert_prompt, content, flags=re.DOTALL)

    # Convert diagrams
    def convert_diagram(match):
        text = re.sub(r'<[^>]+>', '', match.group(0)).strip()
        return f'\n```\n{text}\n```\n'

    content = re.sub(r'<div class="diagram">.*?</div>', convert_diagram, content, flags=re.DOTALL)

    # Convert lists
    content = re.sub(r'<li[^>]*>(.*?)</li>', r'- \1\n', content, flags=re.DOTALL)
    content = re.sub(r'</?[uo]l[^>]*>', '', content)

    # Convert paragraphs
    content = re.sub(r'<p[^>]*>(.*?)</p>', r'\n\1\n', content, flags=re.DOTALL)

    # Convert bold/italic
    content = re.sub(r'<strong>(.*?)</strong>', r'**\1**', content)
    content = re.sub(r'<em>(.*?)</em>', r'*\1*', content)
    content = re.sub(r'<b>(.*?)</b>', r'**\1**', content)
    content = re.sub(r'<i>(.*?)</i>', r'*\1*', content)

    # Remove remaining HTML tags
    content = re.sub(r'<[^>]+>', '', content)

    # Decode HTML entities
    content = html.unescape(content)

    # Clean up whitespace
    content = re.sub(r'\n{4,}', '\n\n\n', content)
    content = re.sub(r'[ \t]+\n', '\n', content)
    content = re.sub(r'\n[ \t]+', '\n', content)
    lines = content.split('\n')
    # Don't strip leading spaces inside code blocks
    content = '\n'.join(lines)
    content = content.strip()

    return content


# Convert both files
for fname in ['hands-on-guide', 'kiro-course']:
    src = Path(f'D:/Documents/AWS/Chat_Athena/chatbot/docs/{fname}.html')
    dst = Path(f'D:/Documents/AWS/Chat_Athena/chatbot/docs/{fname}.md')
    html_content = src.read_text(encoding='utf-8')
    md_content = html_to_md(html_content)
    dst.write_text(md_content, encoding='utf-8')
    print(f'Converted: {fname}.html -> {fname}.md ({len(md_content)} chars)')

print("\nDone!")
