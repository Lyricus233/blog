---
layout: compress
# WARNING: Don't use '//' to comment out code, use '{% comment %}' and '{% endcomment %}' instead.
---

{%- comment -%}
  See: <https://docs.mathjax.org/en/latest/options/input/tex.html#tex-options>
{%- endcomment -%}

MathJax = {
  loader: {   
    load: ['[tex]/ams', '[tex]/physics', '[tex]/color', '[tex]/colorv2', '[tex]/textmacros']
  },  
  tex: {
    inlineMath: [
      ['$', '$'],
      ['\\(', '\\)']
    ],
    displayMath: [
      ['$$', '$$'],
      ['\\[', '\\]']
    ],
    packages: { '[+]': ['ams', 'physics', 'color', 'colorv2', 'textmacros'] },
    tags: 'ams',
    processEscapes: true, 
    processEnvironments: true,
    macros: {
      'e': '\\mathrm{e}',
      'i': '\\mathrm{i}',
      'RR': '\\mathbb{R}',
      'ZZ': '\\mathbb{Z}',
      'QQ': '\\mathbb{Q}',
    }
  },
  svg: { fontCache: 'global'},
};