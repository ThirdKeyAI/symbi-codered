// Append a "Powered by Symbiont" line to the footer, linking to symbiont.dev
// in a new tab.
document.addEventListener('DOMContentLoaded', function () {
  if (document.querySelector('.codered-powered-by')) return;
  var footer = document.querySelector('.md-footer-meta__inner') || document.querySelector('.md-footer');
  if (!footer) return;
  var line = document.createElement('div');
  line.className = 'codered-powered-by';
  line.appendChild(document.createTextNode('Powered by '));
  var a = document.createElement('a');
  a.href = 'https://symbiont.dev';
  a.target = '_blank';
  a.rel = 'noopener';
  a.textContent = 'Symbiont';
  line.appendChild(a);
  footer.appendChild(line);
});
