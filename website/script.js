// ── Nav scroll effect ─────────────────────────────────────────
const nav = document.getElementById('nav');
window.addEventListener('scroll', () => {
  nav.classList.toggle('scrolled', window.scrollY > 20);
}, { passive: true });

// ── Copy hero command ─────────────────────────────────────────
function copyCmd() {
  navigator.clipboard.writeText('npx @vidhaankhare/vibeguard scan .').then(() => {
    const btn = document.querySelector('.install-copy');
    btn.classList.add('copied');
    const orig = btn.innerHTML;
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 1800);
  });
}

// ── Copy any command (install cards) ─────────────────────────
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    // Find the button that was just clicked — it's the event target
    const btn = event.currentTarget;
    btn.classList.add('copied');
    const orig = btn.innerHTML;
    btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 1800);
  });
}

// ── Scroll-reveal observer ────────────────────────────────────
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.08, rootMargin: '0px 0px -32px 0px' });

document.querySelectorAll(
  '.crisis-card, .feature-card, .step, .install-card, .coverage-item'
).forEach((el, i) => {
  el.classList.add('reveal');
  el.style.transitionDelay = `${(i % 4) * 60}ms`;
  revealObserver.observe(el);
});

// ── Hero typewriter ───────────────────────────────────────────
const heroCmd = document.getElementById('hero-cmd');
if (heroCmd) {
  const text = 'npx @vidhaankhare/vibeguard scan .';
  heroCmd.textContent = '';
  let i = 0;
  const type = () => {
    if (i < text.length) {
      heroCmd.textContent += text[i++];
      setTimeout(type, 55 + Math.random() * 45);
    }
  };
  setTimeout(type, 700);
}

// ── Smooth scroll for anchor links ───────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', e => {
    const target = document.querySelector(anchor.getAttribute('href'));
    if (target) {
      e.preventDefault();
      const top = target.getBoundingClientRect().top + window.scrollY - 80;
      window.scrollTo({ top, behavior: 'smooth' });
    }
  });
});
