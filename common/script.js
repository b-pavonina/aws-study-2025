document.addEventListener('DOMContentLoaded', function () {
  // 自動で <h3> に id を追加する
  const content = document.querySelector('.content');
  if (content) {
    const headings = content.querySelectorAll('h3');
    headings.forEach((h) => {
      if (!h.id) {
        const id = h.textContent
          .trim()
          .replace(/\s+/g, '-')
          .replace(/[^\w\-一-龯ぁ-んァ-ヴーａ-ｚＡ-Ｚ０-９ー]/g, '');
        h.id = id;
      }
    });
  }

  const tocLinks = document.querySelectorAll('.toc a');
  tocLinks.forEach((link) => {
    link.addEventListener('click', function (e) {
      const id = decodeURIComponent(this.getAttribute('href')).replace('#', '');
      const target = document.getElementById(id);
      if (target) {
        e.preventDefault();
        const topOffset = target.getBoundingClientRect().top + window.scrollY;
        window.scrollTo({
          top: topOffset - 20,
          behavior: 'smooth',
        });
      }
    });
  });

  // --- Copyボタン機能 ---
  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', function () {
      // 直後または直前の .code-block を探す
      let codeBlock = btn.nextElementSibling;
      if (!codeBlock || !codeBlock.classList.contains('code-block')) {
        codeBlock = btn.previousElementSibling;
      }
      if (!codeBlock || !codeBlock.classList.contains('code-block')) {
        // さらに親要素内で探す
        codeBlock = btn.parentElement.querySelector('.code-block');
      }
      if (codeBlock) {
        navigator.clipboard.writeText(codeBlock.textContent).then(() => {
          const original = btn.textContent;
          btn.textContent = 'コピーしました!';
          btn.disabled = true;
          setTimeout(() => {
            btn.textContent = original;
            btn.disabled = false;
          }, 1200);
        });
      }
    });
  });
});
