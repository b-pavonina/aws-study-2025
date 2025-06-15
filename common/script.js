
document.addEventListener('DOMContentLoaded', function () {
    // 自動で <h3> に id を追加する
    const content = document.querySelector('.content');
    const headings = content.querySelectorAll('h3');
    headings.forEach(h => {
        if (!h.id) {
            const id = h.textContent.trim().replace(/\s+/g, '-').replace(/[^\w\-一-龯ぁ-んァ-ヴーａ-ｚＡ-Ｚ０-９ー]/g, '');
            h.id = id;
        }
    });

    const tocLinks = document.querySelectorAll('.toc a');
    tocLinks.forEach(link => {
        link.addEventListener('click', function (e) {
            const id = decodeURIComponent(this.getAttribute('href')).replace('#', '');
            const target = document.getElementById(id);
            if (target) {
                e.preventDefault();
                const topOffset = target.getBoundingClientRect().top + window.scrollY;
                window.scrollTo({
                    top: topOffset - 20,
                    behavior: 'smooth'
                });
            }
        });
    });
});
