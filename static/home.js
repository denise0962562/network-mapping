document.addEventListener("DOMContentLoaded", () => {
    const navItems = document.querySelectorAll(".nav-item");
    const pages = document.querySelectorAll(".page");
    const ipCountElem = document.getElementById("ip-count");
    const navLinks = document.querySelector(".nav-links");
    const navSlider = document.querySelector(".nav-slider");

    // 初始化滑动条位置
    function updateNavSlider(activeItem) {
    const navRect = navLinks.getBoundingClientRect();
    const itemRect = activeItem.getBoundingClientRect();
    navSlider.style.width = itemRect.width + "px";
    navSlider.style.left = (itemRect.left - navRect.left) + "px";
    navSlider.style.height = activeItem.offsetHeight + "px"; // 高度同步
    navSlider.style.bottom = "8px"; // 你可以调整为css里一样的8px
}
    // 初始定位
    const activeNav = document.querySelector(".nav-item.active");
    if (activeNav) updateNavSlider(activeNav);

    // 导航切换
    navItems.forEach((item) => {
        item.addEventListener("click", () => {
            navItems.forEach((nav) => nav.classList.remove("active"));
            item.classList.add("active");

            updateNavSlider(item);

            const target = item.getAttribute("data-page");
            pages.forEach((page) => {
                page.classList.toggle("active", page.id === target);
            });
        });
    });

    // 模拟动态数字动画函数
    function animateCount(elem, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            elem.textContent = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                requestAnimationFrame(step);
            }
        };
        requestAnimationFrame(step);
    }

    // 模拟 IP 数字动态增长
    let currentCount = 0;
    setInterval(() => {
        const increment = Math.floor(Math.random() * 20 + 10);
        const newCount = currentCount + increment;
        animateCount(ipCountElem, currentCount, newCount, 800);
        currentCount = newCount;
    }, 3000);

    // 扫描任务添加表单提交逻辑
    const form = document.getElementById("task-form");
    const taskList = document.getElementById("task-list");

    form.addEventListener("submit", (e) => {
        e.preventDefault();

        const target = form.target.value.trim();
        const priority = form.priority.value;
        const ports = form.ports.value.trim();

        if (!target || !priority || !ports) {
            alert("请填写完整所有字段");
            return;
        }

        // 新任务 DOM
        const taskItem = document.createElement("div");
        taskItem.className = "task-item";
        taskItem.innerHTML = `
            <span>目标: ${target}</span>
            <span>优先级: ${priority}</span>
            <span>端口: ${ports}</span>
        `;

        taskList.appendChild(taskItem);

        // 重置表单
        form.reset();
    });
});
