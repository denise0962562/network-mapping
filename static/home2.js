// 全局变量
let refreshInterval;
let logUpdateInterval;

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    startAutoRefresh();
    startLogUpdates();
    initScrollEffects();
});

// 初始化滚动效果
function initScrollEffects() {
    let ticking = false;
    
    function updateScrollEffect() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        // 当滚动超过50像素时显示模糊效果
        if (scrollTop > 50) {
            document.body.classList.add('scrolled');
        } else {
            document.body.classList.remove('scrolled');
        }
        
        ticking = false;
    }
    
    function onScroll() {
        if (!ticking) {
            requestAnimationFrame(updateScrollEffect);
            ticking = true;
        }
    }
    
    // 添加滚动事件监听器
    window.addEventListener('scroll', onScroll, { passive: true });
    
    // 初始检查滚动位置
    updateScrollEffect();
}

// 初始化仪表盘
function initializeDashboard() {
    updateLastUpdateTime();
    loadSystemStatus();
    animateProgressBars();
}

// 刷新仪表盘
function refreshDashboard() {
    console.log('刷新仪表盘数据...');
    
    // 显示刷新动画
    const refreshBtn = document.querySelector('.refresh-btn');
    refreshBtn.style.transform = 'rotate(360deg)';
    refreshBtn.disabled = true;
    
    // 模拟数据更新
    setTimeout(() => {
        updateSystemStatus();
        updateScanningStats();
        updateTaskProgress();
        updateLastUpdateTime();
        addLog('系统数据已刷新', 'info');
        
        // 重置按钮状态
        refreshBtn.style.transform = 'rotate(0deg)';
        refreshBtn.disabled = false;
    }, 1000);
}

// 更新系统状态
function updateSystemStatus() {
    // 随机生成一些状态数据
    const cpuUsage = Math.floor(Math.random() * 40) + 30; // 30-70%
    const memUsage = Math.floor(Math.random() * 30) + 50;  // 50-80%
    
    // 更新CPU使用率
    const cpuProgress = document.querySelector('.status-card:first-child .progress-fill');
    const cpuText = document.querySelector('.status-card:first-child .progress-text');
    if (cpuProgress && cpuText) {
        cpuProgress.style.width = cpuUsage + '%';
        cpuText.textContent = cpuUsage + '%';
    }
    
    // 更新内存使用率
    const memProgress = document.querySelector('.status-card:first-child .progress-fill:last-of-type');
    const memText = document.querySelector('.status-card:first-child .progress-text:last-of-type');
    if (memProgress && memText) {
        memProgress.style.width = memUsage + '%';
        memText.textContent = memUsage + '%';
    }
}

// 更新扫描统计
function updateScanningStats() {
    const totalIPs = document.getElementById('totalIPs');
    if (totalIPs) {
        const currentCount = parseInt(totalIPs.textContent.replace(/,/g, ''));
        const newCount = currentCount + Math.floor(Math.random() * 100);
        totalIPs.textContent = newCount.toLocaleString();
    }
}

// 更新任务进度
function updateTaskProgress() {
    const taskProgress = document.querySelector('.task-progress .progress-fill');
    const taskText = document.querySelector('.task-progress .progress-text');
    
    if (taskProgress && taskText) {
        const currentProgress = parseInt(taskProgress.style.width);
        const newProgress = Math.min(currentProgress + Math.floor(Math.random() * 10), 100);
        taskProgress.style.width = newProgress + '%';
        taskText.textContent = newProgress + '%';
        
        // 如果任务完成，更新状态
        if (newProgress >= 100) {
            const taskStatus = document.querySelector('.task-status.running');
            if (taskStatus) {
                taskStatus.textContent = '已完成';
                taskStatus.className = 'task-status completed';
            }
        }
    }
}

// 更新最后更新时间
function updateLastUpdateTime() {
    const lastUpdate = document.getElementById('lastUpdate');
    if (lastUpdate) {
        lastUpdate.textContent = new Date().toLocaleString('zh-CN');
    }
}

// 加载系统状态
function loadSystemStatus() {
    // 模拟加载系统状态
    setTimeout(() => {
        const scannerStatus = document.getElementById('scannerStatus');
        const dbStatus = document.getElementById('dbStatus');
        
        if (scannerStatus) {
            scannerStatus.textContent = '在线';
            scannerStatus.className = 'status-indicator online';
        }
        
        if (dbStatus) {
            dbStatus.textContent = '正常';
            dbStatus.className = 'status-indicator online';
        }
    }, 500);
}

// 动画化进度条
function animateProgressBars() {
    const progressBars = document.querySelectorAll('.progress-fill');
    progressBars.forEach(bar => {
        const width = bar.style.width;
        bar.style.width = '0%';
        setTimeout(() => {
            bar.style.width = width;
        }, 100);
    });
}

// 添加日志
function addLog(message, type = 'info') {
    const logContainer = document.getElementById('logContainer');
    if (!logContainer) return;
    
    const timestamp = new Date().toLocaleString('zh-CN');
    const logItem = document.createElement('div');
    logItem.className = `log-item ${type}`;
    logItem.textContent = `[${timestamp}] ${message}`;
    
    // 添加到日志容器顶部
    logContainer.insertBefore(logItem, logContainer.firstChild);
    
    // 限制日志数量，保留最新的50条
    const logItems = logContainer.querySelectorAll('.log-item');
    if (logItems.length > 50) {
        logContainer.removeChild(logItems[logItems.length - 1]);
    }
    
    // 自动滚动到顶部
    logContainer.scrollTop = 0;
}

// 清空日志
function clearLogs() {
    const logContainer = document.getElementById('logContainer');
    if (logContainer) {
        logContainer.innerHTML = '';
        addLog('日志已清空', 'info');
    }
}

// 过滤活动
function filterActivity(period) {
    console.log('过滤活动:', period);
    // 这里可以根据时间段过滤活动数据
    addLog(`活动过滤器设置为: ${period}`, 'info');
}

// 开始自动刷新
function startAutoRefresh() {
    // 每30秒自动刷新一次数据
    refreshInterval = setInterval(() => {
        updateSystemStatus();
        updateScanningStats();
    }, 30000);
}

// 开始日志更新
function startLogUpdates() {
    const logMessages = [
        '扫描进程正在运行',
        '发现新的网络设备',
        '数据库备份完成',
        '系统性能检查通过',
        '端口扫描任务启动',
        '服务识别完成',
        '漏洞数据库更新'
    ];
    
    const logTypes = ['info', 'success', 'warning'];
    
    // 每1-3分钟随机添加一条日志
    logUpdateInterval = setInterval(() => {
        const randomMessage = logMessages[Math.floor(Math.random() * logMessages.length)];
        const randomType = logTypes[Math.floor(Math.random() * logTypes.length)];
        addLog(randomMessage, randomType);
    }, Math.random() * 120000 + 60000); // 1-3分钟随机间隔
}

// 停止自动刷新
function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
    
    if (logUpdateInterval) {
        clearInterval(logUpdateInterval);
        logUpdateInterval = null;
    }
}

// 导航菜单点击处理
function handleNavigation(target) {
    // 移除所有导航项的active类
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // 为点击的项添加active类
    if (target.classList.contains('nav-item')) {
        target.classList.add('active');
        addLog(`切换到页面: ${target.textContent}`, 'info');
    }
}

// 系统状态监控
function monitorSystemHealth() {
    // 模拟系统健康检查
    const checks = [
        { name: '扫描器服务', status: Math.random() > 0.1 },
        { name: 'PostgreSQL数据库', status: Math.random() > 0.05 },
        { name: '网络连接', status: Math.random() > 0.02 },
        { name: '磁盘空间', status: Math.random() > 0.1 }
    ];
    
    checks.forEach(check => {
        if (!check.status) {
            addLog(`警告: ${check.name}状态异常`, 'warning');
        }
    });
}

// 模拟实时数据更新
function simulateRealTimeData() {
    // 模拟扫描进度更新
    const scanTasks = document.querySelectorAll('.task-item');
    scanTasks.forEach(task => {
        const status = task.querySelector('.task-status');
        const progress = task.querySelector('.progress-fill');
        
        if (status && status.classList.contains('running') && progress) {
            const currentWidth = parseInt(progress.style.width) || 0;
            const newWidth = Math.min(currentWidth + Math.random() * 5, 100);
            progress.style.width = newWidth + '%';
            progress.parentElement.querySelector('.progress-text').textContent = Math.floor(newWidth) + '%';
            
            if (newWidth >= 100) {
                status.textContent = '已完成';
                status.className = 'task-status completed';
                addLog(`任务完成: ${task.querySelector('.task-name').textContent}`, 'success');
            }
        }
    });
}

// 性能指标更新
function updatePerformanceMetrics() {
    const metrics = {
        cpu: Math.floor(Math.random() * 30) + 40, // 40-70%
        memory: Math.floor(Math.random() * 25) + 55, // 55-80%
        network: Math.floor(Math.random() * 50) + 20, // 20-70%
        disk: Math.floor(Math.random() * 15) + 10 // 10-25%
    };
    
    // 更新CPU使用率
    updateProgressBar('.status-card:first-child .metric:nth-of-type(2) .progress-fill', metrics.cpu);
    
    // 更新内存使用率  
    updateProgressBar('.status-card:first-child .metric:nth-of-type(3) .progress-fill', metrics.memory);
    
    // 如果使用率过高，添加警告日志
    if (metrics.cpu > 80) {
        addLog('警告: CPU使用率过高 (' + metrics.cpu + '%)', 'warning');
    }
    
    if (metrics.memory > 85) {
        addLog('警告: 内存使用率过高 (' + metrics.memory + '%)', 'warning');
    }
}

// 更新进度条辅助函数
function updateProgressBar(selector, percentage) {
    const progressBar = document.querySelector(selector);
    const progressText = document.querySelector(selector.replace('.progress-fill', '.progress-text'));
    
    if (progressBar) {
        progressBar.style.width = percentage + '%';
    }
    
    if (progressText) {
        progressText.textContent = percentage + '%';
    }
}

// 添加事件监听器
document.addEventListener('click', function(e) {
    // 处理导航点击
    if (e.target.classList.contains('nav-item')) {
        e.preventDefault();
        handleNavigation(e.target);
    }
    
    // 处理退出登录
    if (e.target.classList.contains('logout-btn')) {
        if (confirm('确定要退出登录吗？')) {
            addLog('用户退出登录', 'info');
            // 这里可以重定向到登录页面
            // window.location.href = 'login.html';
        }
    }
});

// 页面卸载时清理定时器
window.addEventListener('beforeunload', function() {
    stopAutoRefresh();
});

// 定期执行系统监控
setInterval(monitorSystemHealth, 300000); // 每5分钟检查一次
setInterval(simulateRealTimeData, 10000);  // 每10秒更新一次实时数据
setInterval(updatePerformanceMetrics, 15000); // 每15秒更新性能指标

// 初始执行一次监控
setTimeout(monitorSystemHealth, 5000);

// 键盘快捷键支持
document.addEventListener('keydown', function(e) {
    // Ctrl+R 刷新仪表盘
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        refreshDashboard();
    }
    
    // Ctrl+L 清空日志
    if (e.ctrlKey && e.key === 'l') {
        e.preventDefault();
        clearLogs();
    }
});

// 工具函数：格式化数字
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// 工具函数：获取随机颜色
function getRandomColor() {
    const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
    return colors[Math.floor(Math.random() * colors.length)];
}

// 工具函数：计算时间差
function getTimeDifference(timestamp) {
    const now = new Date();
    const diff = now - new Date(timestamp);
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}天前`;
    if (hours > 0) return `${hours}小时前`;
    if (minutes > 0) return `${minutes}分钟前`;
    return '刚刚';
}