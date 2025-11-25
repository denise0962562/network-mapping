function togglePassword() {
    const passwordInput = document.getElementById('password');
    const toggleBtn = passwordInput.nextElementSibling;
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleBtn.textContent = '隐藏';
    } else {
        passwordInput.type = 'password';
        toggleBtn.textContent = '显示';
    }
}

function toggleRegPassword() {
    const passwordInput = document.getElementById('regPassword');
    const toggleBtn = passwordInput.nextElementSibling;
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleBtn.textContent = '隐藏';
    } else {
        passwordInput.type = 'password';
        toggleBtn.textContent = '显示';
    }
}

function toggleConfirmPassword() {
    const passwordInput = document.getElementById('confirmPassword');
    const toggleBtn = passwordInput.nextElementSibling;
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleBtn.textContent = '隐藏';
    } else {
        passwordInput.type = 'password';
        toggleBtn.textContent = '显示';
    }
}

// function switchToRegister() {
//     const loginPage = document.getElementById('loginPage');
//     const registerPage = document.getElementById('registerPage');
    
//     // 清理之前的动画类
//     loginPage.classList.remove('slide-out-left', 'slide-out-right', 'slide-in-left', 'slide-in-right');
//     registerPage.classList.remove('slide-out-left', 'slide-out-right', 'slide-in-left', 'slide-in-right');
    
//     // 登录页面滑出到左侧
//     loginPage.classList.add('slide-out-left');
    
//     setTimeout(() => {
//         loginPage.style.display = 'none';
//         registerPage.style.display = 'block';
        
//         // 注册页面从右侧滑入
//         registerPage.classList.add('slide-in-right');
        
//         // 立即触发动画
//         setTimeout(() => {
//             registerPage.classList.remove('slide-in-right');
//         }, 10);
//     }, 300);
// }

// function switchToLogin() {
//     const loginPage = document.getElementById('loginPage');
//     const registerPage = document.getElementById('registerPage');
    
//     // 清理之前的动画类
//     loginPage.classList.remove('slide-out-left', 'slide-out-right', 'slide-in-left', 'slide-in-right');
//     registerPage.classList.remove('slide-out-left', 'slide-out-right', 'slide-in-left', 'slide-in-right');
    
//     // 注册页面滑出到右侧
//     registerPage.classList.add('slide-out-right');
    
//     setTimeout(() => {
//         registerPage.style.display = 'none';
//         loginPage.style.display = 'block';
        
//         // 登录页面从左侧滑入
//         loginPage.classList.add('slide-in-left');
        
//         // 立即触发动画
//         setTimeout(() => {
//             loginPage.classList.remove('slide-in-left');
//         }, 10);
//     }, 300);
// }

function socialLogin(provider) {
    alert(`使用 ${provider} 登录功能将在此处实现`);
}

document.getElementById('loginForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const remember = document.getElementById('remember').checked;
    
    // 这里可以添加实际的登录逻辑
    console.log('登录信息:', { email, password, remember });

    document.getElementById('loadingOverlay').classList.remove('hidden');
    fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        // 如果 cookie 需要跨域发送，必须加上 credentials
        // credentials: 'include', 
        body: JSON.stringify({
            username: email,
            password: password,
            rememberme: remember
        })
    })
    .then(res => res.json())
    .then(data => {                 //接受json数据格式，且根据success参数判断
        if (data.success) {         //Set-Cookie: token=abc123; Path=/; Max-Age=3600; HttpOnly; Secure   
                                    // Max-Age：单位是秒（3600 = 1小时）Expires：具体时间点（GMT 格式）HttpOnly：JS 不能读取（更安全）Secure：只在 HTTPS 下传输

            alert('登录成功');
            window.location.href = '/home';
            // 后端设置了 Set-Cookie，浏览器会自动保存
        } else {
            alert('登录失败');
            document.getElementById('loadingOverlay').classList.add('hidden');
            // window.location.reload;
        }
    });
    
});

// document.getElementById('registerForm').addEventListener('submit', function(e) {
//     e.preventDefault();
    
//     const username = document.getElementById('regUsername').value;
//     const email = document.getElementById('regEmail').value;
//     const password = document.getElementById('regPassword').value;
//     const confirmPassword = document.getElementById('confirmPassword').value;
//     const agreeTerms = document.getElementById('agreeTerms').checked;
    
//     // 密码确认验证
//     if (password !== confirmPassword) {
//         alert('密码和确认密码不匹配！');
//         return;
//     }
    
//     // 这里可以添加实际的注册逻辑
//     console.log('注册信息:', { username, email, password, agreeTerms });
    
//     // 模拟注册过程
//     const registerBtn = e.target.querySelector('.login-btn');
//     registerBtn.textContent = '注册中...';
//     registerBtn.disabled = true;
    
//     setTimeout(() => {
//         alert('注册成功！');
//         registerBtn.textContent = '注册';
//         registerBtn.disabled = false;
//         // 注册成功后可以切换到登录页面
//         setTimeout(() => {
//             switchToLogin();
//         }, 500);
//     }, 1500);
// });

// 页面加载完成后清理动画类
document.addEventListener('DOMContentLoaded', function() {
    const pages = document.querySelectorAll('.page');
    pages.forEach(page => {
        page.addEventListener('transitionend', function() {
            // 清理所有动画类
            this.classList.remove('slide-out-left', 'slide-out-right', 'slide-in-left', 'slide-in-right');
        });
    });
});

// 为输入框添加动画效果
document.querySelectorAll('.form-input').forEach(input => {
    input.addEventListener('focus', function() {
        this.parentElement.style.transform = 'scale(1.02)';
    });
    
    input.addEventListener('blur', function() {
        this.parentElement.style.transform = 'scale(1)';
    });
});