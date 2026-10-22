"""
Module Quản Lý PWA Cho RC4 Lab (src/ui/pwa.py)
==============================================
Quản lý Web App Manifest, Service Worker, Favicon và tương tác cài đặt PWA (Install Prompt).
"""

import os
from nicegui import app, ui
from starlette.responses import FileResponse

STATIC_PWA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "static", "pwa")


def setup_pwa_routes() -> None:
    """Đăng ký các route phục vụ PWA qua FastAPI / Starlette."""
    # 1. Phục vụ thư mục static/pwa
    if os.path.exists(STATIC_PWA_DIR):
        app.add_static_files("/static/pwa", STATIC_PWA_DIR)

    # 2. Phục vụ manifest.webmanifest
    @app.get("/manifest.webmanifest")
    def get_manifest():
        manifest_path = os.path.join(STATIC_PWA_DIR, "manifest.webmanifest")
        return FileResponse(
            manifest_path,
            media_type="application/manifest+json",
            headers={"Cache-Control": "no-cache"}
        )

    # 3. Phục vụ sw.js ở root với phạm vi (scope) toàn bộ trang
    @app.get("/sw.js")
    def get_service_worker():
        sw_path = os.path.join(STATIC_PWA_DIR, "sw.js")
        return FileResponse(
            sw_path,
            media_type="application/javascript",
            headers={
                "Service-Worker-Allowed": "/",
                "Cache-Control": "no-cache"
            }
        )

    # 4. Phục vụ favicon.ico
    @app.get("/favicon.ico")
    def get_favicon():
        fav_path = os.path.join(STATIC_PWA_DIR, "favicon.ico")
        if os.path.exists(fav_path):
            return FileResponse(fav_path, media_type="image/x-icon")
        return FileResponse(os.path.join(STATIC_PWA_DIR, "icon-192.png"), media_type="image/png")


def inject_pwa_head_tags() -> None:
    """Nhúng các thẻ meta, manifest và script Service Worker vào Head HTML."""
    ui.add_head_html(
        """
        <!-- PWA Primary Meta Tags -->
        <link rel="manifest" href="/manifest.webmanifest">
        <meta name="theme-color" content="#0f172a">
        <meta name="application-name" content="RC4 Lab">
        
        <!-- Apple Mobile Web App Meta Tags -->
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
        <meta name="apple-mobile-web-app-title" content="RC4 Lab">
        <link rel="apple-touch-icon" href="/static/pwa/icon-192.png">
        <link rel="icon" type="image/png" sizes="192x192" href="/static/pwa/icon-192.png">
        <link rel="icon" type="image/x-icon" href="/favicon.ico">

        <!-- PWA Service Worker Registration & Install Prompt Handler -->
        <script>
            // 1. Đăng ký Service Worker
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', () => {
                    navigator.serviceWorker.register('/sw.js', { scope: '/' })
                        .then((reg) => console.log('RC4 Lab: Service Worker registered with scope:', reg.scope))
                        .catch((err) => console.warn('RC4 Lab: Service Worker registration failed:', err));
                });
            }

            // 2. Quản lý sự kiện Cài Đặt Ứng Dụng (beforeinstallprompt)
            window.deferredPwaPrompt = null;
            window.addEventListener('beforeinstallprompt', (e) => {
                // Ngăn trình duyệt tự động hiển thị banner mặc định
                e.preventDefault();
                window.deferredPwaPrompt = e;
                console.log('RC4 Lab: beforeinstallprompt captured!');
                
                // Kích hoạt hiển thị nút cài đặt trong giao diện nếu có
                const btn = document.getElementById('pwa-install-btn');
                if (btn) {
                    btn.classList.remove('hidden');
                    btn.classList.add('flex');
                }
            });

            // Khi người dùng click nút Cài Đặt trong giao diện
            window.triggerPwaInstall = async function() {
                if (!window.deferredPwaPrompt) {
                    // Nếu đã ở trong standalone mode hoặc chưa bắt được prompt
                    if (window.matchMedia('(display-mode: standalone)').matches) {
                        alert('Ứng dụng RC4 Lab đã được cài đặt trên thiết bị của bạn!');
                    } else {
                        alert('Để cài đặt RC4 Lab:\\n- Trên Chrome/Edge máy tính: Click vào biểu tượng cài đặt trên thanh địa chỉ URL.\\n- Trên điện thoại: Nhấn Menu (3 chấm) -> Chọn "Thêm vào màn hình chính" (Install app).');
                    }
                    return;
                }
                const promptEvent = window.deferredPwaPrompt;
                promptEvent.prompt();
                const choiceResult = await promptEvent.userChoice;
                console.log('User PWA choice:', choiceResult.outcome);
                window.deferredPwaPrompt = null;
                
                const btn = document.getElementById('pwa-install-btn');
                if (btn && choiceResult.outcome === 'accepted') {
                    btn.classList.add('hidden');
                }
            };

            // Khi ứng dụng đã được cài đặt thành công
            window.addEventListener('appinstalled', (evt) => {
                console.log('RC4 Lab: App installed successfully!');
                const btn = document.getElementById('pwa-install-btn');
                if (btn) btn.classList.add('hidden');
            });
        </script>
        """
    )
