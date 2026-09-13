// Small helpers the Blazor client cannot do from C# alone.
window.veil = {
    scrollToBottom: (element) => {
        if (element) {
            element.scrollTop = element.scrollHeight;
        }
    },
    isNearBottom: (element) => !element || (element.scrollHeight - element.scrollTop - element.clientHeight) < 120,
    focus: (element) => element && element.focus(),
    deviceName: () => {
        const ua = navigator.userAgent;
        const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
        const os = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
        return (browser + " " + os).trim();
    },
    storageKeys: (prefix) => {
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k && k.startsWith(prefix)) keys.push(k);
        }
        return keys;
    },
    notify: (title, body) => {
        if (document.hasFocus() || !("Notification" in window)) return;
        if (Notification.permission === "granted") new Notification(title, { body });
    },
    requestNotifications: () => {
        if ("Notification" in window && Notification.permission === "default") Notification.requestPermission();
    }
};
