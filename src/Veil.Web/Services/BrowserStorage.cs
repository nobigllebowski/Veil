using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace Veil.Web.Services;

/// <summary>Where the API lives. The UI is normally served by the API, so this is the page origin.</summary>
public sealed record ApiEndpoint(Uri BaseAddress);

/// <summary>Thin JS interop layer over Web Storage and a few DOM helpers.</summary>
public sealed class BrowserStorage(IJSRuntime js)
{
    public ValueTask<string?> GetLocalAsync(string key) => js.InvokeAsync<string?>("localStorage.getItem", key);
    public ValueTask SetLocalAsync(string key, string value) => js.InvokeVoidAsync("localStorage.setItem", key, value);
    public ValueTask RemoveLocalAsync(string key) => js.InvokeVoidAsync("localStorage.removeItem", key);
    public ValueTask<string[]> ListLocalKeysAsync(string prefix) => js.InvokeAsync<string[]>("veil.storageKeys", prefix);

    public ValueTask<string?> GetSessionAsync(string key) => js.InvokeAsync<string?>("sessionStorage.getItem", key);
    public ValueTask SetSessionAsync(string key, string value) => js.InvokeVoidAsync("sessionStorage.setItem", key, value);
    public ValueTask RemoveSessionAsync(string key) => js.InvokeVoidAsync("sessionStorage.removeItem", key);

    public ValueTask<string> DeviceNameAsync() => js.InvokeAsync<string>("veil.deviceName");
    public ValueTask ScrollToBottomAsync(ElementReference element) => js.InvokeVoidAsync("veil.scrollToBottom", element);
    public ValueTask<bool> IsNearBottomAsync(ElementReference element) => js.InvokeAsync<bool>("veil.isNearBottom", element);
    public ValueTask FocusAsync(ElementReference element) => js.InvokeVoidAsync("veil.focus", element);
    public ValueTask NotifyAsync(string title, string body) => js.InvokeVoidAsync("veil.notify", title, body);
    public ValueTask RequestNotificationsAsync() => js.InvokeVoidAsync("veil.requestNotifications");
}
