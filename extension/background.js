// Background service worker for Phish Forensics Chrome Extension

function getAuthTokenWithRetry(interactive = true) {
  return new Promise((resolve) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        resolve({ success: false, error: chrome.runtime.lastError?.message || "Auth failed" });
      } else {
        resolve({ success: true, token });
      }
    });
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getAuthToken") {
    getAuthTokenWithRetry(request.interactive ?? true).then(sendResponse);
    return true;
  }

  if (request.action === "removeCachedToken") {
    if (request.token) {
      chrome.identity.removeCachedAuthToken({ token: request.token }, () => {
        sendResponse({ success: true });
      });
      return true;
    }
  }

  if (request.action === "analyzeDirect") {
    fetch("http://localhost:8000/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request.payload)
    })
      .then(res => res.json())
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }
});
