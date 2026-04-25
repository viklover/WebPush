# <img src="Viklover.WebPush/logo.png" alt="drawing" width="32"/> WebPush
Simple implementation of [Web Push](https://datatracker.ietf.org/doc/html/rfc8030) notification protocol for .NET.

## 📚 Features

- No external dependencies — only built-in .NET libraries
- Fully asynchronous API

## 🚀 Quick start

Installation:

```bash
dotnet add package Viklover.WebPush --version 1.0.0
```

```csharp
// Use subscription received from browser
var subscription = new WebPushSubscription(
    endpoint: "https://push.example.com/...",
    auth: "base64-auth-secret",
    p256dh: "base64-public-key"
);

// Use your VAPID keys
var vapidKeys = new WebPushVapidKeys(
    publicKey: "base64-vapid-public-key",
    privateKey: "base64-vapid-private-key"
);

// Send notification
var client = new WebPushClient(vapidKeys, notificationTTL: TimeSpan.FromHours(24));
await client.SendAsync(subscription, "Hello user's service worker!", CancellationToken.None);
```

## 🛠️ Contribution

Contributions are welcome! Feel free to:

- Report bugs 🐛
- Suggest features 💡
- Submit pull requests 🔄
