# WebPush
[![Nuget](https://badge.fury.io/nu/Viklover.WebPush.svg)](https://badge.fury.io/nu/Viklover.WebPush)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/viklover/Viklover.WebPush/blob/master/LICENSE.txt)
![Unit tests workflow](https://github.com/viklover/Viklover.WebPush/actions/workflows/unit-tests.yml/badge.svg)

Simple implementation of [Web Push](https://datatracker.ietf.org/doc/html/rfc8030) notification protocol for .NET.

## 📚 Features

- No external dependencies — only built-in .NET libraries
- Fully asynchronous API

## 🚀 Quick start

Installation:

```bash
dotnet add package Viklover.WebPush --version 1.0.1
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
