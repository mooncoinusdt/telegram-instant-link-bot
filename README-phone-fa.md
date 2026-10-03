# نسخه مخصوص گوشی

این نسخه عمداً فقط ۳ فایل اصلی دارد تا بتوانی آن‌ها را با GitHub روی گوشی بسازی/آپلود کنی:

- index.js
- package.json
- wrangler.jsonc

در GitHub، اگر آپلود پوشه ممکن نبود، از **Add file → Create new file** استفاده کن.

نام فایل‌ها:

1. `index.js`
2. `package.json`
3. `wrangler.jsonc`

محتویات هر سه فایل در همین پروژه هستند.

مقدار `REPLACE_WITH_YOUR_KV_NAMESPACE_ID` را بعداً با KV Namespace ID خودت عوض کن.

بعد از اتصال Repository به Cloudflare Workers Builds، Build command را خالی یا `npm install` و Deploy command را `npx wrangler deploy` بگذار.
