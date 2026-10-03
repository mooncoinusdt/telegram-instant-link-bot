import { TelegramClient, Api } from "teleproto";
import { StringSession } from "teleproto/sessions";
import bigInt from "big-integer";
import { Buffer } from "node:buffer";

const LINK_TTL_MS = 60 * 60 * 1000; // 1 hour
const DOWNLOAD_CHUNK_SIZE = 512 * 1024; // 512 KiB
const SESSION_KEY = "__mtproto_session";

let telegramClient = null;
let telegramClientPromise = null;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function text(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

function randomToken(bytes = 18) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  let binary = "";
  for (const b of data) binary += String.fromCharCode(b);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64UrlDecodeToBytes(value) {
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function hmacKey(secret, usages) {
  if (!secret) throw new Error("DOWNLOAD_SIGNING_SECRET is missing.");
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    usages,
  );
}

async function makeDownloadToken(data, secret) {
  const payload = base64UrlEncodeBytes(
    new TextEncoder().encode(JSON.stringify(data)),
  );
  const key = await hmacKey(secret, ["sign"]);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload),
  );
  return `${payload}.${base64UrlEncodeBytes(new Uint8Array(signature))}`;
}

async function readDownloadToken(token, secret) {
  const dot = token.lastIndexOf(".");
  if (dot <= 0 || dot >= token.length - 1) return null;

  const payload = token.slice(0, dot);
  const signature = token.slice(dot + 1);

  try {
    const key = await hmacKey(secret, ["verify"]);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecodeToBytes(signature),
      new TextEncoder().encode(payload),
    );
    if (!valid) return null;
  } catch {
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(
      new TextDecoder().decode(base64UrlDecodeToBytes(payload)),
    );
  } catch {
    return null;
  }

  const expiresAt = Number(parsed?.e);
  const messageId = Number(parsed?.m);
  if (!parsed?.c || !Number.isSafeInteger(messageId) || messageId <= 0) {
    return null;
  }
  if (!Number.isFinite(expiresAt) || Date.now() >= expiresAt) return null;

  return {
    chatId: String(parsed.c),
    messageId,
  };
}

function safeFilename(name) {
  const fallback = "download.bin";
  if (!name) return fallback;
  const cleaned = String(name)
    .replace(/[\\\r\n"\u0000]/g, "_")
    .trim();
  return cleaned || fallback;
}

function mediaInfoFromBotMessage(message) {
  const document = message?.document || message?.media?.document;
  if (!document) return null;

  let filename = "download.bin";
  try {
    filename = safeFilename(
      message.file?.name ||
      message.fileName ||
      document.fileName ||
      (message.video ? "video.mp4" : "download.bin"),
    );
  } catch {
    filename = "download.bin";
  }

  return {
    message,
    document,
    filename,
    mimeType: document.mimeType || "application/octet-stream",
    size: Number(document.size),
  };
}

function parseRange(header, totalSize) {
  if (!header) {
    return { start: 0, end: totalSize - 1, partial: false };
  }
  if (!/^bytes=\d*-\d*$/.test(header)) return null;

  const value = header.slice(6);
  const [left, right] = value.split("-");
  let start;
  let end;

  if (left === "") {
    const suffixLength = Number(right);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return null;
    start = Math.max(totalSize - suffixLength, 0);
    end = totalSize - 1;
  } else {
    start = Number(left);
    if (!Number.isSafeInteger(start) || start < 0 || start >= totalSize) return null;
    end = right === "" ? totalSize - 1 : Number(right);
    if (!Number.isSafeInteger(end) || end < start) return null;
    end = Math.min(end, totalSize - 1);
  }

  return { start, end, partial: true };
}

function toBuffer(value) {
  if (value == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return Buffer.from(value);
  if (value?.type === "Buffer" && Array.isArray(value.data)) {
    return Buffer.from(value.data);
  }
  return Buffer.from(value);
}

function idString(value) {
  if (value == null) return "";
  return typeof value === "object" && typeof value.toString === "function"
    ? value.toString()
    : String(value);
}

function replyMessage(chatId, messageId, textValue, url = null) {
  const body = {
    method: "sendMessage",
    chat_id: chatId,
    text: textValue,
    link_preview_options: { is_disabled: true },
  };

  if (messageId) {
    body.reply_parameters = { message_id: messageId };
  }

  if (url) {
    body.reply_markup = {
      inline_keyboard: [[{ text: "⬇️ دانلود مستقیم", url }]],
    };
  }

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function isAllowedUser(message, env) {
  const allowed = String(env.ALLOWED_USER_ID || "").trim();
  if (!allowed) return true;
  return String(message?.from?.id || "") === allowed;
}

async function getTelegramClient(env) {
  if (telegramClient?.connected) return telegramClient;
  if (telegramClientPromise) return telegramClientPromise;

  telegramClientPromise = (async () => {
    if (!env.API_ID || !env.API_HASH || !env.BOT_TOKEN) {
      throw new Error("BOT_TOKEN / API_ID / API_HASH is missing.");
    }

    const saved = await env.STORE.get(SESSION_KEY);
    const client = new TelegramClient(
      new StringSession(saved || ""),
      Number(env.API_ID),
      env.API_HASH,
      {
        connectionRetries: 8,
        autoReconnect: true,
      },
    );

    client.setLogLevel("none");

    if (saved) {
      await client.connect();
    } else {
      // Log in as the bot account once, then keep only the small MTProto
      // session string in KV. No media is stored in KV/R2.
      await client.start({ botToken: env.BOT_TOKEN });
      const session = client.session.save();
      await env.STORE.put(SESSION_KEY, session);
    }

    telegramClient = client;
    return client;
  })();

  try {
    return await telegramClientPromise;
  } finally {
    telegramClientPromise = null;
  }
}

async function ensureDialogEntity(client, chatId) {
  try {
    return await client.getInputEntity(chatId);
  } catch {
    // On a cold worker, warm the entity cache from the bot account's dialogs.
  }

  const dialogs = await client.getDialogs({});
  for (const dialog of dialogs) {
    if (idString(dialog.id) !== idString(chatId)) continue;
    try {
      return await client.getInputEntity(dialog.entity);
    } catch {
      // Continue to the numeric fallback below.
    }
  }

  return await client.getInputEntity(chatId);
}

async function loadDocumentFromBotChat(client, chatId, messageId) {
  const peer = await ensureDialogEntity(client, chatId);
  const messages = await client.getMessages(peer, { ids: [messageId] });
  const message = messages?.[0];
  if (!message) throw new Error("Telegram message not found.");

  const media = mediaInfoFromBotMessage(message);
  if (!media) throw new Error("This message has no downloadable file.");
  return media;
}

async function streamDownload(request, env, token) {
  const mapping = await readDownloadToken(
    token,
    env.DOWNLOAD_SIGNING_SECRET,
  );
  if (!mapping) return text("Link expired or invalid.", 404);

  const client = await getTelegramClient(env);
  const media = await loadDocumentFromBotChat(
    client,
    mapping.chatId,
    mapping.messageId,
  );

  const totalSize = media.size;
  if (!Number.isSafeInteger(totalSize) || totalSize <= 0) {
    return text("Invalid Telegram file size.", 500);
  }

  const range = parseRange(request.headers.get("Range"), totalSize);
  if (!range) {
    return new Response(null, {
      status: 416,
      headers: {
        "Content-Range": `bytes */${totalSize}`,
        "Accept-Ranges": "bytes",
      },
    });
  }

  const contentLength = range.end - range.start + 1;
  const inputLocation = new Api.InputDocumentFileLocation({
    id: bigInt(media.document.id),
    accessHash: bigInt(media.document.accessHash),
    fileReference: toBuffer(media.document.fileReference),
    thumbSize: "",
  });

  const headers = new Headers({
    "Content-Type": media.mimeType,
    "Content-Length": String(contentLength),
    "Accept-Ranges": "bytes",
    "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(media.filename)}`,
    "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff",
  });

  if (range.partial) {
    headers.set(
      "Content-Range",
      `bytes ${range.start}-${range.end}/${totalSize}`,
    );
  }

  const status = range.partial ? 206 : 200;
  if (request.method === "HEAD") {
    return new Response(null, { status, headers });
  }

  const iterator = client.iterDownload({
    file: inputLocation,
    offset: bigInt(range.start),
    limit: bigInt(contentLength),
    requestSize: DOWNLOAD_CHUNK_SIZE,
    chunkSize: DOWNLOAD_CHUNK_SIZE,
  });

  const stream = new ReadableStream({
    async pull(controller) {
      try {
        const next = await iterator.next();
        if (next.done) {
          controller.close();
          return;
        }
        controller.enqueue(new Uint8Array(next.value));
      } catch (error) {
        controller.error(error);
      }
    },
    cancel() {
      try {
        iterator.return?.();
      } catch {
        // Ignore cancellation errors.
      }
    },
  });

  return new Response(stream, { status, headers });
}

async function handleWebhook(request, env) {
  if (request.method !== "POST") return text("Method Not Allowed", 405);

  const suppliedSecret =
    request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  if (!env.WEBHOOK_SECRET || suppliedSecret !== env.WEBHOOK_SECRET) {
    return text("Unauthorized", 401);
  }

  const update = await request.json();
  const message = update?.message;
  if (!message) return text("OK");

  if (!isAllowedUser(message, env)) return text("OK");

  const chatId = message.chat?.id;
  const messageId = message.message_id;
  if (!chatId || !messageId) return text("OK");

  if (message.text === "/start") {
    return replyMessage(
      chatId,
      messageId,
      "سلام! 🎬\n\nیک فایل یا ویدیو را همین‌جا Forward کن تا لینک دانلود مستقیم بسازم.\n\n⏳ لینک‌ها ۱ ساعت اعتبار دارند.",
    );
  }

  if (message.text === "/id") {
    return replyMessage(
      chatId,
      messageId,
      `شناسه عددی تلگرام شما:\n${message.from?.id || "نامشخص"}`,
    );
  }

  const media = mediaInfoFromBotMessage(message);
  if (!media) return text("OK");

  const expiresAt = Date.now() + LINK_TTL_MS;
  const token = await makeDownloadToken(
    {
      c: String(chatId),
      m: messageId,
      e: expiresAt,
      n: randomToken(10),
    },
    env.DOWNLOAD_SIGNING_SECRET,
  );

  const origin = new URL(request.url).origin;
  const link = `${origin}/dl/${token}/download`;
  const sizeGiB = media.size / (1024 ** 3);
  const sizeText = Number.isFinite(sizeGiB)
    ? `\n📦 حجم: ${sizeGiB.toFixed(2)} GB`
    : "";

  return replyMessage(
    chatId,
    messageId,
    `✅ لینک آماده شد!\n\n📁 ${media.filename}${sizeText}\n⏳ اعتبار: ۱ ساعت`,
    link,
  );
}

function health(env) {
  return json({
    ok: true,
    service: "telegram-instant-link-bot",
    link_ttl_seconds: LINK_TTL_MS / 1000,
    file_storage_on_cloudflare: false,
    configured: Boolean(
      env.BOT_TOKEN &&
      env.API_ID &&
      env.API_HASH &&
      env.WEBHOOK_SECRET &&
      env.DOWNLOAD_SIGNING_SECRET,
    ),
  });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (url.pathname === "/" || url.pathname === "/health") {
        return health(env);
      }

      if (url.pathname === "/telegram-webhook") {
        return await handleWebhook(request, env);
      }

      if (url.pathname.startsWith("/dl/")) {
        const token = url.pathname.slice("/dl/".length).split("/")[0];
        if (!token || token.length < 40) return text("Not Found", 404);
        return await streamDownload(request, env, token);
      }

      return text("Not Found", 404);
    } catch (error) {
      console.error(error);
      return text(`Worker error: ${error?.message || "unknown error"}`, 500);
    }
  },
};
