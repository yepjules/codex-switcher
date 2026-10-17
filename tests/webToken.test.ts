import assert from "node:assert/strict";
import test from "node:test";
import {
  WEB_TOKEN_STORAGE_KEY,
  captureWebTokenFromLocation,
  extractTokenFromHash,
  invokeBackend,
  isValidNewPassphrase,
  webAuthErrorMessage,
} from "../src/lib/platform.ts";

const AUTH_MESSAGE =
  "Web access token missing or invalid — reopen the URL printed by codex-web";

test("extractTokenFromHash parses the token fragment", () => {
  assert.equal(extractTokenFromHash("#token=abc"), "abc");
  assert.equal(extractTokenFromHash("#foo=1&token=abc"), "abc");
  assert.equal(extractTokenFromHash("#token=a%2Bb"), "a+b");
});

test("extractTokenFromHash returns null when absent or empty", () => {
  assert.equal(extractTokenFromHash(""), null);
  assert.equal(extractTokenFromHash("#foo=1"), null);
  assert.equal(extractTokenFromHash("#token="), null);
});

test("webAuthErrorMessage maps only 401", () => {
  assert.equal(webAuthErrorMessage(401), AUTH_MESSAGE);
  assert.equal(webAuthErrorMessage(400), null);
});

test("invokeBackend sends the bearer token and maps 401", async () => {
  const realFetch = globalThis.fetch;
  const sessionDesc = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  const store = new Map<string, string>([[WEB_TOKEN_STORAGE_KEY, "tok"]]);
  const calls: RequestInit[] = [];
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    },
  });
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    calls.push(init ?? {});
    return new Response("", { status: 401 });
  }) as typeof fetch;
  try {
    await assert.rejects(invokeBackend("list_accounts"), new Error(AUTH_MESSAGE));
    const headers = calls[0].headers as Record<string, string>;
    assert.equal(headers.Authorization, "Bearer tok");
    assert.equal(headers["Content-Type"], "application/json");
  } finally {
    globalThis.fetch = realFetch;
    if (sessionDesc) Object.defineProperty(globalThis, "sessionStorage", sessionDesc);
    else delete (globalThis as { sessionStorage?: unknown }).sessionStorage;
  }
});

test("isValidNewPassphrase counts Unicode scalars", () => {
  assert.equal(isValidNewPassphrase("abcdefghijkl"), true);
  assert.equal(isValidNewPassphrase("😀😀😀😀😀😀"), false);
  assert.equal(isValidNewPassphrase("ééééééééééé1"), true);
});

test("storage key matches the spec", () => {
  assert.equal(WEB_TOKEN_STORAGE_KEY, "codexSwitcherWebToken");
});

test("hash is stripped whenever it contains token=, even if empty", () => {
  const urls: Array<string | null | undefined> = [];
  const history = { replaceState: (_d: unknown, _u: string, url?: string | null) => void urls.push(url) };
  const stored: string[] = [];
  const storage = { setItem: (_k: string, v: string) => void stored.push(v) };
  captureWebTokenFromLocation({ hash: "#token=", pathname: "/p", search: "?q=1" }, history, storage);
  assert.deepEqual(urls, ["/p?q=1"]);
  assert.deepEqual(stored, []);
  captureWebTokenFromLocation({ hash: "#foo=1", pathname: "/p", search: "" }, history, storage);
  assert.equal(urls.length, 1);
});

test("token survives a throwing sessionStorage via in-memory fallback", async () => {
  const realFetch = globalThis.fetch;
  const sessionDesc = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  const boom = () => {
    throw new Error("denied");
  };
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: { getItem: boom, setItem: boom },
  });
  const calls: RequestInit[] = [];
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    calls.push(init ?? {});
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  try {
    captureWebTokenFromLocation(
      { hash: "#token=memtok", pathname: "/", search: "" },
      { replaceState: () => {} },
      globalThis.sessionStorage
    );
    await invokeBackend("list_accounts");
    const headers = calls[0].headers as Record<string, string>;
    assert.equal(headers.Authorization, "Bearer memtok");
  } finally {
    globalThis.fetch = realFetch;
    if (sessionDesc) Object.defineProperty(globalThis, "sessionStorage", sessionDesc);
    else delete (globalThis as { sessionStorage?: unknown }).sessionStorage;
  }
});
