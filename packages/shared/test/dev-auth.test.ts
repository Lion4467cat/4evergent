import { test } from "node:test";
import assert from "node:assert/strict";
import { DevAuthProvider } from "../src/dev-auth.js";

test("DevAuthProvider: missing authorization header returns default owner", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "default-owner",
    apiKeys: { "secret-key-1234": "mapped-owner" },
  });

  const result = await provider.authenticate({ headers: {} });

  assert.deepEqual(result, {
    subject: "dev-user",
    ownerId: "default-owner",
  });
});

test("DevAuthProvider: known Bearer API key returns mapped owner and apikey:<prefix> subject", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "default-owner",
    apiKeys: {
      "dev-key-1234567890": "owner-alpha",
      short: "owner-short",
    },
  });

  const longResult = await provider.authenticate({
    headers: { authorization: "Bearer dev-key-1234567890" },
  });
  assert.deepEqual(longResult, {
    subject: "apikey:dev-key-",
    ownerId: "owner-alpha",
  });

  const shortResult = await provider.authenticate({
    headers: { authorization: "Bearer short" },
  });
  assert.deepEqual(shortResult, {
    subject: "apikey:short",
    ownerId: "owner-short",
  });
});

test("DevAuthProvider: unknown Bearer key falls back to default owner", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "default-owner",
    apiKeys: { "known-key-12345": "owner-alpha" },
  });

  const result = await provider.authenticate({
    headers: { authorization: "Bearer unknown-key-999" },
  });

  assert.deepEqual(result, {
    subject: "dev-user",
    ownerId: "default-owner",
  });
});

test("DevAuthProvider: handles array-valued authorization header using first element", async () => {
  const provider = new DevAuthProvider({
    defaultOwnerId: "default-owner",
    apiKeys: {
      "first-key-123456": "owner-first",
      "second-key-12345": "owner-second",
    },
  });

  const knownFirst = await provider.authenticate({
    headers: {
      authorization: ["Bearer first-key-123456", "Bearer second-key-12345"],
    },
  });
  assert.deepEqual(knownFirst, {
    subject: "apikey:first-ke",
    ownerId: "owner-first",
  });

  const unknownFirst = await provider.authenticate({
    headers: {
      authorization: ["Bearer invalid-key", "Bearer first-key-123456"],
    },
  });
  assert.deepEqual(unknownFirst, {
    subject: "dev-user",
    ownerId: "default-owner",
  });
});

test("DevAuthProvider: empty or omitted apiKeys config returns default owner", async () => {
  const withEmpty = new DevAuthProvider({
    defaultOwnerId: "fallback-owner",
    apiKeys: {},
  });
  const withoutKeys = new DevAuthProvider({
    defaultOwnerId: "fallback-owner",
  });

  const r1 = await withEmpty.authenticate({
    headers: { authorization: "Bearer any-key-value" },
  });
  const r2 = await withoutKeys.authenticate({
    headers: { authorization: "Bearer any-key-value" },
  });

  assert.deepEqual(r1, { subject: "dev-user", ownerId: "fallback-owner" });
  assert.deepEqual(r2, { subject: "dev-user", ownerId: "fallback-owner" });
});
