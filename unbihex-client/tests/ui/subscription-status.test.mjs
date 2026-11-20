import assert from "node:assert/strict";
import test from "node:test";
import { quotaHtml } from "../../app/ui/entities/subscription/ui.js";

const now = new Date(2026, 5, 4, 12).getTime();
const seconds = (day, hour) => new Date(2026, 5, day, hour).getTime() / 1000;
const renderExpiry = (expire) => quotaHtml({ info: { upload: 8, download: 16, total: 32, expire } }, now);

test("shows the expiry date and distinguishes future, today and expired", () => {
  assert.match(renderExpiry(seconds(5, 12)), /Активна/);
  assert.match(renderExpiry(seconds(5, 12)), /Действует до <time datetime="[^"]+">5 июня 2026/);
  assert.match(renderExpiry(seconds(4, 22)), /Истекает сегодня/);
  assert.match(renderExpiry(seconds(4, 11)), /Срок истёк/);
  assert.match(renderExpiry(now / 1000), /Срок истёк/);
});

test("distinguishes a missing date from an unlimited subscription", () => {
  assert.match(quotaHtml({}, now), /Дата окончания не указана/);
  assert.match(renderExpiry(null), /Дата окончания не указана/);
  assert.match(renderExpiry(Number.MAX_SAFE_INTEGER), /Дата окончания не указана/);
  assert.match(renderExpiry(0), /Бессрочная подписка/);
});
