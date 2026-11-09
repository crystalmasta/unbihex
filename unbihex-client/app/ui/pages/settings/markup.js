// The settings screen: tabs, the form (one fieldset group per tab), the save bar; "О программе" on top of «Общие».
import { aboutMarkup } from "../../widgets/about/index.js";
import { saveBarMarkup } from "../../widgets/save-bar/index.js";
import { settingsTabsMarkup } from "../../widgets/settings-tabs/index.js";
import { adblockMarkup } from "./tabs/adblock.js";
import { appsMarkup } from "./tabs/apps.js";
import { autoMarkup } from "./tabs/auto.js";
import { dnsMarkup } from "./tabs/dns.js";
import { generalMarkup } from "./tabs/general.js";
import { networkMarkup } from "./tabs/network.js";
import { routingMarkup } from "./tabs/routing.js";
import { subsTabMarkup } from "./tabs/subs.js";
import { tlsMarkup } from "./tabs/tls.js";

export const settingsMarkup = `\n${[
  `        <header class="view-head"><h1>Настройки</h1></header>`,
  settingsTabsMarkup,
  aboutMarkup,
  `        <form id="settings-form" class="settings" autocomplete="off">`,
  generalMarkup,
  networkMarkup,
  dnsMarkup,
  routingMarkup,
  adblockMarkup,
  autoMarkup,
  appsMarkup,
  tlsMarkup,
  subsTabMarkup,
  saveBarMarkup,
  `        </form>`,
].join("\n")}\n      `;
