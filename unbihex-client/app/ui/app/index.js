// Entry point (index.html: <script type="module">). Builds the screens and dialogs,
// connects the slices and loads the state. See ../ARCHITECTURE.md.
import { adblockPresets } from "../shared/api/index.js";
import { on, startDataClicks } from "../shared/lib/index.js";
import { onRender, refresh } from "../shared/model/index.js";
import { toast } from "../shared/ui/index.js";
import { mountAddInput } from "../features/add-input/index.js";
import { mountFingerprint } from "../features/fingerprint/index.js";
import { initOpenLinks } from "../features/open-link/index.js";
import { mountSubscriptionEdit } from "../features/subscription-edit/index.js";
import { mountTemplateEdit } from "../features/template-edit/index.js";
import { mountAppsList } from "../widgets/apps-list/index.js";
import { renderAbout } from "../widgets/about/index.js";
import { mountServerMenu } from "../widgets/server-menu/index.js";
import { initHome, renderHome } from "../pages/home/index.js";
import { initLogs, mountLogs } from "../pages/logs/index.js";
import { initServers, mountServers, renderServers } from "../pages/servers/index.js";
import * as settings from "../pages/settings/index.js";
import { initSubs, mountSubs, renderSubs } from "../pages/subs/index.js";
import { listenBackend } from "./backend-events.js";
import { startPolling } from "./poll.js";
import { initRouter, switchView } from "./router.js";

// Markup: the screens, then the dialogs in their page order.
mountServers();
mountSubs();
settings.mountSettings();
mountLogs();
mountAddInput();
mountSubscriptionEdit();
mountServerMenu();
mountFingerprint();
mountTemplateEdit();
mountAppsList({ readSettings: settings.readSettings });

initRouter();
initHome();
initServers();
initSubs();
settings.initSettings();
initLogs();
initOpenLinks();
startDataClicks();

// A full render runs these in this order; render("<topic>") runs one.
onRender("home", renderHome);
onRender("servers", renderServers);
onRender("subs", renderSubs);
onRender("about", renderAbout);
onRender("settings-template", settings.syncSavedTemplate);
onRender("adblock", settings.renderAdblock);

// Signals from lower layers.
on("navigate", switchView);
on("settings:fill", settings.fillSettings);
on("settings:error", settings.showSettingsError);
on("templates:changed", () => settings.renderTemplates());
on("geo:changed", settings.renderGeo);

listenBackend();
adblockPresets().then(settings.setAdblockPresets).catch(() => {});
refresh().catch((e) => toast(String(e), "error"));
startPolling();
