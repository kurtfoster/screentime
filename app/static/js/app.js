/* Screen Time front end: small, dependency-light (htmx handles polling). No inline handlers (CSP). */
(() => {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const flash = document.getElementById("flash");
  const banner = document.getElementById("offline-banner");
  let clockOffset = 0; // server epoch minus client epoch, in seconds
  let lastZeroRefresh = 0;

  const uuid = () =>
    globalThis.crypto?.randomUUID
      ? crypto.randomUUID()
      : Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

  function showFlash(message, kind) {
    if (!flash) return;
    flash.replaceChildren();
    if (!message) return;
    const div = document.createElement("div");
    div.className = `banner ${kind === "ok" ? "notice-ok" : "banner-error"}`;
    div.textContent = (kind === "ok" ? "✓ " : "⚠ ") + message;
    flash.append(div);
    if (kind === "ok") setTimeout(() => flash.replaceChildren(), 6000);
  }

  function setOffline(offline) {
    document.body.classList.toggle("is-offline", offline);
    if (banner) banner.hidden = !offline;
  }

  async function postJson(url, body) {
    try {
      const res = await fetch(url, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify(body || {}),
      });
      setOffline(false);
      let data = {};
      try { data = await res.json(); } catch (_) { /* non-JSON error page */ }
      if (res.status === 401) { location.assign("/login"); }
      return { status: res.status, data, network: false };
    } catch (_) {
      setOffline(true);
      return { status: 0, data: { message: "Screen Time controller unavailable." }, network: true };
    }
  }

  function refreshLive() {
    const live = document.getElementById("live");
    if (!live || !window.htmx) return;
    const base = (live.getAttribute("hx-get") || "").split("?")[0];
    if (base) htmx.ajax("GET", base, { target: "#live", swap: "outerHTML" });
  }

  const fmt = (seconds) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  };

  function syncClock() {
    const live = document.getElementById("live");
    const server = parseFloat(live?.dataset.serverEpoch || "");
    if (!Number.isNaN(server)) clockOffset = server - Date.now() / 1000;
  }

  function tickCountdowns() {
    const now = Date.now() / 1000 + clockOffset;
    document.querySelectorAll("[data-end-epoch]").forEach((el) => {
      const left = Math.max(0, Math.ceil(parseFloat(el.dataset.endEpoch) - now));
      const target = el.querySelector(".js-countdown");
      if (target) target.textContent = fmt(left);
      const warn = parseFloat(el.dataset.warnEpoch || "");
      if (!Number.isNaN(warn) && now >= warn && !el.dataset.warned) {
        el.dataset.warned = "1"; // state changes at the warning point: fetch fresh options
        refreshLive();
      }
      if (left === 0 && Date.now() - lastZeroRefresh > 2000) {
        lastZeroRefresh = Date.now();
        refreshLive();
      }
    });
  }

  // ---- generic action buttons -------------------------------------------------------------
  document.addEventListener("click", async (event) => {
    const btn = event.target.closest("[data-api-post]");
    if (!btn || btn.disabled) return;
    event.preventDefault();
    const confirmText = btn.dataset.confirm;
    if (confirmText && !window.confirm(confirmText)) return;
    const body = btn.dataset.body ? JSON.parse(btn.dataset.body) : {};
    if (btn.hasAttribute("data-idem")) body.request_id = btn.dataset.rid || (btn.dataset.rid = uuid());
    btn.disabled = true; // guards against double-taps; the request id guards against retries
    const { status, data, network } = await postJson(btn.dataset.apiPost, body);
    btn.disabled = false;
    if (!network) delete btn.dataset.rid;
    if (status >= 200 && status < 300 && data.ok) {
      showFlash(btn.dataset.done || data.message || "Done.", "ok");
    } else {
      showFlash(data.message || "That did not work.", "error");
    }
    refreshLive();
  });

  // ---- start-session form -----------------------------------------------------------------
  function initStartForm() {
    const form = document.getElementById("start-form");
    if (!form || form.dataset.ready) return;
    form.dataset.ready = "1";
    const watchers = form.querySelector("#watchers");

    function syncWatchers() {
      const chosen = form.querySelector('input[name="device_id"]:checked');
      const shared = chosen?.dataset.shared === "1";
      if (watchers) watchers.hidden = !shared;
      form.querySelectorAll(".sibling-pw").forEach((el) => {
        const box = form.querySelector(`input[name="sibling"][value="${el.dataset.child}"]`);
        el.hidden = !(shared && box?.checked);
      });
    }
    form.addEventListener("change", syncWatchers);
    syncWatchers();

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      const device = form.querySelector('input[name="device_id"]:checked');
      const minutes = form.querySelector('input[name="minutes"]:checked');
      if (!device || !minutes) { showFlash("Choose a device and a time first.", "error"); return; }
      const participants = [];
      for (const box of form.querySelectorAll('input[name="sibling"]:checked')) {
        const pw = form.querySelector(`input[name="pw_${box.value}"]`)?.value || "";
        if (!pw) { showFlash("Type the password for the person joining you.", "error"); return; }
        participants.push({ child_id: box.value, password: pw });
      }
      submit.disabled = true;
      form.dataset.rid = form.dataset.rid || uuid();
      const payload = {
        device_id: device.value,
        minutes: parseInt(minutes.value, 10),
        participants: device.dataset.shared === "1" ? participants : [],
        request_id: form.dataset.rid,
      };
      const { status, data, network } = await postJson("/api/child/session/start", payload);
      submit.disabled = false;
      if (!network) delete form.dataset.rid; // keep the id only when a retry may repeat this request
      form.querySelectorAll('input[type="password"]').forEach((i) => { i.value = ""; });
      if (status >= 200 && status < 300 && data.ok) {
        showFlash("Screen time started. Have fun!", "ok");
        refreshLive();
      } else {
        // Keep the form exactly as the child left it so they can correct one thing and retry.
        // If state really changed, the 5-second poll notices (the server compares state keys).
        showFlash(data.message || "Could not start.", "error");
      }
    });
  }

  // ---- offline handling -------------------------------------------------------------------
  document.body.addEventListener("htmx:sendError", () => setOffline(true));
  document.body.addEventListener("htmx:responseError", (e) => {
    if (e.detail?.xhr?.status === 401) location.assign("/login");
  });
  document.body.addEventListener("htmx:afterRequest", (e) => {
    if (e.detail?.successful) setOffline(false);
  });
  window.addEventListener("offline", () => setOffline(true));
  window.addEventListener("online", () => { setOffline(false); refreshLive(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshLive(); });
  // Pause dashboard polling while the page is hidden (an iPad left on the dashboard costs the
  // controller CPU for nothing). Done here, not with an hx-trigger filter: filters need eval,
  // which the CSP and htmx config forbid. Becoming visible again refreshes at once (above).
  document.body.addEventListener("htmx:beforeRequest", (e) => {
    if (document.hidden && e.detail?.elt?.id === "live") e.preventDefault();
  });

  document.body.addEventListener("htmx:afterSwap", () => { syncClock(); initStartForm(); });

  // ---- web push ---------------------------------------------------------------------------
  const b64ToBytes = (s) => {
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const raw = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  };

  async function enablePush(button) {
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
      showFlash("Alerts need the Home Screen app on this device.", "error");
      return;
    }
    const perm = await Notification.requestPermission();
    if (perm !== "granted") { showFlash("Alerts were not allowed.", "error"); return; }
    const reg = await navigator.serviceWorker.ready;
    const keyRes = await fetch("/api/push/public-key", { credentials: "same-origin" });
    const key = await keyRes.json();
    if (!key.enabled || !key.public_key) { showFlash("Alerts are not enabled on the controller.", "error"); return; }
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: b64ToBytes(key.public_key),
    });
    const json = sub.toJSON();
    const { data } = await postJson("/api/push/subscribe", { endpoint: json.endpoint, keys: json.keys });
    showFlash(data.message || "Alerts are on.", data.ok ? "ok" : "error");
    if (data.ok) button.hidden = true;
  }

  const pushButton = document.getElementById("enable-push");
  if (pushButton) pushButton.addEventListener("click", () => enablePush(pushButton).catch(() => showFlash("Could not turn on alerts.", "error")));

  // ---- boot -------------------------------------------------------------------------------
  document.body.addEventListener("htmx:configRequest", (e) => { e.detail.headers["X-CSRF-Token"] = csrf; });
  syncClock();
  initStartForm();
  setInterval(tickCountdowns, 1000);
  tickCountdowns();

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/service-worker.js").catch(() => { /* HTTP or unsupported: app still works */ });
  }
})();
