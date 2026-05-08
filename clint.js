#!/usr/bin/env node
import dotenv from "dotenv";
import { chromium } from "playwright";
import axios from "axios";
import chalk from "chalk";
import { ConvexClient as ConvexWsClient } from "convex/browser";
import { anyApi } from "convex/server";
import crypto from "crypto";
import { existsSync } from "fs";
import { mkdir, appendFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const envPath = join(__dirname, ".env");
if (existsSync(envPath)) dotenv.config({ path: envPath, quiet: true });
else dotenv.config({ quiet: true });

const BASE_CONFIG = {
  client: {
    id: process.env.CLIENT_ID || "mining-client-1",
    name: process.env.CLIENT_NAME || "Mining-Client",
  },
  convex: { url: process.env.CONVEX_URL || "" },
  logging: { dir: join(__dirname, "logs") },
  mining: {
    faucetUrl: "https://sepolia-faucet.pk910.de/",
    sessionDuration: 12 * 60 * 60 * 1000,
    maxEthForProgress: 2.5,
  },
  api: {
    statusEndpoint: "https://sepolia-faucet.pk910.de/api/getSessionStatus",
    timeout: 20_000,
  },
  captcha: {
    baseUrl: "https://api.multibot.in",
    apiKey: "XoH9tdX1y10dKa9UrjvepsvfNkZwaxA9",
    sitekeys: {
      recaptcha: "6Leg_psiAAAAAHlE_PSnJuYLQDXbrnBw6G2l_vvu",
      hcaptcha: "89693841-2505-4039-8c39-479c9188991f",
    },
    pollInterval: 5_000,
  },
  timeouts: {
    pageLoad: 60_000,
    buttonWait: 30_000,
    pingInterval: 30_000,
    heartbeatInterval: 60_000,
  },
  restart: {
    maxConsecutiveErrors: 10,
    baseDelay: 30_000,
    maxDelay: 300_000,
    backoffFactor: 1.5,
  },
  miner: {
    disableGif: process.env.POW_MINER_DISABLE_GIF === "true",
    workerCount: parseInt(process.env.POW_MINER_WORKER_COUNT || "10", 10),
  },
};

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function weiToEth(wei) {
  if (!wei) return 0;
  try { return Number(typeof wei === "string" ? BigInt(wei) : BigInt(Math.floor(wei))) / 1e18; }
  catch { return Number(wei) / 1e18; }
}

class ConvexClient {
  constructor(url) {
    if (!url) throw new Error("CONVEX_URL not set in .env");
    this.url = url.replace(/\/$/, "");
    this._ws = new ConvexWsClient(url);
  }
  async mutation(path, args = {}) {
    const res = await axios.post(`${this.url}/api/mutation`, { path, args, format: "json" }, { timeout: 15_000 });
    if (res.data.status === "error") throw new Error(res.data.errorMessage);
    return res.data.value;
  }
  async query(path, args = {}) {
    const res = await axios.post(`${this.url}/api/query`, { path, args, format: "json" }, { timeout: 15_000 });
    if (res.data.status === "error") throw new Error(res.data.errorMessage);
    return res.data.value;
  }
  async close() { try { await this._ws.close(); } catch {} }
}

class Logger {
  static _activeLine = false;
  static _spinnerTimer = null;
  static _spinFrame = 0;
  static _spinFrames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];

  static _ts() { return chalk.dim(new Date().toISOString().replace("T"," ").slice(0,19)); }
  static _tag(type) {
    const tags = {
      INFO:     chalk.bgBlue.white.bold(      " INFO     "),
      SUCCESS:  chalk.bgGreen.black.bold(     " SUCCESS  "),
      ERROR:    chalk.bgRed.white.bold(       " ERROR    "),
      WARN:     chalk.bgYellow.black.bold(    " WARN     "),
      SESSION:  chalk.bgCyan.black.bold(      " SESSION  "),
      MINING:   chalk.bgMagenta.white.bold(   " MINING   "),
      CAPTCHA:  chalk.bgYellow.black.bold(    " CAPTCHA  "),
      WORKFLOW: chalk.bgBlueBright.black.bold(" WORKFLOW "),
    };
    return tags[type] || chalk.bgWhite.black.bold(` ${type.padEnd(8)} `);
  }
  static _clearLine() {
    if (Logger._activeLine) { process.stdout.write("\r\x1b[K"); Logger._activeLine = false; }
  }
  static log(msg, type = "INFO") {
    Logger._clearLine();
    console.log(`${Logger._ts()}  ${Logger._tag(type)}  ${msg}`);
    Logger._writeFile(type, msg).catch(() => {});
  }
  static step(stage, msg) {
    Logger._clearLine();
    console.log(`${Logger._ts()}  ${chalk.bgBlueBright.black.bold(` STEP ${stage} `)}  ${chalk.bold(msg)}`);
    Logger._writeFile("WORKFLOW", `[${stage}] ${msg}`).catch(() => {});
  }
  static divider() { Logger._clearLine(); console.log(chalk.dim("─".repeat(90))); }
  static startSpinner(msgFn) {
    Logger._clearLine();
    Logger._spinFrame = 0;
    const render = () => {
      const frame = Logger._spinFrames[Logger._spinFrame++ % Logger._spinFrames.length];
      process.stdout.write(`\r\x1b[K  ${chalk.cyan(frame)}  ${msgFn()}`);
      Logger._activeLine = true;
    };
    render();
    Logger._spinnerTimer = setInterval(render, 100);
  }
  static stopSpinner() {
    if (Logger._spinnerTimer) { clearInterval(Logger._spinnerTimer); Logger._spinnerTimer = null; }
    Logger._clearLine();
  }
  static status(text) { process.stdout.write(`\r\x1b[K${text}`); Logger._activeLine = true; }
  static bar(cur, tot) {
    const pct = Math.min(100, Math.floor((cur / tot) * 100));
    const f = Math.floor(pct / 5);
    return `[${chalk.green("█".repeat(f))}${chalk.dim("░".repeat(20 - f))}] ${chalk.bold(pct + "%")}`;
  }
  static dur(ms) {
    const h = Math.floor(ms / 3_600_000), m = Math.floor((ms % 3_600_000) / 60_000), s = Math.floor((ms % 60_000) / 1000);
    if (h) return `${h}h ${m}m`; if (m) return `${m}m ${s}s`; return `${s}s`;
  }
  static header(workerCount) {
    console.clear();
    const W = 90, title = "POW MINING CLIENT  v5.0", sub = `${BASE_CONFIG.client.id}  .  ${workerCount} workers`;
    console.log(); console.log(chalk.cyan("▄".repeat(W)));
    console.log(chalk.bgCyan.black.bold(" ".repeat(W)));
    console.log(chalk.bgCyan.black.bold(title.padStart(Math.floor((W + title.length) / 2)).padEnd(W)));
    console.log(chalk.bgCyan.black(sub.padStart(Math.floor((W + sub.length) / 2)).padEnd(W)));
    console.log(chalk.bgCyan.black.bold(" ".repeat(W))); console.log(chalk.cyan("▀".repeat(W))); console.log();
  }
  static async _writeFile(type, msg) {
    try {
      await mkdir(BASE_CONFIG.logging.dir, { recursive: true });
      const date = new Date().toISOString().split("T")[0];
      const ts = new Date().toISOString().replace("T"," ").slice(0,19);
      await appendFile(join(BASE_CONFIG.logging.dir, `${date}-activity.log`), `[${ts}] [${type.padEnd(8)}] ${msg}\n`);
    } catch {}
  }
}

class CaptchaSolver {
  constructor(secrets) {
    this.apiKey = BASE_CONFIG.captcha.apiKey || secrets.captcha_api_key;
    this.baseUrl = "https://api.multibot.in";
    this.timeoutPerAttempt = parseInt(secrets.captcha_timeout || "180") * 1000;
    this.maxRetries = parseInt(secrets.captcha_max_retries || "3");
    this.pollInterval = 5_000;
  }

  async solve(captchaType) {
    if (!this.apiKey) throw new Error("captcha_api_key not set in Convex config");
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      Logger.log(`Captcha attempt ${attempt}/${this.maxRetries}  .  ${captchaType.toUpperCase()}`, "CAPTCHA");
      const token = await this._solveOnce(captchaType, attempt);
      if (token) return token;
      if (attempt < this.maxRetries) { Logger.log(`Attempt ${attempt} failed — retrying in 5s`, "WARN"); await sleep(5000); }
    }
    return null;
  }

  async _solveOnce(captchaType, attempt) {
    try {
      const method = captchaType === "recaptcha" ? "userrecaptcha" : "hcaptcha";
      const sitekey = BASE_CONFIG.captcha.sitekeys[captchaType];
      const form = new FormData();
      form.append("key", this.apiKey);
      form.append("method", method);
      if (captchaType === "recaptcha") form.append("googlekey", sitekey);
      else form.append("sitekey", sitekey);
      form.append("pageurl", BASE_CONFIG.mining.faucetUrl);
      form.append("json", "1");

      const submitRes = await axios.post(`${this.baseUrl}/in.php`, form, { timeout: 15_000 });
      if (submitRes.data?.status !== 1) throw new Error(`Solver rejected: ${submitRes.data?.request}`);

      const taskId = submitRes.data.request;
      Logger.log(`Task ID: ${chalk.dim(taskId)}`, "CAPTCHA");
      let elapsed = 0;

      Logger.startSpinner(() =>
        chalk.yellow(`Solving ${captchaType.toUpperCase()}`) +
        chalk.dim(`  .  attempt ${attempt}/${this.maxRetries}  .  ${elapsed}s`)
      );
      const tick = setInterval(() => elapsed++, 1000);
      try {
        while (true) {
          await sleep(this.pollInterval);
          const poll = await axios.get(`${this.baseUrl}/res.php`,
            { params: { key: this.apiKey, action: "get", id: taskId, json: 1 }, timeout: 10_000 });
          if (poll.data?.status === 1) {
            clearInterval(tick); Logger.stopSpinner();
            Logger.log(`Solved in ${elapsed}s`, "SUCCESS");
            return poll.data.request;
          }
          if (poll.data?.request !== "CAPCHA_NOT_READY") throw new Error(`Solver error: ${poll.data?.request}`);
        }
      } finally { clearInterval(tick); Logger.stopSpinner(); }
    } catch (e) { Logger.log(`Attempt ${attempt} failed: ${e.message}`, "ERROR"); return null; }
  }
}

class MiningClient {
  constructor() {
    this.convex = new ConvexClient(BASE_CONFIG.convex.url);
    this.secrets = null;
    this.captchaSolver = null;
    this.proxy = null;
    this.browser = null;
    this.page = null;
    this.sessionId = null;
    this.walletAddress = null;
    this.sessionStartTime = null;
    this.isResuming = false;
    this._pingTimer = null;
  }

  async loadSecrets() {
    const all = await this.convex.query("config:getAll", {});
    this.secrets = all;
    this.captchaSolver = new CaptchaSolver(all);
    if (all.proxy_host) {
      this.proxy = {
        protocol: all.proxy_protocol || "http",
        host: all.proxy_host,
        port: parseInt(all.proxy_port || "24125", 10),
        username: all.proxy_user || "",
        password: all.proxy_pass || "",
      };
    }
  }

  async start() {
    Logger.header(BASE_CONFIG.miner.workerCount);

    Logger.step("1/5", "Connecting to Convex + loading secrets");
    await this.registerClient();
    await this.loadSecrets();
    Logger.log("Connected and secrets loaded", "SUCCESS");
    Logger.divider();

    Logger.step("2/5", "Checking for existing session");
    const sessionData = await this.checkForExistingSession();

    if (sessionData.existingSession) {
      Logger.log(`Resuming session: ${chalk.cyan(sessionData.sessionId)}`, "SESSION");
      this.sessionId = sessionData.sessionId;
      this.walletAddress = sessionData.walletAddress;
      this.sessionStartTime = sessionData.startTime;
      this.isResuming = true;
      Logger.divider();
      await this.resumeSession(sessionData);
    } else {
      Logger.log("Starting new session", "SESSION");
      Logger.divider();
      await this.startNewSession();
    }
    await this.monitorMining();
  }

  async cleanup() {
    Logger.stopSpinner();
    if (this._pingTimer) { clearInterval(this._pingTimer); this._pingTimer = null; }
    if (this.browser) {
      try { await this.browser.close(); } catch {}
      this.browser = null; this.page = null;
    }
    if (this.walletAddress) {
      try {
        const sess = await this.convex.query("sessions:getForClient", { clientId: BASE_CONFIG.client.id });
        if (!sess) await this.convex.mutation("wallets:release", { address: this.walletAddress }).catch(() => {});
      } catch {}
    }
    try { await this.convex.mutation("clients:disconnect", { clientId: BASE_CONFIG.client.id }); } catch {}
    this.convex.close();
    this.sessionId = this.walletAddress = this.sessionStartTime = null;
  }

  async registerClient() {
    await this.convex.mutation("clients:upsert", {
      clientId: BASE_CONFIG.client.id,
      name: BASE_CONFIG.client.name,
      status: "active",
    });
    this._pingTimer = setInterval(async () => {
      try { await this.convex.mutation("clients:ping", { clientId: BASE_CONFIG.client.id, sessionId: this.sessionId || undefined }); } catch {}
    }, BASE_CONFIG.timeouts.pingInterval);
  }

  async checkForExistingSession() {
    const existing = await this.convex.query("sessions:getForClient", { clientId: BASE_CONFIG.client.id });
    if (!existing) { Logger.log("No existing session — starting fresh", "SUCCESS"); return { existingSession: false }; }
    if (["claimed","failed","expired"].includes(existing.status)) {
      Logger.log("Previous session completed — starting fresh", "SUCCESS");
      return { existingSession: false };
    }
    Logger.log(`Found active session: ${chalk.cyan(existing.sessionId)}`, "SUCCESS");
    return { existingSession: true, sessionId: existing.sessionId, walletAddress: existing.walletAddress, startTime: existing.startTime };
  }

  async resumeSession(sessionData) {
    Logger.step("3/5", "Launching browser (headless resume)");
    this.browser = await chromium.launch({ headless: true, timeout: 30_000, args: ["--no-sandbox"] });
    const ctx = await this.browser.newContext({ viewport: null });
    this.page = await ctx.newPage();
    const url = `${BASE_CONFIG.mining.faucetUrl}#/mine/${sessionData.sessionId}`;
    try {
      await this.page.goto(BASE_CONFIG.mining.faucetUrl, { waitUntil: "domcontentloaded", timeout: BASE_CONFIG.timeouts.pageLoad });
      await this._injectMinerSettings(this.page);
      await sleep(500);
      await this.page.goto(url, { waitUntil: "domcontentloaded", timeout: BASE_CONFIG.timeouts.pageLoad });
    } catch (e) { Logger.log(`Navigation warning: ${e.message}`, "WARN"); }
    Logger.log("Session resumed", "SUCCESS");
    Logger.divider();
  }

  async startNewSession() {
    Logger.step("3/5", "Claiming mining wallet");
    const wallet = await this.convex.mutation("wallets:claimAvailable", {});
    if (!wallet) throw new Error("No wallets available");
    this.walletAddress = wallet;
    Logger.log(`Wallet: ${chalk.cyan(wallet)}`, "SUCCESS");
    Logger.divider();

    Logger.step("4/5", "Browser + captcha");
    this.browser = await chromium.launch({ headless: false, timeout: 30_000, args: ["--no-sandbox", "--start-maximized"] });
    const ctx = await this.browser.newContext({ viewport: null });
    this.page = await ctx.newPage();

    await this.page.goto(BASE_CONFIG.mining.faucetUrl, { waitUntil: "domcontentloaded", timeout: BASE_CONFIG.timeouts.pageLoad });
    Logger.log("Faucet loaded", "SUCCESS");
    await sleep(5000);

    const captchaType = await this._detectCaptchaType();
    if (!captchaType) throw new Error("No captcha found on page");
    Logger.log(`Captcha: ${chalk.yellow(captchaType.toUpperCase())}`, "CAPTCHA");

    const token = await this.captchaSolver.solve(captchaType);
    if (!token) throw new Error("Captcha solve failed");

    await this._injectToken(captchaType, token);
    Logger.log("Token injected", "SUCCESS");

    let intercepted = null;
    await this.page.route("**/api/startSession*", async (route, req) => {
      intercepted = { url: req.url(), method: req.method(), headers: req.headers(), postData: req.postData() };
      await route.abort("blockedbyclient");
    });

    const btn = this.page.getByRole("button", { name: /Start Mining/i });
    await btn.waitFor({ state: "visible", timeout: BASE_CONFIG.timeouts.buttonWait });
    await btn.click();
    Logger.log("Start Mining clicked", "MINING");
    await sleep(3000);
    if (!intercepted) throw new Error("Failed to intercept startSession");

    Logger.step("5/5", "Starting faucet session");
    const miningUrl = await this._startFaucetSession(intercepted, wallet);
    if (!miningUrl) throw new Error("Faucet rejected session");

    Logger.log(`Session URL: ${chalk.cyan(miningUrl)}`, "SUCCESS");
    Logger.divider();

    await this.browser.close();
    this.browser = await chromium.launch({ headless: true, timeout: 30_000, args: ["--no-sandbox"] });
    const hCtx = await this.browser.newContext({ viewport: null });
    this.page = await hCtx.newPage();
    try {
      await this.page.goto(BASE_CONFIG.mining.faucetUrl, { waitUntil: "domcontentloaded", timeout: BASE_CONFIG.timeouts.pageLoad });
      await this._injectMinerSettings(this.page);
      await sleep(500);
      await this.page.goto(miningUrl, { waitUntil: "domcontentloaded", timeout: BASE_CONFIG.timeouts.pageLoad });
    } catch (e) { Logger.log(`Navigation warning: ${e.message}`, "WARN"); }
    Logger.log("Mining active (headless)", "MINING");
  }

  async _startFaucetSession(requestData, walletAddress) {
    try {
      const postData = JSON.parse(requestData.postData);
      postData.addr = walletAddress;
      const safeH = { ...requestData.headers };
      delete safeH["content-length"]; delete safeH["host"];

      const reqCfg = {
        method: requestData.method,
        url: requestData.url,
        headers: { ...safeH, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        data: postData,
        timeout: 30_000,
      };

      if (this.proxy) {
        const { protocol, username, password, host, port } = this.proxy;
        const proxyUrl = `${protocol}://${encodeURIComponent(username)}:${encodeURIComponent(password)}@${host}:${port}`;
        const { HttpsProxyAgent } = await import("https-proxy-agent");
        const { HttpProxyAgent } = await import("http-proxy-agent");
        reqCfg.httpsAgent = new HttpsProxyAgent(proxyUrl);
        reqCfg.httpAgent = new HttpProxyAgent(proxyUrl);
        reqCfg.proxy = false;
      }

      const res = await axios(reqCfg);
      if (res.data?.session) {
        const sessionId = res.data.session;
        const miningUrl = `https://sepolia-faucet.pk910.de/#/mine/${sessionId}`;
        this.sessionId = sessionId;
        this.sessionStartTime = Date.now();
        Logger.log(`Wallet: ${chalk.cyan(walletAddress)}`, "SUCCESS");
        Logger.log(`Session: ${chalk.cyan(sessionId)}`, "SUCCESS");
        await this.convex.mutation("sessions:add", { sessionId, walletAddress, clientId: BASE_CONFIG.client.id, miningUrl, startTime: Date.now() });
        await this.convex.mutation("clients:setSession", { clientId: BASE_CONFIG.client.id, sessionId });
        await this.convex.mutation("events:write", { level: "success", event: "Session Started", detail: `${sessionId} . ${walletAddress}`, sessionId, clientId: BASE_CONFIG.client.id }).catch(() => {});
        return miningUrl;
      }
      if (res.data?.status === "failed") {
        Logger.log(`Faucet rejected: ${res.data.failedReason || "unknown"}`, "ERROR");
        await this.convex.mutation("wallets:release", { address: walletAddress }).catch(() => {});
        this.walletAddress = null;
      }
      return null;
    } catch (e) {
      Logger.log(`Session start error: ${e.message}`, "ERROR");
      await this.convex.mutation("wallets:release", { address: walletAddress }).catch(() => {});
      this.walletAddress = null;
      return null;
    }
  }

  async _detectCaptchaType() {
    try {
      const hcVisible = await this.page.frameLocator('iframe[src*="hcaptcha.com"]').first().locator("body").isVisible().catch(() => false);
      if (hcVisible) return "hcaptcha";
      const rcExists = await this.page.evaluate(() =>
        Array.from(document.querySelectorAll("iframe")).some(f => f.src.includes("google.com/recaptcha"))
      );
      return rcExists ? "recaptcha" : null;
    } catch { return null; }
  }

  async _injectToken(type, token) {
    const ok = await this.page.evaluate(({ type, token }) => {
      if (type === "recaptcha") {
        const ta = document.querySelector('textarea[name="g-recaptcha-response"]');
        if (ta) {
          ta.value = token;
          ta.dispatchEvent(new Event("input", { bubbles: true }));
          try { Object.values(___grecaptcha_cfg?.clients || {}).forEach(c => c.callback?.(token)); } catch {}
          return true;
        }
      } else {
        const tx = document.querySelector('textarea[name="h-captcha-response"]');
        if (tx) {
          tx.value = token;
          tx.dispatchEvent(new Event("input", { bubbles: true }));
          try { window.hcaptcha && (window.hcaptcha.getResponse = () => token); } catch {}
          return true;
        }
      }
      return false;
    }, { type, token });
    if (!ok) throw new Error("Token injection failed");
  }

  async _injectMinerSettings(page) {
    try {
      await page.evaluate((s) => {
        localStorage.setItem("powMinerDisableGif", s.disableGif.toString());
        localStorage.setItem("powMinerSettings", JSON.stringify({ workerCount: s.workerCount }));
      }, { disableGif: BASE_CONFIG.miner.disableGif, workerCount: BASE_CONFIG.miner.workerCount });
    } catch {}
  }

  async monitorMining() {
    Logger.log(`Mining active  .  ${BASE_CONFIG.miner.workerCount} workers  .  server handles claiming`, "MINING");
    if (this.isResuming && this.sessionStartTime) {
      const remaining = BASE_CONFIG.mining.sessionDuration - (Date.now() - this.sessionStartTime);
      if (remaining > 0) Logger.log(`Time remaining: ~${Logger.dur(remaining)}`, "INFO");
    }
    Logger.log("Ctrl+C to stop client  (server keeps monitoring)", "INFO");
    Logger.divider();
    console.log();

    return new Promise((resolve) => {
      let done = false;
      const finish = (reason) => {
        if (done) return;
        done = true;
        clearInterval(statInterval);
        clearInterval(heartbeat);
        clearInterval(pollSession);
        clearInterval(browserAlive);
        clearTimeout(safetyTimer);
        Logger.stopSpinner();
        Logger.log(`Monitor ended: ${reason}`, "SESSION");
        resolve();
      };

      const statInterval = setInterval(async () => {
        const sid = this.sessionId;
        if (!sid || done) return;
        try {
          const d = await axios.get(`${BASE_CONFIG.api.statusEndpoint}?session=${sid}&details=1&_=${Date.now()}`, { timeout: BASE_CONFIG.api.timeout }).then(r => r.data).catch(() => null);
          if (!d || done) return;
          const bal = weiToEth(d.balance).toFixed(6);
          const st = (d.status || "unknown").toUpperCase();
          const rt = Logger.dur(Date.now() - (this.sessionStartTime || Date.now()));
          const stColor = { RUNNING: chalk.bgWhite.black, CLAIMABLE: chalk.bgGreen.black, FINISHED: chalk.bgGreen.black, FAILED: chalk.bgRed.white }[st] || chalk.white;
          const prog = d.status === "running" ? `  ${Logger.bar(parseFloat(bal), BASE_CONFIG.mining.maxEthForProgress)}` : "";
          Logger.status(chalk.dim(`  ${new Date().toLocaleTimeString()}`) + `  ${chalk.bold.white(bal + " ETH")}  ${stColor(` . ${st} `)}  ${chalk.dim("uptime")} ${chalk.white(rt)}` + prog);
        } catch {}
      }, 30_000);

      const heartbeat = setInterval(async () => {
        if (this.sessionId) try { await this.convex.mutation("sessions:heartbeat", { sessionId: this.sessionId }); } catch {}
      }, BASE_CONFIG.timeouts.heartbeatInterval);
      if (this.sessionId) this.convex.mutation("sessions:heartbeat", { sessionId: this.sessionId }).catch(() => {});

      const pollSession = setInterval(async () => {
        if (!this.sessionId || done) return;
        try {
          const s = await this.convex.query("sessions:getBySessionId", { sessionId: this.sessionId });
          if (s === null || ["claimed","failed","expired"].includes(s.status)) {
            Logger._clearLine(); Logger.log("Session completed", "SUCCESS"); finish("completed");
          }
        } catch {}
      }, 60_000);

      const browserAlive = setInterval(async () => {
        try {
          const ok = await this.page?.isVisible("body").catch(() => false);
          if (!ok) { Logger._clearLine(); Logger.log("Browser closed", "INFO"); finish("browser closed"); }
        } catch { finish("browser lost"); }
      }, 60_000);

      const safetyTimer = setTimeout(() => { Logger._clearLine(); finish("safety timeout"); }, BASE_CONFIG.mining.sessionDuration * 2 + 3_600_000);
    });
  }
}

async function main() {
  let errors = 0;
  while (true) {
    const client = new MiningClient();
    try {
      await client.start();
      errors = 0;
      await client.cleanup();
      Logger.divider();
      Logger.log("Cycle complete — restarting in 10s", "SESSION");
      await sleep(10_000);
    } catch (e) {
      errors++;
      Logger.stopSpinner();
      Logger.log(e.message, "ERROR");
      Logger.log(`Attempt ${errors} of ${BASE_CONFIG.restart.maxConsecutiveErrors}`, "WARN");
      await client.cleanup();
      if (errors >= BASE_CONFIG.restart.maxConsecutiveErrors) {
        Logger.divider();
        Logger.log("Too many errors — stopping", "ERROR");
        process.exit(1);
      }
      const delay = Math.min(BASE_CONFIG.restart.baseDelay * Math.pow(BASE_CONFIG.restart.backoffFactor, errors - 1), BASE_CONFIG.restart.maxDelay);
      Logger.log(`Retrying in ${Math.round(delay / 1000)}s`, "WARN");
      await sleep(delay);
    }
  }
}

process.on("SIGINT", () => { Logger._clearLine(); Logger.divider(); Logger.log("Client stopped", "INFO"); process.exit(0); });
process.on("SIGTERM", () => process.exit(0));
main();