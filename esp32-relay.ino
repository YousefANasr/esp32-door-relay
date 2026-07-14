
/*
  Wiring reminder:
    ESP32 GPIO RELAY_PIN -> relay module IN
    Relay module VCC -> 5V, GND -> GND
    Relay module COM + NO -> the two wires from the intercom's
      door-release button contacts (wired in parallel)
*/

#include <WiFi.h>
#include <WebServer.h>
#include <mbedtls/md.h>
#include <esp_random.h>
#include <string.h>
#include <Preferences.h>

// ---------- Log entry & Custom Types: defined immediately after includes so
// Arduino's auto-generated function prototypes can see them. ----------
const int HISTORY_SIZE = 20;
struct LogEvent { char time[24]; char name[24]; char ip[16]; };

struct IpLockout {
  IPAddress ip;
  int failedAttempts;
  unsigned long firstFailureAt;
  unsigned long lockoutUntil;
  bool used;
};

// ---------- CONFIG: EDIT THESE ----------
const char* WIFI_SSID     = "NAME";
const char* WIFI_PASSWORD = "PASSWORD";
const char* UNLOCK_TOKEN  = "TOKEN_PASSWORD";

const int RELAY_PIN         = 26;
const bool RELAY_ACTIVE_LOW = false;
const int PULSE_MS          = 700;

IPAddress local_IP(192, 168, 1, 20); // reserved to this MAC via router DHCP Binding
IPAddress gateway(192, 168, 1, 1);
IPAddress subnet(255, 255, 255, 0);

const int LOCKOUT_THRESHOLD    = 10;
const unsigned long LOCKOUT_WINDOW_MS   = 60000;
const unsigned long LOCKOUT_DURATION_MS = 60000;
// -----------------------------------------

WebServer server(80);
Preferences prefs;

// ---------- Relay ----------
void setRelay(bool energized) {
  bool level = RELAY_ACTIVE_LOW ? !energized : energized;
  digitalWrite(RELAY_PIN, level ? HIGH : LOW);
}

// ---------- Hex helpers ----------
String bytesToHex(const uint8_t* data, size_t len) {
  static const char* hexChars = "0123456789abcdef";
  String out; out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out += hexChars[(data[i] >> 4) & 0xF];
    out += hexChars[data[i] & 0xF];
  }
  return out;
}
int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
bool hexToBytes(const String& hex, uint8_t* out, size_t outLen) {
  if ((size_t)hex.length() != outLen * 2) return false;
  for (size_t i = 0; i < outLen; i++) {
    int hi = hexVal(hex[i * 2]), lo = hexVal(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}
bool constantTimeEquals(const String& a, const String& b) {
  if (a.length() != b.length()) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < (size_t)a.length(); i++) diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
  return diff == 0;
}

// ---------- HMAC-SHA256 ----------
void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[32]) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_setup(&ctx, info, 1);
  mbedtls_md_hmac_starts(&ctx, key, keyLen);
  mbedtls_md_hmac_update(&ctx, msg, msgLen);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// ---------- Challenge state (single in-flight slot) ----------
uint8_t currentNonce[16];
bool challengeActive = false;
bool challengeUsed = false;
unsigned long challengeIssuedAt = 0;
const unsigned long CHALLENGE_TTL_MS = 30000;

bool checkChallengeResponse(const String& nonceHex, const String& macHex) {
  bool ok = challengeActive && !challengeUsed && (millis() - challengeIssuedAt) <= CHALLENGE_TTL_MS;
  uint8_t submittedNonce[16];
  if (ok) ok = hexToBytes(nonceHex, submittedNonce, sizeof(submittedNonce));
  if (ok) ok = memcmp(submittedNonce, currentNonce, sizeof(currentNonce)) == 0;
  if (ok) {
    uint8_t expectedMac[32];
    hmacSha256((const uint8_t*)UNLOCK_TOKEN, strlen(UNLOCK_TOKEN),
               currentNonce, sizeof(currentNonce), expectedMac);
    ok = constantTimeEquals(bytesToHex(expectedMac, sizeof(expectedMac)), macHex);
  }
  challengeUsed = true;
  return ok;
}

void handleChallenge() {
  esp_fill_random(currentNonce, sizeof(currentNonce));
  challengeActive = true;
  challengeUsed = false;
  challengeIssuedAt = millis();
  server.send(200, "text/plain", bytesToHex(currentNonce, sizeof(currentNonce)));
}
// ---------- Logs (in-memory, cleared on reboot) ----------
LogEvent history[HISTORY_SIZE];
int historyCount = 0, historyHead = 0;
LogEvent failedHistory[HISTORY_SIZE];
int failedCount = 0, failedHead = 0;

void addEvent(LogEvent* buf, int* count, int* head, const String& t, const String& name, const String& ip) {
  LogEvent &e = buf[*head];
  sanitizeField(t).substring(0, 23).toCharArray(e.time, 24);
  sanitizeField(name).substring(0, 23).toCharArray(e.name, 24);
  sanitizeField(ip).substring(0, 15).toCharArray(e.ip, 16);
  *head = (*head + 1) % HISTORY_SIZE;
  if (*count < HISTORY_SIZE) (*count)++;
}

String sanitizeField(const String& s) {
  String out = s;
  out.replace("|", " ");
  out.replace("\n", " ");
  out.replace("\r", " ");
  return out;
}

String jsonEscape(const String& s) {
  String out;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"' || c == '\\') out += '\\';
    out += c;
  }
  return out;
}

String buildLogJson(LogEvent* buf, int count, int head) {
  String json = "[";
  for (int i = 0; i < count; i++) {
    int idx = (head - 1 - i + HISTORY_SIZE) % HISTORY_SIZE;
    if (i > 0) json += ",";
    json += "{\"time\":\"" + jsonEscape(buf[idx].time) + "\",";
    json += "\"name\":\"" + jsonEscape(buf[idx].name) + "\",";
    json += "\"ip\":\"" + jsonEscape(buf[idx].ip) + "\"}";
  }
  json += "]";
  return json;
}

String serializeLog(LogEvent* buf, int count, int head) {
  String out;
  for (int i = count - 1; i >= 0; i--) {
    int idx = (head - 1 - i + HISTORY_SIZE) % HISTORY_SIZE;
    out += String(buf[idx].time) + "|" + String(buf[idx].name) + "|" + String(buf[idx].ip) + "\n";
  }
  return out;
}

void saveHistoryToPrefs() { prefs.putString("hist", serializeLog(history, historyCount, historyHead)); }

void loadLogFromPrefs(const char* key, LogEvent* buf, int* count, int* head) {
  String data = prefs.getString(key, "");
  int start = 0;
  while (start < (int)data.length()) {
    int nl = data.indexOf('\n', start);
    if (nl < 0) break;
    String line = data.substring(start, nl);
    start = nl + 1;
    int p1 = line.indexOf('|');
    int p2 = line.indexOf('|', p1 + 1);
    if (p1 < 0 || p2 < 0) continue;
    addEvent(buf, count, head, line.substring(0, p1), line.substring(p1 + 1, p2), line.substring(p2 + 1));
  }
}

// ---------- Per-IP lockout state ----------
const int MAX_TRACKED_IPS = 8;
IpLockout ipTable[MAX_TRACKED_IPS];

IpLockout* getOrCreateIpEntry(IPAddress ip) {
  int oldestIdx = 0;
  unsigned long oldestTime = ULONG_MAX;
  for (int i = 0; i < MAX_TRACKED_IPS; i++) {
    if (ipTable[i].used && ipTable[i].ip == ip) return &ipTable[i];
    if (!ipTable[i].used) { oldestIdx = i; oldestTime = 0; break; } // free slot wins immediately
    if (ipTable[i].firstFailureAt < oldestTime) { oldestTime = ipTable[i].firstFailureAt; oldestIdx = i; }
  }
  // Reuse free slot or evict oldest entry (LRU-ish) if table is full
  ipTable[oldestIdx] = { ip, 0, 0, 0, true };
  return &ipTable[oldestIdx];
}

bool isIpLockedOut(IPAddress ip) {
  IpLockout* e = getOrCreateIpEntry(ip);
  return millis() < e->lockoutUntil;
}

void registerIpFailure(IPAddress ip) {
  IpLockout* e = getOrCreateIpEntry(ip);
  unsigned long now = millis();
  if (e->failedAttempts == 0) e->firstFailureAt = now;
  if (now - e->firstFailureAt > LOCKOUT_WINDOW_MS) { e->failedAttempts = 0; e->firstFailureAt = now; }
  e->failedAttempts++;
  if (e->failedAttempts >= LOCKOUT_THRESHOLD) {
    e->lockoutUntil = now + LOCKOUT_DURATION_MS;
    e->failedAttempts = 0;
    Serial.println("Lockout triggered for one IP after repeated failed attempts");
  }
}

void registerFailure(const String& t, const String& name, const String& ip) {
  addEvent(failedHistory, &failedCount, &failedHead, t, name, ip);
}

void getReqFields(String &t, String &name, String &ip) {
  t = server.arg("t"); if (t.length() == 0) t = "unknown time";
  name = server.arg("name"); if (name.length() == 0) name = "unknown";
  ip = server.client().remoteIP().toString();
}

void handleHeartbeat() { server.send(200, "text/plain", "ok"); }

void handleUnlock() {
  String t, name, ip;
  getReqFields(t, name, ip);

  if (isIpLockedOut(server.client().remoteIP())) { server.send(429, "text/plain", "locked out"); return; }

  bool ok = checkChallengeResponse(server.arg("nonce"), server.arg("mac"));
  if (!ok) {
    registerFailure(t, name, ip);
    registerIpFailure(server.client().remoteIP());
    server.send(401, "text/plain", "unauthorized");
    Serial.println("Rejected unlock attempt: bad challenge/response");
    return;
  }

  // 1. Log and save successful unlocks
  addEvent(history, &historyCount, &historyHead, t, name, ip);
  saveHistoryToPrefs();
  
  // 2. Respond immediately so UI doesn't hang
  server.send(200, "text/plain", "unlocked");

  // 3. Pulse the relay
  Serial.println("Unlock authorized — pulsing relay");
  setRelay(true);
  delay(PULSE_MS);
  setRelay(false);
}

void handleHistory() {
  String t, name, ip;
  getReqFields(t, name, ip);
  if (isIpLockedOut(server.client().remoteIP())) { server.send(429, "text/plain", "locked out"); return; }
  bool ok = checkChallengeResponse(server.arg("nonce"), server.arg("mac"));
  if (!ok) {
    registerFailure(t, name, ip);
    registerIpFailure(server.client().remoteIP());
    server.send(401, "text/plain", "unauthorized");
    return;
  }
  server.send(200, "application/json", buildLogJson(history, historyCount, historyHead));
}

void handleFailedHistory() {
  String t, name, ip;
  getReqFields(t, name, ip);
  if (isIpLockedOut(server.client().remoteIP())) { server.send(429, "text/plain", "locked out"); return; }
  bool ok = checkChallengeResponse(server.arg("nonce"), server.arg("mac"));
  if (!ok) {
    registerFailure(t, name, ip);
    registerIpFailure(server.client().remoteIP());
    server.send(401, "text/plain", "unauthorized");
    return;
  }
  server.send(200, "application/json", buildLogJson(failedHistory, failedCount, failedHead));
}

// ---------- Web page (Arabic, RTL) ----------
const char INDEX_HTML[] PROGMEM = R"HTMLPAGE(<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, user-scalable=no">
<meta name="theme-color" content="#14171c">
<title>الباب</title>
<link rel="manifest" href="/manifest.json">
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body {
    margin: 0; min-height: 100%; background: #14171c; color: #e7e5df;
    font-family: -apple-system, "Segoe UI", Tahoma, sans-serif;
    overscroll-behavior: none; user-select: none;
  }
  .wrap { min-height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px; gap: 22px; }
  .heartbeat { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #8a8c92; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: #5f5e5a; transition: background .3s; }
  .dot.on { background: #5dcaa5; } .dot.off { background: #e24b4a; }
  .eyebrow { font-size: 13px; color: #8a8c92; }
  #btn {
    width: 190px; height: 190px; border-radius: 50%; border: 1px solid #33363d; background: #1d2027;
    color: #e7e5df; font-size: 20px; font-weight: 500; display: flex; align-items: center; justify-content: center;
    transition: transform .08s ease, background .2s ease, border-color .2s ease; margin: 4px 0;
  }
  #btn:active { transform: scale(0.96); }
  #btn.ok   { background: #163a2a; border-color: #2f7a52; color: #7fd9a8; }
  #btn.fail { background: #3a1a1a; border-color: #7a2f2f; color: #e08a8a; }
  #btn.busy { opacity: .6; }
  #status { font-size: 14px; color: #8a8c92; min-height: 18px; }
  #logsMsg { font-size: 13px; color: #b98a8a; min-height: 16px; }
  #gear, #logsBtn {
    position: fixed; top: 18px; width: 36px; height: 36px; border-radius: 50%;
    border: 1px solid #33363d; background: #1d2027; color: #8a8c92; display: flex;
    align-items: center; justify-content: center; font-size: 16px;
  }
  #gear { left: 18px; }
  #logsBtn { right: 18px; }
  .panel h2 { font-size: 13px; font-weight: 500; color: #8a8c92; margin: 16px 0 10px; }
  .panel.failed h2 { color: #a35a5a; }
  .panel ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .panel li {
    background: #1d2027; border: 1px solid #2a2d34; border-radius: 10px; padding: 10px 12px;
    display: flex; justify-content: space-between; align-items: center; font-size: 13px; color: #c7c5bd;
  }
  .panel.failed li { border-color: #3a2424; color: #b98a8a; }
  .panel .empty { text-align: center; color: #5f5e5a; font-size: 13px; padding: 14px; justify-content: center; }
  .entry-main { display: flex; flex-direction: column; gap: 2px; }
  .entry-main .ip { font-size: 11px; color: #6f7178; }
  .entry-time { font-size: 12px; color: #8a8c92; }
  dialog { background: #1d2027; color: #e7e5df; border: 1px solid #33363d; border-radius: 12px; padding: 20px; width: 280px; max-height: 80vh; overflow-y: auto; }
  dialog label { font-size: 12px; color: #8a8c92; display: block; margin-top: 4px; }
  dialog input { width: 100%; padding: 10px; margin-top: 6px; border-radius: 8px; border: 1px solid #33363d; background: #14171c; color: #e7e5df; font-size: 15px; }
  dialog button { margin-top: 16px; width: 100%; padding: 10px; border-radius: 8px; border: none; background: #3a6f4f; color: white; font-size: 15px; }
  dialog .close { background: #2a2d34; margin-top: 8px; }
  dialog::backdrop { background: rgba(0,0,0,.5); }
</style>
</head>
<body>
  <button id="gear" onclick="settings.showModal()">&#9881;</button>
  <button id="logsBtn" onclick="openLogs()">&#9776;</button>
  <div class="wrap">
    <div class="heartbeat"><span class="dot" id="hbDot"></span><span id="hbText">جارٍ التحقق...</span></div>
    <div class="eyebrow">المنزل</div>
    <button id="btn" onclick="unlock()">فتح</button>
    <div id="status">اضغط لفتح الباب</div>
    <div id="logsMsg"></div>
  </div>

  <dialog id="settings">
    <div style="font-size:15px;font-weight:500;">الإعدادات</div>
    <label>رمز الدخول</label>
    <input id="tokenInput" type="password" placeholder="رمز الدخول">
    <label>اسم الجهاز</label>
    <input id="nameInput" type="text" placeholder="مثلاً: هاتفي">
    <button onclick="saveSettings()">حفظ</button>
  </dialog>

  <dialog id="logsDialog">
    <div style="font-size:15px;font-weight:500;">السجلات</div>
    <div class="panel">
      <h2>سجل الفتح</h2>
      <ul id="historyList"></ul>
    </div>
    <div class="panel failed">
      <h2>محاولات فاشلة</h2>
      <ul id="failedList"></ul>
    </div>
    <button class="close" onclick="logsDialog.close()">إغلاق</button>
  </dialog>

<script>
  const settings = document.getElementById('settings');
  const logsDialog = document.getElementById('logsDialog');
  const btn = document.getElementById('btn');
  const status = document.getElementById('status');
  const logsMsg = document.getElementById('logsMsg');
  const hbDot = document.getElementById('hbDot');
  const hbText = document.getElementById('hbText');

  if (!localStorage.getItem('doorToken')) settings.showModal();
  document.getElementById('tokenInput').value = localStorage.getItem('doorToken') || '';
  document.getElementById('nameInput').value = localStorage.getItem('doorDevice') || '';

  function saveSettings() {
    const tok = document.getElementById('tokenInput').value.trim();
    const name = document.getElementById('nameInput').value.trim();
    if (tok) localStorage.setItem('doorToken', tok);
    if (name) localStorage.setItem('doorDevice', name);
    settings.close();
  }

  function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
  function sha256(msg) {
    const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const len = msg.length, bitLen = len * 8;
    const total = (((len + 9 + 63) >> 6) << 6);
    const buf = new Uint8Array(total); buf.set(msg); buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 4, bitLen >>> 0, false);
    dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000), false);
    const w = new Uint32Array(64);
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
        const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
      }
      let [a,b,c,d,e,f,g,h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    const out = new Uint8Array(32); const odv = new DataView(out.buffer);
    for (let i=0;i<8;i++) odv.setUint32(i*4, H[i], false);
    return out;
  }
  function concatBytes(a,b){ const out=new Uint8Array(a.length+b.length); out.set(a,0); out.set(b,a.length); return out; }
  function hmacSha256(keyBytes, msgBytes) {
    const blockSize = 64; let key = keyBytes;
    if (key.length > blockSize) key = sha256(key);
    if (key.length < blockSize) { const k = new Uint8Array(blockSize); k.set(key); key = k; }
    const oKeyPad = new Uint8Array(blockSize), iKeyPad = new Uint8Array(blockSize);
    for (let i=0;i<blockSize;i++) { oKeyPad[i]=key[i]^0x5c; iKeyPad[i]=key[i]^0x36; }
    const inner = sha256(concatBytes(iKeyPad, msgBytes));
    return sha256(concatBytes(oKeyPad, inner));
  }
  function toHex(bytes){ return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join(''); }
  function hexToBytes(hex){ const out=new Uint8Array(hex.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(hex.substr(i*2,2),16); return out; }
  function strToBytes(str){ return new TextEncoder().encode(str); }
  function formatTime(d) {
    const p = n => String(n).padStart(2,'0');
    return `${p(d.getDate())}/${p(d.getMonth()+1)}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  async function authedFetch(path) {
    const token = localStorage.getItem('doorToken');
    if (!token) { settings.showModal(); throw new Error('no token'); }
    const chRes = await fetch('/challenge', { cache: 'no-store' });
    if (!chRes.ok) throw new Error('challenge failed');
    const nonceHex = (await chRes.text()).trim();
    const macBytes = hmacSha256(strToBytes(token), hexToBytes(nonceHex));
    const macHex = toHex(macBytes);
    const t = encodeURIComponent(formatTime(new Date()));
    const name = encodeURIComponent(localStorage.getItem('doorDevice') || 'غير معروف');
    return fetch(`${path}?nonce=${nonceHex}&mac=${macHex}&t=${t}&name=${name}`, { cache: 'no-store' });
  }

  async function unlock() {
    btn.classList.remove('ok', 'fail');
    btn.classList.add('busy');
    status.textContent = 'جارٍ الفتح...';
    if (navigator.vibrate) navigator.vibrate(15);
    try {
      const res = await authedFetch('/unlock');
      btn.classList.remove('busy');
      if (res.ok) {
        btn.classList.add('ok');
        status.textContent = 'تم فتح الباب';
        if (navigator.vibrate) navigator.vibrate([10, 40, 10]);
      } else if (res.status === 429) {
        btn.classList.add('fail');
        status.textContent = 'محاولات كثيرة، انتظر قليلاً';
      } else {
        btn.classList.add('fail');
        status.textContent = res.status === 401 ? 'رمز خاطئ' : 'فشل (' + res.status + ')';
      }
    } catch (e) {
      btn.classList.remove('busy');
      btn.classList.add('fail');
      status.textContent = 'تعذر الوصول إلى الجهاز';
    }
    setTimeout(() => { btn.classList.remove('ok', 'fail'); status.textContent = 'اضغط لفتح الباب'; }, 1800);
  }

  function renderList(el, items, emptyText) {
    el.innerHTML = '';
    if (items.length === 0) { el.innerHTML = `<li class="empty">${emptyText}</li>`; return; }
    for (const it of items) {
      const li = document.createElement('li');
      const main = document.createElement('div'); main.className = 'entry-main';
      const name = document.createElement('span'); name.textContent = it.name;
      const ip = document.createElement('span'); ip.className = 'ip'; ip.textContent = it.ip;
      main.appendChild(name); main.appendChild(ip);
      const time = document.createElement('span'); time.className = 'entry-time'; time.textContent = it.time;
      li.appendChild(main); li.appendChild(time);
      el.appendChild(li);
    }
  }

  async function openLogs() {
    logsMsg.textContent = '';
    try {
      const hRes = await authedFetch('/history');
      if (!hRes.ok) {
        logsMsg.textContent = hRes.status === 401 ? 'رمز خاطئ' : hRes.status === 429 ? 'محاولات كثيرة، انتظر قليلاً' : 'فشل';
        return;
      }
      const hData = await hRes.json();
      const fRes = await authedFetch('/failed-history');
      const fData = fRes.ok ? await fRes.json() : [];
      renderList(document.getElementById('historyList'), hData, 'لا يوجد سجل بعد');
      renderList(document.getElementById('failedList'), fData, 'لا توجد محاولات فاشلة');
      logsDialog.showModal();
    } catch (e) {
      logsMsg.textContent = 'تعذر الوصول إلى الجهاز';
    }
  }

  async function heartbeat() {
    try {
      const res = await fetch('/heartbeat', { cache: 'no-store' });
      if (res.ok) { hbDot.className = 'dot on'; hbText.textContent = 'متصل'; }
      else { hbDot.className = 'dot off'; hbText.textContent = 'غير متصل'; }
    } catch (e) { hbDot.className = 'dot off'; hbText.textContent = 'غير متصل'; }
  }
  heartbeat();
  setInterval(heartbeat, 1000);

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
</script>
</body>
</html>
)HTMLPAGE";

const char MANIFEST_JSON[] PROGMEM = R"JSONPAGE({
  "name": "الباب",
  "short_name": "الباب",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#14171c",
  "theme_color": "#14171c",
  "icons": [ { "src": "/icon.svg", "sizes": "any", "type": "image/svg+xml" } ]
})JSONPAGE";

const char ICON_SVG[] PROGMEM = R"SVGPAGE(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="20" fill="#1d2027"/><rect x="30" y="46" width="40" height="32" rx="6" fill="#e7e5df"/><path d="M38 46V34a12 12 0 0 1 24 0v12" stroke="#e7e5df" stroke-width="7" fill="none"/></svg>)SVGPAGE";

const char SW_JS[] PROGMEM = R"SWPAGE(
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => self.clients.claim());
self.addEventListener('fetch', e => {});
)SWPAGE";

void handleRoot() {
  server.sendHeader("Cache-Control", "no-store");
  server.send_P(200, "text/html", INDEX_HTML);
}
void handleManifest() { server.send_P(200, "application/json", MANIFEST_JSON); }
void handleIcon()     { server.send_P(200, "image/svg+xml", ICON_SVG); }
void handleSW()       { server.send_P(200, "application/javascript", SW_JS); }

void setup() {
  Serial.begin(115200);
  pinMode(RELAY_PIN, OUTPUT);
  setRelay(false);

  prefs.begin("doorlog", false);
  loadLogFromPrefs("hist", history, &historyCount, &historyHead);
  
  WiFi.config(local_IP, gateway, subnet);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  WiFi.setSleep(false);

  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(400);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Connected. IP address: ");
  Serial.println(WiFi.localIP());

  server.on("/", handleRoot);
  server.on("/manifest.json", handleManifest);
  server.on("/icon.svg", handleIcon);
  server.on("/sw.js", handleSW);
  server.on("/challenge", handleChallenge);
  server.on("/unlock", handleUnlock);
  server.on("/history", handleHistory);
  server.on("/failed-history", handleFailedHistory);
  server.on("/heartbeat", handleHeartbeat);
  server.begin();
}

void loop() {
  server.handleClient();
}