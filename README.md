# ESP32 Remote Relay / Door Release

A small ESP32 project that serves a mobile-friendly web page with one big button. Tap it, and the ESP32 pulses a relay for a fraction of a second.

I built this to trigger my building's intercom door-release button remotely, but the relay pulse is generic. Swap the relay's COM/NO wires onto anything that's normally switched by a momentary push-button (a garage door opener, a gate latch, a doorbell, a lab instrument's trigger input, etc.) and this works the same way.

## Features

- **One-button web UI** (Arabic, RTL), installable as a home-screen PWA, works from any phone on the network or over your own VPN/port-forward.
- **Challenge-response authentication**: the browser never sends the shared token over the wire. It fetches a random nonce from `/challenge` and returns an HMAC-SHA256(token, nonce) computed in-browser; the ESP32 checks it with a constant-time comparison.
- **Per-IP lockout**: repeated failed attempts from the same IP get temporarily locked out.
- **Activity log**: successful unlocks and failed attempts are logged (time, device name, IP) and persisted across reboots using `Preferences` (flash-backed key/value storage).
- **Live heartbeat indicator** on the page so you can see at a glance whether the ESP32 is reachable.

## Hardware

- An ESP32 dev board
- A relay module (with an opto-isolated input is recommended)
- The two wires from whatever momentary contact you want to trigger

### Wiring

![Wiring diagram](images/wiring-diagram.svg)

Wiring in parallel means the original button still works normally. The relay just gives you a second, remote way to close the same contact.

## Setup

1. **Install the Arduino ESP32 core** (Boards Manager, search "esp32", install the Espressif package).
2. **Libraries used**: `WiFi`, `WebServer`, `mbedtls`, `esp_random`, `Preferences`. All of these ship with the ESP32 core, no extra installs needed.
3. **Open `door-relay.ino`** and edit the config block near the top:

   ```cpp
   const char* WIFI_SSID     = "NAME";
   const char* WIFI_PASSWORD = "PASSWORD";
   const char* UNLOCK_TOKEN  = "TOKEN_PASSWORD";

   const int RELAY_PIN         = 26;
   const bool RELAY_ACTIVE_LOW = false;   // set true if your relay triggers on LOW
   const int PULSE_MS          = 700;     // how long the relay stays closed

   IPAddress local_IP(192, 168, 1, 20);   // pick a free address, reserve it via
   IPAddress gateway(192, 168, 1, 1);     // a DHCP binding on your router so it
   IPAddress subnet(255, 255, 255, 0);    // doesn't collide with anything
   ```

   Use a long, random `UNLOCK_TOKEN`. It's the shared secret the HMAC is built from.

4. **Flash it** to the ESP32, open the Serial Monitor at `115200` baud, and confirm it connects to Wi-Fi and prints its IP.
5. **Browse to that IP** from your phone. On first load it'll prompt for the token. Enter the same `UNLOCK_TOKEN` you set in the sketch, plus an optional device name for the log. Add it to your home screen for a one-tap app.

## Adapting it to other relay uses

The unlock logic is completely generic, it's just "close the relay for `PULSE_MS` milliseconds." To repurpose this for something other than a door:

- Change `PULSE_MS` if you need a longer or shorter pulse.
- If your target needs the relay to stay latched rather than pulse, replace the `setRelay(true); delay(...); setRelay(false);` block in `handleUnlock()` with your own logic (e.g. toggle-on/toggle-off, or a fixed hold time).
- Everything else (auth, lockout, logging, the web page) works unchanged regardless of what's on the other side of the relay.

## Security notes

- This is a hobby project for a private home network, not a certified access-control product. Use it at your own risk, and don't rely on it as your only security measure for anything important.
- The token is the only secret protecting the endpoint. Keep your network private (Wi-Fi password, VPN for remote access) rather than port-forwarding this directly onto the open internet.
- Logs are kept in flash memory (via `Preferences`) and are limited to the most recent entries; this isn't meant to be a tamper-proof audit trail.

## License

MIT, see [LICENSE](LICENSE).
