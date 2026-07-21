#include "cloud_client.h"

#include <cstring>
#include <ctime>

#include <cJSON.h>
#include <esp_crt_bundle.h>
#include <esp_http_client.h>
#include <esp_system.h>
#include <esp_tls.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "esphome/core/log.h"
#include "mac_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.cloud";

// The OAuth-style clientId the official SwitchBot app uses.
constexpr const char *CLIENT_ID = "5nnwmhmsa9xxskm14hd85lm9bm";

constexpr const char *ACCOUNT_BASE = "https://account.api.switchbot.net";

// NOTE: keypads are no longer identified by their cloud SKU. The cloud is used
// only to enumerate the account's devices (MAC + name) and to fetch each
// keypad's communication key. Whether a device *is* a keypad — and which
// protocol family it speaks — is decided solely from its BLE advertisement, the
// way the official pySwitchbot library does it (see keypad_advert.h). This keeps
// us from chasing SwitchBot's ever-growing list of device_type codes.

// Build the account-login request body. cJSON handles escaping, so a
// password containing `"` or `\` is sent correctly rather than producing
// malformed JSON.
std::string build_login_body(const std::string &email,
                             const std::string &password) {
  cJSON *o = cJSON_CreateObject();
  cJSON_AddStringToObject(o, "clientId", CLIENT_ID);
  cJSON_AddStringToObject(o, "username", email.c_str());
  cJSON_AddStringToObject(o, "password", password.c_str());
  cJSON_AddStringToObject(o, "grantType", "password");
  cJSON_AddStringToObject(o, "verifyCode", "");
  char *s = cJSON_PrintUnformatted(o);
  std::string body = (s != nullptr) ? s : "{}";
  if (s != nullptr) cJSON_free(s);
  cJSON_Delete(o);
  return body;
}

// Body recipient for esp_http_client. We accumulate into a std::string
// owned by user_data, growing as data comes in.
esp_err_t http_event_handler(esp_http_client_event_t *evt) {
  if (evt->event_id == HTTP_EVENT_ON_DATA && evt->user_data != nullptr) {
    auto *buf = static_cast<std::string *>(evt->user_data);
    buf->append(static_cast<const char *>(evt->data),
                static_cast<size_t>(evt->data_len));
  }
  return ESP_OK;
}

// Parsed SwitchBot API envelope. Every endpoint wraps its payload the same
// way: `{"statusCode": 100, "message": "...", "body": {...}}`. The cJSON
// tree is freed on scope exit, so error paths can simply return.
class Envelope {
 public:
  explicit Envelope(const std::string &raw) {
    this->root_ = cJSON_ParseWithLength(raw.data(), raw.size());
    if (this->root_ == nullptr) return;
    cJSON *sc = cJSON_GetObjectItemCaseSensitive(this->root_, "statusCode");
    this->status_code_ = cJSON_IsNumber(sc) ? sc->valueint : -1;
    cJSON *msg = cJSON_GetObjectItemCaseSensitive(this->root_, "message");
    if (cJSON_IsString(msg) && msg->valuestring != nullptr) {
      this->message_ = msg->valuestring;
    }
  }
  ~Envelope() {
    if (this->root_ != nullptr) cJSON_Delete(this->root_);
  }
  Envelope(const Envelope &) = delete;
  Envelope &operator=(const Envelope &) = delete;

  bool is_json() const { return this->root_ != nullptr; }
  // SwitchBot APIs set statusCode 100 on success.
  bool ok() const { return this->is_json() && this->status_code_ == 100; }
  // The API's own error message, or `fallback` when it didn't send one.
  std::string error_or(const char *fallback) const {
    return this->message_.empty() ? fallback : this->message_;
  }
  cJSON *body() const {
    return this->is_json() ? cJSON_GetObjectItemCaseSensitive(this->root_, "body") : nullptr;
  }
  // Convenience: `body()[key]`, or nullptr anywhere along the way.
  cJSON *body_item(const char *key) const {
    cJSON *b = this->body();
    return b != nullptr ? cJSON_GetObjectItemCaseSensitive(b, key) : nullptr;
  }

 private:
  cJSON *root_{nullptr};
  int status_code_{-1};
  std::string message_;
};

bool parse_hex_byte(const char *s, uint8_t &out) {
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  int hi = digit(s[0]);
  int lo = digit(s[1]);
  if (hi < 0 || lo < 0) return false;
  out = static_cast<uint8_t>((hi << 4) | lo);
  return true;
}

bool parse_hex_string(const std::string &hex, std::vector<uint8_t> &out) {
  if (hex.size() % 2 != 0) return false;
  out.clear();
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t b;
    if (!parse_hex_byte(hex.c_str() + i, b)) return false;
    out.push_back(b);
  }
  return true;
}

}  // namespace

// ── HTTPS plumbing ────────────────────────────────────────────────────────

bool CloudClient::post_json_(const std::string &url, const std::string &body,
                             const std::string &bearer, std::string &out,
                             std::string &error_out) {
  out.clear();

  // TLS cert validation needs a valid system clock — at first boot the ESP32
  // wakes up at the epoch, so cert.notBefore checks fail and the handshake
  // errors out as ESP_ERR_HTTP_CONNECT. Wait briefly for SNTP (or HA-API
  // sync) to set the clock before issuing the request.
  constexpr time_t MIN_VALID_TIME = 1700000000;  // 2023-11-14
  const TickType_t start = xTaskGetTickCount();
  while (time(nullptr) < MIN_VALID_TIME) {
    if ((xTaskGetTickCount() - start) > pdMS_TO_TICKS(10000)) {
      error_out = "Device clock not set — TLS needs a valid system time. Add "
                  "`time: - platform: sntp` to the YAML, or wait until Home "
                  "Assistant connects (its API component syncs the clock).";
      return false;
    }
    vTaskDelay(pdMS_TO_TICKS(200));
  }

  esp_http_client_config_t cfg = {};
  cfg.url = url.c_str();
  cfg.method = HTTP_METHOD_POST;
  cfg.event_handler = http_event_handler;
  cfg.user_data = &out;
  cfg.transport_type = HTTP_TRANSPORT_OVER_SSL;
  cfg.crt_bundle_attach = esp_crt_bundle_attach;
  cfg.timeout_ms = 8000;
  cfg.buffer_size = 1024;
  cfg.buffer_size_tx = 1024;

  esp_http_client_handle_t client = esp_http_client_init(&cfg);
  if (client == nullptr) {
    error_out = "esp_http_client_init failed";
    return false;
  }

  esp_http_client_set_header(client, "Content-Type", "application/json");
  esp_http_client_set_header(client, "Accept", "application/json");
  if (!bearer.empty()) {
    esp_http_client_set_header(client, "authorization", bearer.c_str());
  }
  esp_http_client_set_post_field(client, body.c_str(),
                                 static_cast<int>(body.size()));

  esp_err_t err = esp_http_client_perform(client);
  if (err != ESP_OK) {
    // Transient connect failures ("sock < 0") happen when a TLS handshake
    // lands on a bad moment — BLE/WiFi radio contention or a short heap dip.
    // Log the heap for diagnosis and retry once before giving up.
    ESP_LOGW(TAG, "HTTPS attempt failed (%s), free heap %u — retrying once",
             esp_err_to_name(err),
             static_cast<unsigned>(esp_get_free_heap_size()));
    esp_http_client_close(client);
    out.clear();
    vTaskDelay(pdMS_TO_TICKS(500));
    err = esp_http_client_perform(client);
  }
  bool ok = false;
  if (err != ESP_OK) {
    error_out = "HTTPS request failed: ";
    error_out += esp_err_to_name(err);
  } else {
    int status = esp_http_client_get_status_code(client);
    if (status / 100 != 2) {
      error_out = "HTTP ";
      error_out += std::to_string(status);
      // Body may still be useful for diagnostics.
      ESP_LOGW(TAG, "%s -> %d, body: %s", url.c_str(), status, out.c_str());
    } else {
      ok = true;
    }
  }
  esp_http_client_cleanup(client);
  return ok;
}

std::string CloudClient::wonderlabs_base_() const {
  std::string url = "https://wonderlabs.";
  url += this->region_.empty() ? "us" : this->region_;
  url += ".api.switchbot.net";
  return url;
}

// ── Public API ────────────────────────────────────────────────────────────

bool CloudClient::login(const std::string &email, const std::string &password,
                        std::string &error_out) {
  this->clear();

  // Step 1: account login -> bearer token.
  {
    std::string url = std::string(ACCOUNT_BASE) + "/account/api/v1/user/login";
    std::string body = build_login_body(email, password);
    std::string response;
    if (!this->post_json_(url, body, "", response, error_out)) {
      return false;
    }

    Envelope env(response);
    if (!env.is_json()) {
      error_out = "Login response was not valid JSON";
      return false;
    }
    if (!env.ok()) {
      error_out = env.error_or("Login rejected");
      return false;
    }
    cJSON *tok = env.body_item("access_token");
    if (!cJSON_IsString(tok) || tok->valuestring == nullptr) {
      error_out = "Login succeeded but no access_token returned";
      return false;
    }
    this->auth_token_ = tok->valuestring;
  }

  // Step 2: userinfo -> region. Failure here is non-fatal: we default
  // to "us" and continue.
  this->region_ = "us";
  {
    std::string url = std::string(ACCOUNT_BASE) + "/account/api/v1/user/userinfo";
    std::string response;
    std::string ignored_err;
    if (this->post_json_(url, "{}", this->auth_token_, response, ignored_err)) {
      Envelope env(response);
      cJSON *r = env.ok() ? env.body_item("botRegion") : nullptr;
      if (cJSON_IsString(r) && r->valuestring && r->valuestring[0] != '\0') {
        this->region_ = r->valuestring;
      }
    }
  }

  ESP_LOGI(TAG, "Logged in, region=%s", this->region_.c_str());
  return true;
}

bool CloudClient::list_devices(std::vector<AccountDevice> &out_devices,
                               std::string &error_out, bool force_refresh) {
  if (!this->is_logged_in()) {
    error_out = "Not logged in";
    return false;
  }
  if (!force_refresh && !this->devices_cache_.empty()) {
    out_devices = this->devices_cache_;
    return true;
  }

  std::string url = this->wonderlabs_base_() + "/wonder/device/v3/getdevice";
  std::string response;
  if (!this->post_json_(url, R"json({"required_type":"All"})json",
                        this->auth_token_, response, error_out)) {
    return false;
  }

  Envelope env(response);
  if (!env.is_json()) {
    error_out = "Device list response was not valid JSON";
    return false;
  }
  if (!env.ok()) {
    error_out = env.error_or("Device list rejected");
    return false;
  }

  cJSON *items = env.body_item("Items");
  if (!cJSON_IsArray(items)) {
    error_out = "Device list missing Items array";
    return false;
  }

  // Return every account device that has a MAC. We don't classify here — the
  // setup UI decides which of these are keypads purely from each device's
  // live BLE advertisement (see keypad_advert.h).
  std::vector<AccountDevice> picked;
  cJSON *item = nullptr;
  cJSON_ArrayForEach(item, items) {
    cJSON *mac = cJSON_GetObjectItemCaseSensitive(item, "device_mac");
    if (!cJSON_IsString(mac) || mac->valuestring == nullptr) continue;
    cJSON *name = cJSON_GetObjectItemCaseSensitive(item, "device_name");
    cJSON *detail = cJSON_GetObjectItemCaseSensitive(item, "device_detail");
    cJSON *type = detail != nullptr ? cJSON_GetObjectItemCaseSensitive(detail, "device_type")
                                    : nullptr;

    AccountDevice dev;
    dev.mac          = compact_mac(mac->valuestring);
    dev.mac_pretty   = pretty_mac(dev.mac);
    dev.name         = (cJSON_IsString(name) && name->valuestring) ? name->valuestring
                                                                    : dev.mac_pretty;
    dev.device_type  = (cJSON_IsString(type) && type->valuestring) ? type->valuestring : "";
    picked.push_back(std::move(dev));
  }

  ESP_LOGI(TAG, "Account has %u device(s)", static_cast<unsigned>(picked.size()));

  this->devices_cache_ = picked;
  out_devices = std::move(picked);
  return true;
}

bool CloudClient::fetch_device_key(const std::string &mac,
                                   std::string &key_id_hex,
                                   std::vector<uint8_t> &key_bytes,
                                   std::string &error_out) {
  if (!this->is_logged_in()) {
    error_out = "Not logged in";
    return false;
  }

  std::string url = this->wonderlabs_base_() + "/wonder/keys/v1/communicate";
  std::string body;
  body.reserve(64);
  body += R"json({"device_mac":")json";
  body += compact_mac(mac);
  body += R"json(","keyType":"user"})json";

  std::string response;
  if (!this->post_json_(url, body, this->auth_token_, response, error_out)) {
    return false;
  }

  Envelope env(response);
  if (!env.is_json()) {
    error_out = "communicate response was not valid JSON";
    return false;
  }
  if (!env.ok()) {
    error_out = env.error_or("communicate rejected");
    return false;
  }

  cJSON *ckey = env.body_item("communicationKey");
  if (!cJSON_IsObject(ckey)) {
    error_out = "communicate response missing communicationKey";
    return false;
  }
  cJSON *kid = cJSON_GetObjectItemCaseSensitive(ckey, "keyId");
  cJSON *k   = cJSON_GetObjectItemCaseSensitive(ckey, "key");
  if (!cJSON_IsString(kid) || !cJSON_IsString(k) ||
      kid->valuestring == nullptr || k->valuestring == nullptr) {
    error_out = "communicate response missing keyId/key";
    return false;
  }

  key_id_hex = kid->valuestring;
  if (!parse_hex_string(k->valuestring, key_bytes) || key_bytes.size() != 16) {
    error_out = "communicate returned a malformed AES key";
    return false;
  }
  return true;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
