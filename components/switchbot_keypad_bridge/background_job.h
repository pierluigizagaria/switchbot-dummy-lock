#pragma once

// Shared progress/job scaffold for the setup wizard's background BLE tasks.
// Protocol-specific classes keep their own Request and success payloads.

#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <utility>

#include "esphome/core/log.h"

namespace esphome {
namespace switchbot_keypad_bridge {

class BackgroundBleJob {
 public:
  enum class State : uint8_t {
    IDLE,
    RUNNING,
    SUCCESS,
    FAILED,
  };

  struct Status {
    State state{State::IDLE};
    uint8_t step{0};
    uint8_t total{0};
    std::string message;
    std::string error;
    std::string job_id;
  };

  State state() const {
    std::lock_guard<std::mutex> lk(this->mu_);
    return this->status_.state;
  }

 protected:
  bool is_running_() const {
    std::lock_guard<std::mutex> lk(this->mu_);
    return this->status_.state == State::RUNNING;
  }

  void copy_status_base_(Status &out) const { out = this->status_; }

  void mark_running_(uint8_t total, const std::string &job_id,
                     const char *first_message) {
    std::lock_guard<std::mutex> lk(this->mu_);
    this->status_ = Status{};
    this->status_.state = State::RUNNING;
    this->status_.total = total;
    this->status_.message = first_message != nullptr ? first_message : "";
    this->status_.job_id = job_id;
  }

  void mark_step_(uint8_t step, const char *message, const char *tag) {
    std::lock_guard<std::mutex> lk(this->mu_);
    ESP_LOGI(tag, "Step %u/%u: %s", static_cast<unsigned>(step + 1),
             static_cast<unsigned>(this->status_.total),
             message != nullptr ? message : "");
    this->status_.step = step;
    this->status_.message = message != nullptr ? message : "";
  }

  void mark_failed_(const std::string &err, const char *tag,
                    const char *job_label) {
    ESP_LOGW(tag, "%s failed: %s", job_label, err.c_str());
    std::lock_guard<std::mutex> lk(this->mu_);
    this->status_.state = State::FAILED;
    this->status_.error = err;
    this->status_.message = err;
  }

  template <typename Owner, typename Request, typename Prepare>
  std::string start_job_(Owner *owner, Request req, char job_prefix,
                         const char *task_name, uint8_t total_steps,
                         const char *first_message, const char *start_error,
                         const char *tag, const char *job_label,
                         TaskHandle_t *task_handle, Prepare prepare) {
    char job_buf[16];
    std::snprintf(job_buf, sizeof(job_buf), "%c-%lu", job_prefix,
                  static_cast<unsigned long>(esp_timer_get_time() / 1000));
    std::string job_id = job_buf;

    auto *req_heap = new Request(std::move(req));
    {
      std::lock_guard<std::mutex> lk(this->mu_);
      if (this->status_.state == State::RUNNING) {
        delete req_heap;
        return "";
      }
      prepare(*req_heap);
      this->status_ = Status{};
      this->status_.state = State::RUNNING;
      this->status_.total = total_steps;
      this->status_.message = first_message != nullptr ? first_message : "";
      this->status_.job_id = job_id;
    }

    struct TaskCtx {
      Owner *self;
      Request *req;
      TaskHandle_t *task_handle;
    };
    auto *ctx = new TaskCtx{owner, req_heap, task_handle};

    BaseType_t rc = xTaskCreatePinnedToCore(
        [](void *raw) {
          auto *c = static_cast<TaskCtx *>(raw);
          c->self->execute_(*c->req);
          delete c->req;
          if (c->task_handle != nullptr) {
            *c->task_handle = nullptr;
          }
          delete c;
          vTaskDelete(nullptr);
        },
        task_name, 8192, ctx, tskIDLE_PRIORITY + 2, task_handle, 0);

    if (rc != pdPASS) {
      delete ctx;
      delete req_heap;
      this->mark_failed_(start_error, tag, job_label);
      return "";
    }
    return job_id;
  }

  mutable std::mutex mu_;
  Status status_{};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
