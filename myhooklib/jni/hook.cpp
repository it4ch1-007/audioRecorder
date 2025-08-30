#include <iostream>
// #include <android/log.h>
#include "file_utils.h"
#include <queue>
#include "packet.h"
#include "vad.h"
#include <condition_variable>
#include <mutex>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <optional>
#include <cstdint>

typedef int32_t status_t;
#define LOG_TAG "NativeHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

std::atomic<bool> is_mode_enabled = false;
std::atomic<bool> is_writer_thread_running = false;
std::thread writer_thread;
// std::vector<std::byte> received_packets, sent_packets;

const auto HANGOVER_DURATION = std::chrono::milliseconds(400);

enum class AudioDirection
{
    IN,
    OUT
};
enum class PacketType
{
    VOICE_CANDIDATE,
    HANGOVER_SILENCE
};

struct AudioPacket
{
    std::chrono::steady_clock::time_point timestamp;
    AudioDirection direction;
    PacketType type;
    std::vector<int16_t> data;

    // custom condition for the priority queue...
    bool operator>(const AudioPacket &other) const
    {
        return timestamp > other.timestamp;
    }
};

struct ConversationState
{
    std::mutex mtx;
    std::chrono::steady_clock::time_point last_voice_activity_time{std::chrono::steady_clock::now()};
} conv_state;

// Priority queue
template <typename T>
class PQ
{
public:
    PQ(size_t max_size) : m_max_size(max_size) {};
    bool try_push(T value)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_max_size)
        {
            return false;
        }
        m_queue.push(std::move(value));
        m_cond.notify_one();
        return true;
    }

    bool try_pop(T &value)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.empty())
        {
            return false;
        }

        value = m_queue.top();
        m_queue.pop();
        return true;
    }

    void wait_and_pop(T &value)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cond.wait(lock, [this]
                    { return !m_queue.empty(); });
        value = m_queue.top();
        m_queue.pop();
    }
    bool is_empty()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty();
    }

private:
    std::priority_queue<T, std::vector<T>, std::greater<T>> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    const size_t m_max_size;
};
PQ<AudioPacket> audio_queue(2000);

bool is_voice_fft(const std::vector<int16_t> &pcm_data);

void file_writer_task()
{
    std::ofstream pcm_file("/sdcard/Download/capturedPcm.dat", std::ios::binary);
    if (!pcm_file.is_open())
    { // LOGI("Failed to open output file!");
        return;
    }
    is_writer_thread_running = true;
    while (is_writer_thread_running || !audio_queue.is_empty())
    {
        AudioPacket packet;
        audio_queue.wait_and_pop(packet);
        pcm_file.write(reinterpret_cast<const char*>(packet.data.data()), packet.data.size() * sizeof(int16_t));
    }
    pcm_file.close();
}

void audio_packet_handler(void *buffer, size_t num_bytes, AudioDirection direction)
{
    if (!is_mode_enabled || num_bytes == 0)
        return;

    auto *pcm_buffer = static_cast<const int16_t *>(buffer);
    size_t num_samples = num_bytes / sizeof(int16_t);
    auto now = std::chrono::steady_clock::now();
    Packet packet = Packet(static_cast<char *>(buffer), num_bytes);
    if (packet.is_voice())
    {
        {
            std::lock_guard<std::mutex> lock(conv_state.mtx);
            conv_state.last_voice_activity_time = now;
        }

        AudioPacket packet_;
        packet_.timestamp = now;
        packet_.direction = direction;
        packet_.type = PacketType::VOICE_CANDIDATE;
        packet_.data.assign(pcm_buffer, pcm_buffer + num_samples);
        audio_queue.try_push(std::move(packet_));
    }
    else
    {
        std::chrono::steady_clock::time_point last_activity;
        {
            std::lock_guard<std::mutex> lock(conv_state.mtx);
            last_activity = conv_state.last_voice_activity_time;
        }
        if (now - last_activity < HANGOVER_DURATION)
        {
            AudioPacket packet_;
            packet_.timestamp = now;
            packet_.direction = direction;
            packet_.type = PacketType::HANGOVER_SILENCE;
            packet_.data.assign(pcm_buffer, pcm_buffer + num_samples);
            audio_queue.try_push(std::move(packet_));
        }
    }
}

/// TODO: Add hook for the setMode fn
/// TODO: Add the fn to hook and put the pcm packets inside the data file.

status_t (*origAudioflingerSetMode)(void *this_ptr, int mode) = nullptr;
ssize_t (*origAudioStreamOutWrite)(void *buffer, size_t numBytes) = nullptr;
status_t (*origAudioStreamInRead)(void *buffer, size_t bytes, size_t *read) = nullptr;
status_t newAudioFlingersetMode(void *this_, int mode)
{
    if(mode==3){
        if(!is_mode_enabled.exchange(true)){
            // LOGI("Starting writer thread!!");
            writer_thread = std::thread(file_writer_task);
        }
        else{
            if(is_mode_enabled.exchange(false)){
                is_writer_thread_running = false;
                if(writer_thread.joinable()){
                    writer_thread.join();
                }
            }
        }
    }
    status_t result = origAudioflingerSetMode(this_, mode);
    return result;
}

ssize_t newAudioStreamOutWrite(void *buffer, size_t numBytes)
{
    audio_packet_handler(buffer, numBytes, AudioDirection::IN);
    ssize_t result = origAudioStreamOutWrite(buffer, numBytes);
    return result;
}

status_t newAudioStreamInRead(void *buffer, size_t bytes, size_t *read)
{
    audio_packet_handler(buffer, bytes, AudioDirection::OUT);
    status_t result = origAudioStreamInRead(buffer, bytes, read);
    return result;
}

void hook_main()

{
    // hooking the fn to get the mode value
    const char *libraryPath = "libaudioflinger.so";
    const char *mangledSymbol = "_ZN7android12AudioFlinger7setModeEi";
    NativeHook::Hook(libraryPath, mangledSymbol, (void *)newAudioFlingersetMode, (void **)origAudioflingerSetMode);
    const char *mangledSymbol2 = "_ZN7android14AudioStreamOut5writeEPKvj";
    NativeHook::Hook(libraryPath, mangledSymbol2, (void *)newAudioStreamOutWrite, (void **)origAudioStreamOutWrite);
    const char *mangledSymbol3 = "_ZN7android13AudioStreamIn4readEPvj";
    NativeHook::Hook(libraryPath, mangledSymbol3, (void *)newAudioStreamInRead, (void **)origAudioStreamInRead);
    // hooking to get the PCM packets that are received
    // hooking to get the PCM packets that are sent from the device to the other end.
}
// Constructor that runs when the library is first loaded.
__attribute__((constructor)) void on_load()
{
    // LOGI("libhook.so loaded successfully and on_load() was called!");
    std::ofstream ofs("/data/local/tmp/hookconfirm.txt");
    ofs << "Loaded!" << std::endl;
    ofs.close();
    std::thread(hook_main).detach();
}
