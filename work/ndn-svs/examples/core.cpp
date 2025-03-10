#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <chrono>
#include <mutex>
#include <atomic>
#include <random>

#include <ndn-cxx/util/time.hpp>
#include <ndn-svs/svsync.hpp>
#include <ndn-cxx/util/random.hpp>


struct Options
{
  std::string prefix;
  std::string m_id;
  int pub_timing; // Frequency of publishing in milliseconds
  int timerSetting; // Timer setting for experiments
};

class Program
{
public:
    Program(const Options& options)
        : m_options(options), m_running(true) // Initialize m_running to true
    {
        // Create the SVSyncCore instance
        m_svs = std::make_shared<ndn::svs::SVSyncCore>(
            face,                                    // Shared NDN face
            ndn::Name(m_options.prefix),             // Sync prefix, common for all nodes in the group
            std::bind(&Program::onUpdate, this, _1), // Callback on learning new sequence numbers from SVS
            ndn::svs::SecurityOptions::DEFAULT,      // Security configuration
            ndn::Name(m_options.m_id),               // Unique prefix for this node
            m_options.timerSetting
        );

        std::cout << "SVS client starting: " << m_options.m_id << std::endl;
    }

    void run()
    {
        // Begin processing face events in a separate thread.
        std::thread svsThread([this] { 
            while (m_running) { // Check m_running flag
                face.processEvents(ndn::time::milliseconds(500));
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Small sleep to avoid busy-waiting
            }
        });

        // Use the NDN-CXX random number engine
        auto& rng = ndn::random::getRandomNumberEngine();
        // Uniform distribution between 0 and pub_timing
        std::uniform_int_distribution<> dist(0, m_options.pub_timing);

        std::this_thread::sleep_for(std::chrono::milliseconds(dist(rng)));

        auto startTime = std::chrono::steady_clock::now(); // Record the start time

        // Increment our sequence number every PUB_TIMING milliseconds
        while (true) {
            auto currentTime = std::chrono::steady_clock::now();
            auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();

            // Stop publishing after 120 seconds
            if (elapsedTime < 120) {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto seq = m_svs->getSeqNo() + 1;
                m_svs->updateSeqNo(seq);
                auto timeSinceEpoch = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                std::cout << "Published sequence number: " << m_options.m_id << "=" << seq <<
                  " at " << timeSinceEpoch << std::endl;
            }

            // Exit the loop after 150 seconds
            if (elapsedTime >= 150) {
                break;
            }

            // Sleep for PUB_TIMING milliseconds
            std::this_thread::sleep_for(std::chrono::milliseconds(m_options.pub_timing));
        }

        // Stop the face.processEvents() thread
        m_running = false; // Set the flag to false
        svsThread.join();  // Wait for the thread to finish

        // Terminate the application
        std::cout << "Stopping SVS client: " << m_options.m_id << std::endl;
    }

protected:
    void onUpdate(const std::vector<ndn::svs::MissingDataInfo>& v)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto timeSinceEpoch = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        for (size_t i = 0; i < v.size(); i++) {
            for (ndn::svs::SeqNo s = v[i].low; s <= v[i].high; ++s) {
                std::cout << "Received update: " << v[i].nodeId << "=" << s << 
                  " at " << timeSinceEpoch << std::endl;
            }
        }
    }

public:
    const Options m_options;
    ndn::Face face;
    std::shared_ptr<ndn::svs::SVSyncCore> m_svs;
    ndn::KeyChain m_keyChain;

private:
    std::mutex m_mutex; // For thread safety in writing to log
    std::atomic<bool> m_running; // Flag to control the face.processEvents() thread
};

int
main(int argc, char** argv)
{
  if (argc != 4) {
    std::cerr << "Usage: " << argv[0] << " <prefix> <pub_timing> <timerSetting>" << std::endl;
    return 1;
  }

  Options opt;
  opt.prefix = "/ndn/svs";
  opt.m_id = argv[1];
  opt.pub_timing = std::stoi(argv[2]);
  opt.timerSetting = std::stoi(argv[3]);

  Program program(opt);

  // Run the program indefinitely
  program.run();

  return 0;
}