#include "../include/load_balancer.h"
#include <iostream>
#include <chrono>
#include <stdexcept>

namespace DPI {

// ============================================================================
// LoadBalancer Implementation
// ============================================================================

LoadBalancer::LoadBalancer(int lb_id,
                           std::vector<std::shared_ptr<ThreadSafeQueue<PacketJob>>> fp_queues,
                           int fp_start_id)
    : lb_id_(lb_id),
      fp_start_id_(fp_start_id),
      num_fps_(fp_queues.size()),
      input_queue_(10000),
      fp_queues_(std::move(fp_queues)),
      per_fp_counts_(std::make_unique<std::atomic<uint64_t>[]>(fp_queues_.size())) {
    for (int i = 0; i < num_fps_; i++) {
        per_fp_counts_[i] = 0;
    }
}

LoadBalancer::~LoadBalancer() {
    stop();
}

void LoadBalancer::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&LoadBalancer::run, this);
    
    std::cout << "[LB" << lb_id_ << "] Started (serving FP" 
              << fp_start_id_ << "-FP" << (fp_start_id_ + num_fps_ - 1) << ")\n";
}

void LoadBalancer::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[LB" << lb_id_ << "] Stopped\n";
}

void LoadBalancer::run() {
    while (running_) {
        // Get packet from input queue (with timeout to check running flag)
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            continue;  // Timeout or shutdown
        }
        
        packets_received_++;
        
        // Select target FP based on five-tuple hash
        int fp_index = selectFP(job_opt->tuple);
        
        // Push to selected FP's queue
        bool enqueued = false;
        if (fp_queues_[fp_index]) {
            enqueued = fp_queues_[fp_index]->push(std::move(*job_opt));
        }
        
        if (enqueued) {
            packets_dispatched_++;
            per_fp_counts_[fp_index]++;
        }
    }
}

int LoadBalancer::selectFP(const FiveTuple& tuple) {
    // Hash the five-tuple and map to one of our FPs
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    return hash % num_fps_;
}

LoadBalancer::LBStats LoadBalancer::getStats() const {
    LBStats stats;
    stats.packets_received = packets_received_.load();
    stats.packets_dispatched = packets_dispatched_.load();
    
    stats.per_fp_packets.resize(num_fps_);
    for (int i = 0; i < num_fps_; i++) {
        stats.per_fp_packets[i] = per_fp_counts_[i].load();
    }
    
    return stats;
}

// ============================================================================
// LBManager Implementation
// ============================================================================

LBManager::LBManager(int num_lbs, int fps_per_lb,
                     std::vector<std::shared_ptr<ThreadSafeQueue<PacketJob>>> fp_queues)
    : fps_per_lb_(fps_per_lb) {
    
    if (num_lbs <= 0 || fps_per_lb <= 0) {
        throw std::invalid_argument("num_lbs and fps_per_lb must be positive");
    }

    const size_t expected = static_cast<size_t>(num_lbs) * static_cast<size_t>(fps_per_lb);
    if (fp_queues.size() != expected) {
        throw std::invalid_argument("LB/FP topology must match the number of FP queues");
    }

    for (const auto& queue : fp_queues) {
        if (!queue) {
            throw std::invalid_argument("FP queue pointers must be non-null");
        }
    }
    
    // Create load balancers, each handling a subset of FPs
    for (int lb_id = 0; lb_id < num_lbs; lb_id++) {
        std::vector<std::shared_ptr<ThreadSafeQueue<PacketJob>>> lb_fp_queues;
        int fp_start = lb_id * fps_per_lb;
        
        for (int i = 0; i < fps_per_lb; i++) {
            lb_fp_queues.push_back(fp_queues[fp_start + i]);
        }
        
        lbs_.push_back(std::make_unique<LoadBalancer>(lb_id, lb_fp_queues, fp_start));
    }
    
    std::cout << "[LBManager] Created " << num_lbs << " load balancers, "
              << fps_per_lb << " FPs each\n";
}

LBManager::~LBManager() {
    stopAll();
}

void LBManager::startAll() {
    for (auto& lb : lbs_) {
        lb->start();
    }
}

void LBManager::stopAll() {
    for (auto& lb : lbs_) {
        lb->stop();
    }
}

LoadBalancer& LBManager::getLBForPacket(const FiveTuple& tuple) {
    // First level of load balancing: select LB based on hash
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    size_t total_fps = lbs_.size() * fps_per_lb_;
    size_t global_index = hash % total_fps;
    int lb_index = global_index / fps_per_lb_;
    return *lbs_[lb_index];
}

LBManager::AggregatedStats LBManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0};
    
    for (const auto& lb : lbs_) {
        auto lb_stats = lb->getStats();
        stats.total_received += lb_stats.packets_received;
        stats.total_dispatched += lb_stats.packets_dispatched;
    }
    
    return stats;
}

} // namespace DPI
