#pragma once

#include <cmath>
#include <algorithm>

namespace flows {

class RunningStats {
public:
    RunningStats() : count_(0), mean_(0.0), m2_(0.0), min_(0.0), max_(0.0) {}

    void push(double x) {
        if (count_ == 0) {
            min_ = max_ = x;
        } else {
            min_ = std::min(min_, x);
            max_ = std::max(max_, x);
        }

        count_++;
        double delta = x - mean_;
        mean_ += delta / count_;
        double delta2 = x - mean_;
        m2_ += delta * delta2;
    }

    uint64_t count() const { return count_; }
    double mean() const { return mean_; }
    double variance() const { return (count_ > 1) ? m2_ / count_ : 0.0; }
    double stddev() const { return std::sqrt(variance()); }
    double min() const { return min_; }
    double max() const { return max_; }

private:
    uint64_t count_;
    double mean_;
    double m2_;
    double min_;
    double max_;
};

} // namespace flows
