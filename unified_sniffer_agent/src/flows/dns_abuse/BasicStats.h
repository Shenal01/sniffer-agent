#ifndef BASIC_STATS_H
#define BASIC_STATS_H

#include <cmath>

/**
 * Helper class to calculate basic statistics (Min, Max, Mean, StdDev, Variance)
 * Ported EXACTLY from Java's Apache Commons Math3 SummaryStatistics (Sample
 * Variance) to guarantee 100% mathematical parity with the XGBoost training
 * data.
 */
class BasicStats {
private:
  long count;
  double min_val;
  double max_val;
  double mean;
  double m2; // Sum of squared distances from the mean
  double sum;

public:
  BasicStats()
      : count(0), min_val(0.0), max_val(0.0), mean(0.0), m2(0.0), sum(0.0) {}

  void addValue(double value) {
    count++;
    sum += value;

    if (count == 1) {
      min_val = value;
      max_val = value;
      mean = value;
      m2 = 0.0;
    } else {
      if (value < min_val)
        min_val = value;
      if (value > max_val)
        max_val = value;

      // Welford's algorithm for numerically stable variance
      double delta = value - mean;
      mean += delta / count;
      double delta2 = value - mean;
      m2 += delta * delta2;
    }
  }

  double getMin() const { return (count == 0) ? 0.0 : min_val; }

  double getMax() const { return (count == 0) ? 0.0 : max_val; }

  double getMean() const { return (count == 0) ? 0.0 : mean; }

  // Matches Apache Commons Math3 SummaryStatistics getVariance() (Sample
  // Variance: N-1)
  double getVariance() const { return (count < 2) ? 0.0 : (m2 / (count - 1)); }

  // Matches Apache Commons Math3 SummaryStatistics getStandardDeviation()
  double getStdDev() const {
    return (count < 2) ? 0.0 : std::sqrt(getVariance());
  }

  double getSum() const { return sum; }

  long getCount() const { return count; }
};

#endif // BASIC_STATS_H
