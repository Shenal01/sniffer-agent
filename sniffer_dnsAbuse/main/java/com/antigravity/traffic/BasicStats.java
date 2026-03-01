package com.antigravity.traffic;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

/**
 * Helper class to calculate basic statistics (Min, Max, Mean, StdDev)
 * for a stream of values (e.g., Packet Lengths, IATs).
 */
public class BasicStats {
    private SummaryStatistics stats = new SummaryStatistics();

    public void addValue(double value) {
        stats.addValue(value);
    }

    public double getMin() {
        return stats.getN() == 0 ? 0 : stats.getMin();
    }

    public double getMax() {
        return stats.getN() == 0 ? 0 : stats.getMax();
    }

    public double getMean() {
        return stats.getN() == 0 ? 0 : stats.getMean();
    }

    public double getStdDev() {
        return stats.getN() == 0 ? 0 : stats.getStandardDeviation();
    }

    public double getVariance() {
        return stats.getN() == 0 ? 0 : stats.getVariance();
    }

    public double getSum() {
        return stats.getSum();
    }

    public long getCount() {
        return stats.getN();
    }
}
