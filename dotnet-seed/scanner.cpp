// Single-threaded inversion of affine low-byte observations modulo 2^31-1.
// This scans a necessary-condition superset. Callers must replay candidates
// through the exact historical constructor, and separately handle exceptions.
// Input: branch_count, then branch_id observation_count and draw a b mask value.
// A full observed byte with nonzero a is required in every branch.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr std::uint64_t M = 2147483647ULL;
using Clock = std::chrono::steady_clock;

std::uint64_t reduce(std::uint64_t value) {
    value = (value & M) + (value >> 31);
    value = (value & M) + (value >> 31);
    return value >= M ? value - M : value;
}

std::uint64_t inverse(std::uint64_t value) {
    std::uint64_t result = 1;
    for (std::uint64_t exponent = M - 2; exponent; exponent >>= 1) {
        if (exponent & 1) result = reduce(result * value);
        value = reduce(value * value);
    }
    return result;
}

struct Observation {
    std::uint64_t draw, a, b, mask, value;
};
struct Branch {
    std::uint64_t id;
    std::vector<Observation> observations;
};
struct Result {
    std::uint64_t id = 0, anchor_draw = 0, anchor_values = 0, tested = 0;
    std::uint64_t evaluations = 0;
    bool complete = true;
    std::string status = "complete", reason;
    double seconds = 0;
    std::vector<std::uint64_t> candidates, filter_draws, filter_passes;
};

std::uint64_t field(const char* name, std::uint64_t maximum) {
    std::int64_t value;
    if (!(std::cin >> value) || value < 0 || static_cast<std::uint64_t>(value) > maximum)
        throw std::runtime_error(std::string("Invalid or missing ") + name);
    return static_cast<std::uint64_t>(value);
}

std::vector<Branch> read_input() {
    const auto count = field("branch_count", 64);
    if (!count) throw std::runtime_error("branch_count must be positive");
    std::set<std::uint64_t> ids;
    std::vector<Branch> branches;
    for (std::uint64_t i = 0; i < count; ++i) {
        Branch branch;
        branch.id = field("branch_id", 1000000000);
        if (!ids.insert(branch.id).second) throw std::runtime_error("Duplicate branch_id");
        const auto n = field("observation_count", 100000);
        if (!n) throw std::runtime_error("observation_count must be positive");
        std::set<std::uint64_t> draws;
        bool has_anchor = false;
        for (std::uint64_t j = 0; j < n; ++j) {
            Observation row;
            row.draw = field("draw", 1000000000);
            row.a = field("a", M - 1);
            row.b = field("b", M - 1);
            row.mask = field("mask", 255);
            row.value = field("value", 255);
            if (!row.mask || (row.value & ~row.mask))
                throw std::runtime_error("Invalid observation mask/value");
            if (!draws.insert(row.draw).second) throw std::runtime_error("Duplicate observation draw");
            has_anchor |= row.mask == 255 && row.a != 0;
            branch.observations.push_back(row);
        }
        if (!has_anchor) throw std::runtime_error("No invertible full-byte anchor");
        branches.push_back(std::move(branch));
    }
    std::string trailing;
    if (std::cin >> trailing) throw std::runtime_error("Unexpected trailing input");
    return branches;
}

unsigned bits(std::uint64_t value) {
    unsigned result = 0;
    for (; value; value &= value - 1) ++result;
    return result;
}

Result scan(const Branch& branch, std::size_t candidate_limit) {
    const auto started = Clock::now();
    Result result;
    result.id = branch.id;
    auto ordered = branch.observations;
    std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
        if (bits(left.mask) != bits(right.mask)) return bits(left.mask) > bits(right.mask);
        return left.draw < right.draw;
    });
    const auto anchor_it = std::find_if(ordered.begin(), ordered.end(), [](const auto& row) {
        return row.mask == 255 && row.a != 0;
    });
    const Observation anchor = *anchor_it;
    ordered.erase(anchor_it);
    result.anchor_draw = anchor.draw;
    result.anchor_values = (M - 1 - anchor.value) / 256 + 1;
    for (const auto& row : ordered) result.filter_draws.push_back(row.draw);
    result.filter_passes.resize(ordered.size(), 0);
    for (const auto& row : ordered) {
        if (row.a == 0 && (row.b & row.mask) != row.value) {
            result.reason = "constant_observation_contradiction";
            result.seconds = std::chrono::duration<double>(Clock::now() - started).count();
            return result;
        }
    }
    const auto inv = inverse(anchor.a);
    auto seed = reduce(inv * ((anchor.value + M - anchor.b) % M));
    const auto step = reduce(inv * 256);
    for (std::uint64_t k = 0; k < result.anchor_values; ++k) {
        ++result.tested;
        bool accepted = true;
        for (std::size_t j = 0; j < ordered.size(); ++j) {
            const auto& row = ordered[j];
            ++result.evaluations;
            if ((reduce(row.a * seed + row.b) & row.mask) != row.value) {
                accepted = false;
                break;
            }
            ++result.filter_passes[j];
        }
        if (accepted) {
            // Both endpoints represent residue zero, but are distinct allowed
            // constructor seed magnitudes. Preserve both for exact replay.
            const std::size_t needed = seed == 0 ? 2 : 1;
            if (result.candidates.size() + needed > candidate_limit) {
                result.complete = false;
                result.status = "candidate_limit";
                break;
            }
            result.candidates.push_back(seed);
            if (seed == 0) result.candidates.push_back(M);
        }
        seed += step;
        if (seed >= M) seed -= M;
    }
    std::sort(result.candidates.begin(), result.candidates.end());
    result.seconds = std::chrono::duration<double>(Clock::now() - started).count();
    return result;
}

void array(const std::vector<std::uint64_t>& values) {
    std::cout << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) std::cout << ',';
        std::cout << values[i];
    }
    std::cout << ']';
}

void write_result(const std::vector<Result>& results) {
    bool complete = true;
    std::set<std::uint64_t> union_candidates;
    std::uint64_t tested = 0;
    for (const auto& result : results) {
        complete &= result.complete;
        tested += result.tested;
        union_candidates.insert(result.candidates.begin(), result.candidates.end());
    }
    std::cout.precision(12);
    std::cout << "{\"modulus\":" << M << ",\"complete\":" << (complete ? "true" : "false")
              << ",\"status\":\"" << (complete ? "complete" : "candidate_limit")
              << "\",\"tested_anchor_values\":" << tested << ",\"candidate_seeds\":";
    array(std::vector<std::uint64_t>(union_candidates.begin(), union_candidates.end()));
    std::cout << ",\"branches\":[";
    for (std::size_t i = 0; i < results.size(); ++i) {
        if (i) std::cout << ',';
        const auto& row = results[i];
        std::cout << "{\"branch_id\":" << row.id << ",\"complete\":" << (row.complete ? "true" : "false")
                  << ",\"status\":\"" << row.status << "\",\"reason\":\"" << row.reason
                  << "\",\"anchor_draw\":" << row.anchor_draw << ",\"anchor_values\":" << row.anchor_values
                  << ",\"tested_anchor_values\":" << row.tested << ",\"filter_evaluations\":" << row.evaluations
                  << ",\"seconds\":" << row.seconds << ",\"candidate_seeds\":";
        array(row.candidates);
        std::cout << ",\"filter_draws\":";
        array(row.filter_draws);
        std::cout << ",\"passed_filter_counts\":";
        array(row.filter_passes);
        std::cout << '}';
    }
    std::cout << "]}\n";
}
}  // namespace

int main(int argc, char** argv) {
    try {
        std::size_t candidate_limit = 10000;
        if (argc != 1) {
            if (argc != 3 || std::string(argv[1]) != "--max-candidates")
                throw std::runtime_error("Usage: scanner [--max-candidates 1..1000000]");
            const std::string argument(argv[2]);
            if (argument.empty() || argument.find_first_not_of("0123456789") != std::string::npos)
                throw std::runtime_error("Invalid candidate limit");
            const auto value = std::stoull(argument);
            if (value == 0 || value > 1000000) throw std::runtime_error("Invalid candidate limit");
            candidate_limit = static_cast<std::size_t>(value);
        }
        const auto branches = read_input();
        std::vector<Result> results;
        for (const auto& branch : branches) results.push_back(scan(branch, candidate_limit));
        write_result(results);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "scanner: " << error.what() << '\n';
        return 2;
    }
}
