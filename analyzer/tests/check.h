// Minimal test harness: CHECK / CHECK_EQ record failures; main returns non-zero if any failed.
#pragma once
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace check {

inline int& Failures() { static int f = 0; return f; }
inline std::vector<std::pair<char const*, std::function<void()>>>& Tests() { static std::vector<std::pair<char const*, std::function<void()>>> t; return t; }

struct Register { Register(char const* n, std::function<void()> f) { Tests().emplace_back(n, std::move(f)); } };

inline int RunAll()
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    for (auto& [name, fn] : Tests()) {
        int const before = Failures();
        fn();
        std::printf("%s %s\n", Failures() == before ? "ok  " : "FAIL", name);
    }
    std::printf("%d failure(s)\n", Failures());
    return Failures() ? 1 : 0;
}

} // namespace check

#define TEST(name) static void name(); static check::Register reg_##name(#name, name); static void name()
#define CHECK(cond) do { if (!(cond)) { ++check::Failures(); std::printf("  %s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_EQ(a, b) do { auto const _a = (a); auto const _b = (b); if (!(_a == _b)) { ++check::Failures(); \
    std::printf("  %s:%d: CHECK_EQ(%s, %s): %llu vs %llu\n", __FILE__, __LINE__, #a, #b, (unsigned long long)_a, (unsigned long long)_b); } } while (0)
#define TEST_MAIN int main() { return check::RunAll(); }
