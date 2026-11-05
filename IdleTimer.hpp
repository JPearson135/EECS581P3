#pragma once

#include <ctime>

class IdleTimer {
public:
    explicit IdleTimer(int limitSeconds = 0, std::time_t now = std::time(nullptr));

    void touch(std::time_t now);
    bool expired(std::time_t now) const;

private:
    std::time_t lastActivity_;
    int limitSeconds_;
};
