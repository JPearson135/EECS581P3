#include "IdleTimer.hpp"

IdleTimer::IdleTimer(int limitSeconds, std::time_t now)
    : lastActivity_(now), limitSeconds_(limitSeconds) {}

void IdleTimer::touch(std::time_t now) {
    lastActivity_ = now;
}

bool IdleTimer::expired(std::time_t now) const {
    return limitSeconds_ > 0 && now - lastActivity_ >= limitSeconds_;
}