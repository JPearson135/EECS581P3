// Totp.hpp - Authenticator feature. Stores authenticator accounts and generates the time-based 6-digit codes with the seconds remaining.
#include <string>
using namespace std;

class Authenticator{
    public:
    void addAccount();
    string currentCode();
    int secondsRemaining();
    void removeAccount();
};