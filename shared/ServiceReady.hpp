// Bazarish project (c) 2026
#pragma once

namespace bazarish {

// sd_notify(3) READY=1 to $NOTIFY_SOCKET; a process started without one tells nobody.
void announceReady();

}  // namespace bazarish
