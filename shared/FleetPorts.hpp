// Bazarish project (c) 2026
#pragma once

// Where each service of a fleet listens unless its configuration says otherwise.
namespace bazarish::fleet {

inline constexpr const char* kLoopback = "127.0.0.1";

inline constexpr int kFacadeDirectPort = 8418;
inline constexpr int kFacadePort = 8419;
inline constexpr int kCorePort = 8420;
inline constexpr int kNodePort = 8421;
inline constexpr int kCoreGatewayPort = 8424;
inline constexpr int kNodeOpsPort = 8427;
inline constexpr int kCoreOpsPort = 8428;
inline constexpr int kFacadeOpsPort = 8429;
inline constexpr int kGatewayOpsPort = 8439;
inline constexpr int kPanelPort = 8460;

}  // namespace bazarish::fleet
