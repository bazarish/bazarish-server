// Bazarish project (c) 2026
#pragma once

namespace bazarish::fleet {

inline constexpr char kMessagingAccount[] = "/v1/messaging/account";
inline constexpr char kMessagingCard[] = "/v1/messaging/card";
inline constexpr char kMessagingI2pDest[] = "/v1/messaging/i2p-dest";
inline constexpr char kMessagingLogs[] = "/v1/messaging/logs";
inline constexpr char kMessagingNodeCard[] = "/v1/messaging/node-card";
inline constexpr char kMessagingQuota[] = "/v1/messaging/quota";
inline constexpr char kMessagingRestart[] = "/v1/messaging/restart";
inline constexpr char kMessagingSettings[] = "/v1/messaging/settings";
inline constexpr char kMessagingStorage[] = "/v1/messaging/storage";

inline constexpr char kAccountApprove[] = "/v1/account/approve";
inline constexpr char kAccountBan[] = "/v1/account/ban";
inline constexpr char kAccountCard[] = "/v1/account/card";
inline constexpr char kAccountLogs[] = "/v1/account/logs";
inline constexpr char kAccountQuota[] = "/v1/account/quota";
inline constexpr char kAccountRestart[] = "/v1/account/restart";
inline constexpr char kAccountSettings[] = "/v1/account/settings";
inline constexpr char kAccountUnban[] = "/v1/account/unban";
inline constexpr char kAccountUndelegate[] = "/v1/account/undelegate";

inline constexpr char kLoginClaim[] = "/v1/login/claim";
inline constexpr char kLoginExpect[] = "/v1/login/expect";

// The facade's and the gateway's operator face.
inline constexpr char kOpsLogs[] = "/logs";
inline constexpr char kOpsRestart[] = "/restart";
inline constexpr char kOpsSettings[] = "/settings";

}  // namespace bazarish::fleet
