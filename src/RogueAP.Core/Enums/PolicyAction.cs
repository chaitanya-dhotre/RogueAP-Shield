namespace RogueAP.Core.Enums;

public enum PolicyAction
{
    None = 0,
    AlertInfo = 1,
    AlertHighPriority = 2,
    AlertCritical = 3,
    AttemptVpnConnect = 4,
    BlockInternet = 5,
    UnblockInternet = 6
}