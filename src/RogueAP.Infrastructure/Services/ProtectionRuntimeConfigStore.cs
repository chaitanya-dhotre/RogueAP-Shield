using RogueAP.Core.Interfaces;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class ProtectionRuntimeConfigStore : IProtectionRuntimeConfigStore
{
    private readonly object _sync = new();
    private string _deploymentProfile;

    public ProtectionRuntimeConfigStore(ProtectionOptions options)
    {
        _deploymentProfile = Normalize(options.DeploymentProfile);
    }

    public string GetDeploymentProfile()
    {
        lock (_sync)
        {
            return _deploymentProfile;
        }
    }

    public void SetDeploymentProfile(string profile)
    {
        lock (_sync)
        {
            _deploymentProfile = Normalize(profile);
        }
    }

    private static string Normalize(string? profile)
    {
        if (string.IsNullOrWhiteSpace(profile))
        {
            return "Home";
        }

        var value = profile.Trim().ToLowerInvariant();
        return value switch
        {
            "enterprise" => "Enterprise",
            "campus" => "Campus",
            _ => "Home"
        };
    }
}
