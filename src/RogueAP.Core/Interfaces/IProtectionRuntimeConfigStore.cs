namespace RogueAP.Core.Interfaces;

public interface IProtectionRuntimeConfigStore
{
    string GetDeploymentProfile();

    void SetDeploymentProfile(string profile);
}
