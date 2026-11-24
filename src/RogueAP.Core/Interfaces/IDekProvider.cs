namespace RogueAP.Core.Interfaces;

public interface IDekProvider
{
    bool HasInMemoryDek { get; }

    byte[]? GetInMemoryDekIfExists();

    byte[] GetDek();
}

