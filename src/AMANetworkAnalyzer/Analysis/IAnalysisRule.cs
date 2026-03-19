namespace AMANetworkAnalyzer.Analysis;

using AMANetworkAnalyzer.Models;

/// <summary>Interface for all diagnostic rules.</summary>
public interface IAnalysisRule
{
    string Name { get; }
    string Category { get; }
    List<AnalysisFinding> Analyze(List<ParsedPacket> packets);
}
