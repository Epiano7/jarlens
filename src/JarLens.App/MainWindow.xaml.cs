using JarLens.Scanner;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace JarLens.App;

public partial class MainWindow : Window
{
    private readonly JarScanner scanner = new();

    public MainWindow()
    {
        InitializeComponent();
    }

    private void OpenJar_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Java archives (*.jar)|*.jar|All files (*.*)|*.*",
            Title = "Open jar"
        };

        if (dialog.ShowDialog(this) == true)
        {
            Scan(dialog.FileName);
        }
    }

    private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ReportText.Text = "Checking GitHub Releases. No jars are uploaded.";
            var update = await UpdateChecker.CheckLatestReleaseAsync();
            if (update.IsUpdateAvailable && update.ReleaseUrl is not null)
            {
                var answer = MessageBox.Show(this, update.Message + Environment.NewLine + Environment.NewLine + "Open the GitHub release page?", "Update available", MessageBoxButton.YesNo, MessageBoxImage.Information);
                if (answer == MessageBoxResult.Yes)
                {
                    UpdateChecker.OpenReleasePage(update.ReleaseUrl);
                }
            }
            else
            {
                MessageBox.Show(this, update.Message, "JarLens updates", MessageBoxButton.OK, MessageBoxImage.Information);
            }

            ReportText.Text = update.Message;
        }
        catch (Exception ex)
        {
            ReportText.Text = "Update check failed. JarLens only checks GitHub when you click Check updates." + Environment.NewLine + ex.Message;
            MessageBox.Show(this, "Update check failed. This does not affect local jar scanning.", "JarLens updates", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
        {
            Scan(files[0]);
        }
    }

    private void FindingsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FindingsList.SelectedItem is Finding finding)
        {
            ReportText.Text = FormatFinding(finding);
        }
    }

    private void Scan(string path)
    {
        try
        {
            var result = scanner.Scan(path);
            SelectedFileText.Text = result.FilePath;
            RiskText.Text = result.Risk.Level;
            RiskScoreText.Text = $"Score: {result.Risk.Score}";
            RiskText.Foreground = RiskBrush(result.Risk.Level);
            FindingsList.ItemsSource = result.Findings;
            ReportText.Text = FormatReport(result);
        }
        catch (Exception ex)
        {
            RiskText.Text = "Error";
            RiskScoreText.Text = "Score: -";
            FindingsList.ItemsSource = null;
            ReportText.Text = ex.Message;
        }
    }

    private static Brush RiskBrush(string level) => level switch
    {
        "High" => Brushes.Firebrick,
        "Medium" => Brushes.DarkOrange,
        "Low" => Brushes.DarkGoldenrod,
        _ => Brushes.SeaGreen
    };

    private static string FormatReport(ScanResult result)
    {
        var lines = new List<string>
        {
            $"JarLens report for {result.FileName}",
            $"Risk: {result.Risk.Level} ({result.Risk.Score})",
            result.Risk.Verdict,
            "",
            $"SHA256: {result.Sha256}",
            $"Size: {result.SizeBytes:N0} bytes",
            $"Entries: {result.EntryCount}",
            $"Classes: {result.ClassCount}",
            $"Nested jars: {result.NestedJarCount}",
            ""
        };

        if (result.Metadata.Count > 0)
        {
            lines.Add("Metadata");
            lines.Add("--------");
            lines.AddRange(result.Metadata);
            lines.Add("");
        }

        if (result.Findings.Count == 0)
        {
            lines.Add("No findings.");
            return string.Join(Environment.NewLine, lines);
        }

        lines.Add("Findings");
        lines.Add("--------");
        foreach (var finding in result.Findings)
        {
            lines.Add(FormatFinding(finding));
            lines.Add("");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatFinding(Finding finding)
    {
        var lines = new List<string>
        {
            $"[{finding.Severity}] {finding.Label}",
            $"Category: {finding.Category}",
            finding.Explanation,
            "",
            "Evidence:"
        };

        lines.AddRange(finding.Evidence.Select(e => $"- {e.Source}: {e.Match}"));
        return string.Join(Environment.NewLine, lines);
    }
}
