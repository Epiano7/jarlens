using JarLens.Scanner;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace JarLens.App;

public partial class MainWindow : Window
{
    private readonly JarScanner scanner = new();
    private ThemePalette palette = ThemePalette.Light;

    public MainWindow()
    {
        InitializeComponent();
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        ApplyTheme(ThemePalette.FromSystem());
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
                var answer = MessageBox.Show(this,
                    update.Message + Environment.NewLine + Environment.NewLine +
                    "JarLens will download the release zip from GitHub, verify its SHA-256 checksum, close, replace the portable files, and restart.",
                    "Update available",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);
                if (answer == MessageBoxResult.Yes)
                {
                    var progress = new Progress<string>(message => ReportText.Text = message);
                    var preparedUpdate = await UpdateChecker.DownloadAndPrepareUpdateAsync(update, progress);
                    ReportText.Text = "Starting updater. JarLens will close and restart.";
                    UpdateChecker.StartUpdaterAndExit(preparedUpdate);
                    Close();
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
            DetailTitleText.Text = finding.Label;
            DetailSubtitleText.Text = $"{finding.Severity} severity, {ScoreContribution(finding.Severity)} points, {finding.Evidence.Count} evidence item(s).";
        }
        else if (FindingsList.SelectedItem is FindingView findingView)
        {
            ReportText.Text = FormatFinding(findingView.Finding);
            DetailTitleText.Text = findingView.Label;
            DetailSubtitleText.Text = $"{findingView.Severity} severity, {findingView.Points} points, {findingView.EvidenceCount} evidence item(s).";
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
            RiskMeter.Value = Math.Clamp(result.Risk.Score, 0, 100);
            RiskMeter.Foreground = RiskBrush(result.Risk.Level);
            FindingsList.ItemsSource = result.Findings.Select(FindingView.FromFinding).ToList();
            ReportText.Text = FormatReport(result);
            DetailTitleText.Text = "Report";
            DetailSubtitleText.Text = result.Risk.Verdict;
        }
        catch (Exception ex)
        {
            RiskText.Text = "Error";
            RiskScoreText.Text = "Score: -";
            RiskMeter.Value = 0;
            FindingsList.ItemsSource = null;
            ReportText.Text = ex.Message;
            DetailTitleText.Text = "Scan error";
            DetailSubtitleText.Text = "The jar could not be inspected.";
        }
    }

    private Brush RiskBrush(string level) => level switch
    {
        "High" => palette.HighRisk,
        "Medium" => palette.MediumRisk,
        "Low" => palette.LowRisk,
        _ => palette.SafeRisk
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
            $"Embedded executables/scripts: {result.EmbeddedExecutableCount}",
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
            $"Score contribution: {ScoreContribution(finding.Severity)}",
            finding.Explanation,
            "",
            "Evidence:"
        };

        lines.AddRange(finding.Evidence.Select(e => $"- {e.Source}: {e.Match}"));
        return string.Join(Environment.NewLine, lines);
    }

    private void ApplyTheme(ThemePalette selectedPalette)
    {
        palette = selectedPalette;
        Background = palette.WindowBackground;
        Root.Background = palette.WindowBackground;

        foreach (var textBlock in FindVisualChildren<TextBlock>(this))
        {
            textBlock.Foreground = palette.PrimaryText;
        }

        foreach (var textBox in FindVisualChildren<TextBox>(this))
        {
            textBox.Background = palette.CardBackground;
            textBox.Foreground = palette.PrimaryText;
            textBox.CaretBrush = palette.PrimaryText;
        }

        foreach (var listBox in FindVisualChildren<ListBox>(this))
        {
            listBox.Background = palette.CardBackground;
            listBox.Foreground = palette.PrimaryText;
        }

        foreach (var button in FindVisualChildren<Button>(this))
        {
            button.Background = palette.ButtonBackground;
            button.Foreground = palette.PrimaryText;
            button.BorderBrush = palette.Border;
        }

        foreach (var border in new[] { DropCard, FindingsCard, ReportCard })
        {
            border.Background = palette.CardBackground;
            border.BorderBrush = palette.Border;
        }

        RiskCard.Background = palette.RiskCardBackground;
        RiskCard.BorderBrush = palette.Border;
        SubtitleText.Foreground = palette.SecondaryText;
        TrustText.Foreground = palette.SecondaryText;
        SelectedFileText.Foreground = palette.SecondaryText;
        RiskLabelText.Foreground = palette.SecondaryText;
        RiskScoreText.Foreground = palette.SecondaryText;
        LowThresholdText.Foreground = palette.SecondaryText;
        MediumThresholdText.Foreground = palette.SecondaryText;
        HighThresholdText.Foreground = palette.SecondaryText;
        DetailSubtitleText.Foreground = palette.SecondaryText;
        RiskText.Foreground = RiskBrush(RiskText.Text);
        RiskMeter.Foreground = RiskBrush(RiskText.Text);
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject dependencyObject) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(dependencyObject); i++)
        {
            var child = VisualTreeHelper.GetChild(dependencyObject, i);
            if (child is T typedChild)
            {
                yield return typedChild;
            }

            foreach (var descendant in FindVisualChildren<T>(child))
            {
                yield return descendant;
            }
        }
    }

    private static int ScoreContribution(Severity severity) => severity switch
    {
        Severity.Critical => 60,
        Severity.High => 35,
        Severity.Medium => 15,
        Severity.Low => 5,
        _ => 0
    };

    private sealed record FindingView(Finding Finding, string Label, Severity Severity, string Category, int Points, int EvidenceCount)
    {
        public string Summary => $"{Points} points - {EvidenceCount} evidence item(s)";

        public static FindingView FromFinding(Finding finding) =>
            new(finding, finding.Label, finding.Severity, finding.Category, ScoreContribution(finding.Severity), finding.Evidence.Count);
    }

    private sealed record ThemePalette(
        Brush WindowBackground,
        Brush CardBackground,
        Brush RiskCardBackground,
        Brush ButtonBackground,
        Brush Border,
        Brush PrimaryText,
        Brush SecondaryText,
        Brush SafeRisk,
        Brush LowRisk,
        Brush MediumRisk,
        Brush HighRisk)
    {
        public static readonly ThemePalette Light = new(
            new SolidColorBrush(Color.FromRgb(246, 247, 249)),
            Brushes.White,
            new SolidColorBrush(Color.FromRgb(240, 243, 247)),
            new SolidColorBrush(Color.FromRgb(250, 251, 253)),
            new SolidColorBrush(Color.FromRgb(216, 222, 232)),
            new SolidColorBrush(Color.FromRgb(21, 24, 29)),
            new SolidColorBrush(Color.FromRgb(86, 96, 112)),
            Brushes.SeaGreen,
            Brushes.DarkGoldenrod,
            Brushes.DarkOrange,
            Brushes.Firebrick);

        public static readonly ThemePalette Dark = new(
            new SolidColorBrush(Color.FromRgb(18, 20, 24)),
            new SolidColorBrush(Color.FromRgb(27, 31, 37)),
            new SolidColorBrush(Color.FromRgb(34, 39, 47)),
            new SolidColorBrush(Color.FromRgb(41, 47, 56)),
            new SolidColorBrush(Color.FromRgb(67, 76, 91)),
            new SolidColorBrush(Color.FromRgb(235, 239, 245)),
            new SolidColorBrush(Color.FromRgb(168, 177, 190)),
            new SolidColorBrush(Color.FromRgb(78, 201, 138)),
            new SolidColorBrush(Color.FromRgb(222, 183, 80)),
            new SolidColorBrush(Color.FromRgb(235, 151, 69)),
            new SolidColorBrush(Color.FromRgb(238, 94, 94)));

        public static ThemePalette FromSystem()
        {
            const string keyPath = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
            var value = Registry.CurrentUser.OpenSubKey(keyPath)?.GetValue("AppsUseLightTheme");
            return value is int intValue && intValue == 0 ? Dark : Light;
        }
    }
}
