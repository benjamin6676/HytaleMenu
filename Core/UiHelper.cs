using ImGuiNET;
using System.Numerics;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Shared UI drawing helpers used by all tabs.
/// Call these instead of raw ImGui button/label calls to keep styling consistent.
/// </summary>
public static class UiHelper
{
    // ── Section box — the main panel container used on every tab ──────────

    public static void SectionBox(string label, float w, float h, Action content)
    {
        var dl = ImGui.GetWindowDrawList();
        var p0 = ImGui.GetCursorScreenPos();

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild($"##sb_{label}_{(int)p0.X}_{(int)p0.Y}",
            new Vector2(w, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        // Accent left border stripe
        dl.AddRectFilled(p0, p0 + new Vector2(3, h),
            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        // Label
        ImGui.SetCursorPos(new Vector2(12, 10));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted(label);
        ImGui.PopStyleColor();

        // Thin line under label
        var lp = ImGui.GetCursorScreenPos();
        dl.AddLine(new Vector2(p0.X + 12, lp.Y - 2),
                   new Vector2(p0.X + w  - 12, lp.Y - 2),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        ImGui.SetCursorPosX(12);
        ImGui.Spacing();

        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(8, 7));
        content();
        ImGui.PopStyleVar();

        ImGui.EndChild();
    }

    // ── Buttons ───────────────────────────────────────────────────────────

    /// Green — primary positive action
    public static void PrimaryButton(string label, float w, float h, Action action)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,
            new Vector4(0.18f, 0.95f, 0.45f, 0.22f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered,
            new Vector4(0.18f, 0.95f, 0.45f, 0.38f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,
            new Vector4(0.18f, 0.95f, 0.45f, 0.55f));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
        if (ImGui.Button(label, new Vector2(w, h))) action();
        ImGui.PopStyleColor(4);
    }

    /// Neutral — secondary / utility action
    public static void SecondaryButton(string label, float w, float h, Action action)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColBg3);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered,
            new Vector4(0.18f, 0.95f, 0.45f, 0.15f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,
            new Vector4(0.18f, 0.95f, 0.45f, 0.28f));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColText);
        if (ImGui.Button(label, new Vector2(w, h))) action();
        ImGui.PopStyleColor(4);
    }

    /// Red — destructive / stop action
    public static void DangerButton(string label, float w, float h, Action action)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColDangerDim);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered,
            new Vector4(0.95f, 0.28f, 0.22f, 0.30f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,
            new Vector4(0.95f, 0.28f, 0.22f, 0.50f));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
        if (ImGui.Button(label, new Vector2(w, h))) action();
        ImGui.PopStyleColor(4);
    }

    /// Amber — exploit / test action (use for anything that sends packets)
    public static void WarnButton(string label, float w, float h, Action action)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColWarnDim);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered,
            new Vector4(0.95f, 0.75f, 0.10f, 0.30f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,
            new Vector4(0.95f, 0.75f, 0.10f, 0.50f));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
        if (ImGui.Button(label, new Vector2(w, h))) action();
        ImGui.PopStyleColor(4);
    }

    /// Blue — informational action
    public static void BlueButton(string label, float w, float h, Action action)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColBlueDim);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered,
            new Vector4(0.28f, 0.72f, 1.00f, 0.30f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,
            new Vector4(0.28f, 0.72f, 1.00f, 0.50f));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
        if (ImGui.Button(label, new Vector2(w, h))) action();
        ImGui.PopStyleColor(4);
    }

    // ── Text helpers ──────────────────────────────────────────────────────

    public static void MutedLabel(string text)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(text);
        ImGui.PopStyleColor();
    }

    public static void AccentText(string text)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
        ImGui.TextUnformatted(text);
        ImGui.PopStyleColor();
    }

    public static void WarnText(string text)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
        ImGui.TextUnformatted(text);
        ImGui.PopStyleColor();
    }

    public static void DangerText(string text)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
        ImGui.TextUnformatted(text);
        ImGui.PopStyleColor();
    }

    // ── Status row — label + value side by side ───────────────────────────

    public static void StatusRow(string label, string value, bool ok, float labelW = 90)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(label);
        ImGui.PopStyleColor();
        ImGui.SameLine(labelW);
        ImGui.PushStyleColor(ImGuiCol.Text,
            ok ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(value);
        ImGui.PopStyleColor();
    }

    // ── Pill badge ────────────────────────────────────────────────────────

    public static void Pill(string text, Vector4 col, Vector4 bg)
    {
        var  dl  = ImGui.GetWindowDrawList();
        var  p   = ImGui.GetCursorScreenPos();
        float tw = ImGui.CalcTextSize(text).X;
        float ph = 20f;
        float pw = tw + 16f;

        dl.AddRectFilled(p, p + new Vector2(pw, ph),
            ImGui.ColorConvertFloat4ToU32(bg), 3f);
        dl.AddRect(p, p + new Vector2(pw, ph),
            ImGui.ColorConvertFloat4ToU32(col), 3f);

        ImGui.SetCursorScreenPos(p + new Vector2(8, 3));
        ImGui.PushStyleColor(ImGuiCol.Text, col);
        ImGui.TextUnformatted(text);
        ImGui.PopStyleColor();

        ImGui.SetCursorScreenPos(p + new Vector2(0, ph + 6));
    }
}
