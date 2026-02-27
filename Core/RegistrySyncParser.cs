using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Parses the Asset/Registry sync packets Hytale sends immediately after login.
///
/// CONFIRMED FROM PROTOCOL MAP (screenshots):
///   - Opcodes 0x28–0x3F and 0x43–0x55 (decimal 40–85 minus 0x30/0x31/0x40-0x42)
///     appear ONCE at login with no repeat hits = true registry packets.
///   - Opcodes 0x40/0x41/0x42 appear 160+ times = high-frequency entity updates,
///     NOT registry. These are renamed in OpcodeRegistry.
///
/// PREVIOUS ZSTD GATE BUG:
///   Previous code required 0x28 0xB5 0x2F 0xFD magic to process.
///   But none of the captured registry packets start with this magic,
///   so ALL real registry packets were silently dropped.
///
/// THIS VERSION:
///   1. Processes ALL opcode-40-85 packets regardless of header magic.
///   2. Tries 4 different binary parse strategies per packet.
///   3. DUMPS raw bytes to disk → %AppData%\HytaleMenu\registry_dump\
///      Load the dumps in a hex editor or share with community to crack format.
///   4. Uses quality filtering instead of magic gating to reject garbage.
///   5. Renames high-frequency "entity" packets (0x40-0x42) properly.
/// </summary>
public static class RegistrySyncParser
{
    // ── Registry opcode range (decimal 40–85, community-confirmed login range) ─
    public const int RegistryOpcodeMin = 0;
    public const int RegistryOpcodeMax = 450;

    // ── Dump folder ───────────────────────────────────────────────────────────
    private static readonly string DumpDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "HytaleMenu", "registry_dump");
    private static bool _dumpDirCreated = false;
    private static int  _dumpCount      = 0;
    private const  int  MaxDumps        = 50;   // cap so we don't fill disk

    // ── High-frequency opcodes that are NOT registry (entity updates) ─────────
    // These fall inside 40-85 decimal range but appear 100+ times → not login-only
    private static readonly HashSet<byte> EntityUpdateOpcodes = new() { 0x40, 0x41, 0x42 };

    // ── Real Hytale item IDs (hytaleguide.net, confirmed Jan 2026 release) ─────────────
    // Format: string ID -> display name.  These match /give command IDs exactly.
    // Pattern: Category_Subcategory_Material (e.g. Weapon_Sword_Iron, Tool_Pickaxe_Cobalt)
    public static readonly IReadOnlyDictionary<string, string> BuiltInNames =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // ── WEAPONS: Swords ──
            ["Weapon_Sword_Iron"]             = "Iron Sword",
            ["Weapon_Sword_Copper"]           = "Copper Sword",
            ["Weapon_Sword_Bronze"]           = "Bronze Sword",
            ["Weapon_Sword_Cobalt"]           = "Cobalt Sword",
            ["Weapon_Sword_Adamantite"]       = "Adamantite Sword",
            ["Weapon_Sword_Steel"]            = "Steel Sword",
            ["Weapon_Longsword_Iron"]         = "Iron Longsword",
            ["Weapon_Longsword_Cobalt"]       = "Cobalt Longsword",
            ["Weapon_Longsword_Adamantite"]   = "Adamantite Longsword",
            ["Weapon_Sword_Bronze_Ancient"]   = "Ancient Bronze Sword",
            ["Weapon_Longsword_Adamantite_Saurian"] = "Adamantite Saurian Saber",
            // ── WEAPONS: Axes ──
            ["Weapon_Axe_Iron"]               = "Iron Axe",
            ["Weapon_Axe_Copper"]             = "Copper Axe",
            ["Weapon_Axe_Cobalt"]             = "Cobalt Axe",
            ["Weapon_Axe_Adamantite"]         = "Adamantite Axe",
            ["Weapon_Battleaxe_Iron"]         = "Iron Battleaxe",
            ["Weapon_Battleaxe_Cobalt"]       = "Cobalt Battleaxe",
            ["Weapon_Battleaxe_Adamantite"]   = "Adamantite Battleaxe",
            // ── WEAPONS: Maces & Clubs ──
            ["Weapon_Mace_Iron"]              = "Iron Mace",
            ["Weapon_Mace_Copper"]            = "Copper Mace",
            ["Weapon_Mace_Cobalt"]            = "Cobalt Mace",
            ["Weapon_Mace_Adamantite"]        = "Adamantite Mace",
            ["Weapon_Club_Iron"]              = "Iron Club",
            ["Weapon_Club_Copper"]            = "Copper Club",
            ["Weapon_Club_Adamantite"]        = "Adamantite Club",
            // ── WEAPONS: Daggers ──
            ["Weapon_Daggers_Iron"]           = "Iron Daggers",
            ["Weapon_Daggers_Copper"]         = "Copper Daggers",
            ["Weapon_Daggers_Cobalt"]         = "Cobalt Daggers",
            ["Weapon_Daggers_Adamantite"]     = "Adamantite Daggers",
            ["Weapon_Daggers_Bronze_Ancient"] = "Ancient Bronze Daggers",
            ["Weapon_Daggers_Adamantite_Saurian"] = "Adamantite Saurian Daggers",
            // ── WEAPONS: Spears ──
            ["Weapon_Spear_Iron"]             = "Iron Spear",
            ["Weapon_Spear_Cobalt"]           = "Cobalt Spear",
            ["Weapon_Spear_Adamantite"]       = "Adamantite Spear",
            ["Weapon_Spear_Adamantite_Saurian"] = "Adamantite Saurian Spear",
            // ── WEAPONS: Ranged ──
            ["Weapon_Shortbow_Iron"]          = "Iron Shortbow",
            ["Weapon_Shortbow_Cobalt"]        = "Cobalt Shortbow",
            ["Weapon_Shortbow_Adamantite"]    = "Adamantite Shortbow",
            ["Weapon_Crossbow_Iron"]          = "Iron Crossbow",
            ["Weapon_Crossbow_Ancient_Steel"] = "Ancient Steel Hand Crossbow",
            // ── WEAPONS: Shields & Staves ──
            ["Weapon_Shield_Iron"]            = "Iron Shield",
            ["Weapon_Shield_Copper"]          = "Copper Shield",
            ["Weapon_Shield_Cobalt"]          = "Cobalt Shield",
            ["Weapon_Shield_Adamantite"]      = "Adamantite Shield",
            ["Weapon_Shield_Orbis_Knight"]    = "Ancient Knight's Shield",
            ["Weapon_Shield_Orbis_Incandescent"] = "Ancient Knight's Incandescent Shield",
            ["Weapon_Staff_Iron"]             = "Iron Staff",
            ["Weapon_Staff_Cobalt"]           = "Cobalt Staff",
            ["Weapon_Staff_Adamantite"]       = "Adamantite Staff",
            // ── TOOLS ──
            ["Tool_Pickaxe_Iron"]             = "Iron Pickaxe",
            ["Tool_Pickaxe_Copper"]           = "Copper Pickaxe",
            ["Tool_Pickaxe_Cobalt"]           = "Cobalt Pickaxe",
            ["Tool_Pickaxe_Adamantite"]       = "Adamantite Pickaxe",
            ["Tool_Hatchet_Iron"]             = "Iron Hatchet",
            ["Tool_Hatchet_Copper"]           = "Copper Hatchet",
            ["Tool_Hatchet_Cobalt"]           = "Cobalt Hatchet",
            ["Tool_Hatchet_Adamantite"]       = "Adamantite Hatchet",
            ["Tool_Shovel_Iron"]              = "Iron Shovel",
            ["Tool_Shovel_Copper"]            = "Copper Shovel",
            ["Tool_Shovel_Cobalt"]            = "Cobalt Shovel",
            // ── ARMOR ──
            ["Armor_Iron_Head"]               = "Iron Helm",
            ["Armor_Iron_Chest"]              = "Iron Cuirass",
            ["Armor_Iron_Legs"]               = "Iron Greaves",
            ["Armor_Iron_Hands"]              = "Iron Gauntlets",
            ["Armor_Copper_Head"]             = "Copper Helm",
            ["Armor_Copper_Chest"]            = "Copper Cuirass",
            ["Armor_Copper_Legs"]             = "Copper Greaves",
            ["Armor_Copper_Hands"]            = "Copper Gauntlets",
            ["Armor_Cobalt_Head"]             = "Cobalt Helm",
            ["Armor_Cobalt_Chest"]            = "Cobalt Cuirass",
            ["Armor_Cobalt_Legs"]             = "Cobalt Greaves",
            ["Armor_Cobalt_Hands"]            = "Cobalt Gauntlets",
            ["Armor_Adamantite_Head"]         = "Adamantite Helm",
            ["Armor_Adamantite_Chest"]        = "Adamantite Cuirass",
            ["Armor_Adamantite_Legs"]         = "Adamantite Greaves",
            ["Armor_Adamantite_Hands"]        = "Adamantite Gauntlets",
            ["Armor_Steel_Ancient_Head"]      = "Ancient Steel Helm",
            ["Armor_Steel_Ancient_Chest"]     = "Ancient Steel Cuirass",
            ["Armor_Steel_Ancient_Legs"]      = "Ancient Steel Greaves",
            ["Armor_Steel_Ancient_Hands"]     = "Ancient Steel Gauntlets",
            // ── ORES & RAW MATERIALS ──
            ["Ore_Iron"]                      = "Iron Ore",
            ["Ore_Copper"]                    = "Copper Ore",
            ["Ore_Cobalt"]                    = "Cobalt Ore",
            ["Ore_Adamantite"]                = "Adamantite Ore",
            ["Ore_Adamantite_Basalt"]         = "Adamantite Ore (Basalt)",
            ["Ore_Adamantite_Magma"]          = "Adamantite Ore (Magma)",
            ["Ore_Adamantite_Shale"]          = "Adamantite Ore (Shale)",
            ["Ore_Adamantite_Slate"]          = "Adamantite Ore (Slate)",
            ["Ore_Adamantite_Stone"]          = "Adamantite Ore (Stone)",
            ["Ore_Adamantite_Volcanic"]       = "Adamantite Ore (Volcanic)",
            ["Ore_Gold"]                      = "Gold Ore",
            ["Ore_Ruby"]                      = "Ruby Ore",
            ["Ore_Emerald"]                   = "Emerald Ore",
            ["Ore_Sapphire"]                  = "Sapphire Ore",
            ["Ore_Coal"]                      = "Coal",
            // ── INGREDIENTS / CRAFTING ──
            ["Ingredient_Bar_Iron"]           = "Iron Ingot",
            ["Ingredient_Bar_Copper"]         = "Copper Ingot",
            ["Ingredient_Bar_Bronze"]         = "Bronze Ingot",
            ["Ingredient_Bar_Cobalt"]         = "Cobalt Ingot",
            ["Ingredient_Bar_Adamantite"]     = "Adamantite Ingot",
            ["Ingredient_Bar_Gold"]           = "Gold Ingot",
            ["Ingredient_Bar_Steel"]          = "Steel Ingot",
            ["Ingredient_Leather"]            = "Leather",
            ["Ingredient_Fabric"]             = "Fabric",
            ["Ingredient_Silk"]               = "Silk",
            ["Ingredient_Wood"]               = "Wood",
            ["Ingredient_Bone"]               = "Bone",
            ["Ingredient_Ruby"]               = "Ruby",
            ["Ingredient_Emerald"]            = "Emerald",
            ["Ingredient_Sapphire"]           = "Sapphire",
            // ── FOOD ──
            ["Food_Pie_Apple"]                = "Apple Pie",
            ["Food_Meat_Cooked"]              = "Cooked Meat",
            ["Food_Meat_Raw"]                 = "Raw Meat",
            ["Food_Bread"]                    = "Bread",
            ["Food_Mushroom_Soup"]            = "Mushroom Soup",
            ["Plant_Fruit_Apple"]             = "Apple",
            ["Plant_Fruit_Berry"]             = "Berry",
            ["Plant_Fruit_Carrot"]            = "Carrot",
            ["Plant_Sapling_Apple"]           = "Apple Sapling",
            ["Plant_Flower_Common_Pink2"]     = "Allium",
            ["Plant_Leaves_Goldentree"]       = "Amber Leaves",
            ["Plant_Leaves_Amber"]            = "Amber Leaves",
            // ── BLOCKS / WOOD ──
            ["Wood_Amber_Trunk"]              = "Amber Log",
            ["Wood_Amber_Trunk_Full"]         = "Amber Tree Trunk",
            ["Wood_Amber_Roots"]              = "Amber Roots",
            ["Wood_Amber_Branch_Long"]        = "Amber Branch (Long)",
            ["Wood_Amber_Branch_Short"]       = "Amber Branch (Short)",
            ["Wood_Amber_Branch_Corner"]      = "Amber Branch (Corner)",
            // ── POTIONS ──
            ["Potion_Antidote"]               = "Antidote",
            ["Potion_Health"]                 = "Health Potion",
            ["Potion_Mana"]                   = "Mana Potion",
            ["Potion_Strength"]               = "Strength Potion",
            ["Potion_Speed"]                  = "Speed Potion",
            // ── CRAFTING STATIONS ──
            ["Bench_Alchemy"]                 = "Alchemist's Workbench",
            ["Bench_Forge"]                   = "Forge",
            ["Bench_Crafting"]                = "Crafting Bench",
            ["Bench_Cooking"]                 = "Cooking Station",
            // ── MISC ──
            ["Portal_Device"]                 = "Ancient Gateway",
            ["Recipe_Book_Magic_Air"]         = "Air Grimoire",
            ["Recipe_Book_Magic_Fire"]        = "Fire Grimoire",
            ["Recipe_Book_Magic_Water"]       = "Water Grimoire",
            ["Recipe_Book_Magic_Earth"]       = "Earth Grimoire",
            ["Deco_Bucket"]                   = "Ancient Bucket",
        };

        // ── Live data ─────────────────────────────────────────────────────────────
    public static readonly ConcurrentDictionary<uint, string>   NumericIdToName  = new();
    public static readonly ConcurrentDictionary<string, string> LiveNameMap      =
        new(StringComparer.OrdinalIgnoreCase);
    public static readonly ConcurrentDictionary<string, bool>   LiteralNames     = new();
    public static readonly ConcurrentDictionary<byte, int>      SeenRegistryOpcodes = new();

    public static int  TotalRegistryEntriesParsed { get; private set; }
    public static bool HasLiveData                { get; private set; }
    public static int  DumpedPacketCount          => _dumpCount;

    // ── Regex ─────────────────────────────────────────────────────────────────
    private static readonly Regex PascalRx    = new(@"[A-Z][a-z][a-zA-Z]{1,28}", RegexOptions.Compiled);
    private static readonly Regex NamespaceRx = new(@"hytale:[a-z][a-z0-9_]{2,40}", RegexOptions.Compiled);
    private static readonly Regex JunkRx      = new(@"[./\\:<>|]", RegexOptions.Compiled);

    static RegistrySyncParser()
    {
        foreach (var kv in BuiltInNames)
            LiveNameMap[kv.Key] = kv.Value;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>
    /// Process every S→C packet in range 40-85.
    /// No magic gating — we try to parse every packet and use quality filtering.
    /// Also dumps raw bytes to disk for community format analysis.
    /// </summary>
    public static bool TryParse(byte opcode, byte[] payload,
                                 ConcurrentDictionary<uint, string> idNameMap)
    {
        if (opcode < RegistryOpcodeMin || opcode > RegistryOpcodeMax) return false;
        if (payload.Length < 4) return false;

        // Skip known high-frequency entity-update opcodes (0x40/0x41/0x42 = 160+ hits)
        if (EntityUpdateOpcodes.Contains(opcode)) return false;

        SeenRegistryOpcodes.AddOrUpdate(opcode, 1, (_, v) => v + 1);

        // ── 1. Dump raw bytes to disk (first MaxDumps packets only) ───────────
        DumpRawPacket(opcode, payload);

        // ── 2. Try all 4 parsing strategies ───────────────────────────────────
        int found = 0;
        found += ParseStrategy_LengthPrefix(payload, idNameMap, prefix: 2, idBefore: true);   // [uint32 id][uint16 len][utf8]
        found += ParseStrategy_LengthPrefix(payload, idNameMap, prefix: 1, idBefore: true);   // [uint32 id][uint8  len][utf8]
        found += ParseStrategy_LengthPrefix(payload, idNameMap, prefix: 2, idBefore: false);  // [uint16 len][utf8][uint32 id]
        found += ParseStrategy_VarIntStrings(payload, idNameMap);                              // [VarInt count][VarInt len][utf8]... index=id
        found += ParseStrategy_AsciiScan(payload, idNameMap);                                  // raw ASCII literal scan

        if (found > 0)
        {
            HasLiveData = true;
            TotalRegistryEntriesParsed += found;
        }
        return found > 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>
    /// Strategy A: [uint32 numericId][prefixLen bytes: length][utf8 name]
    /// or reversed: [prefixLen bytes: length][utf8 name][uint32 numericId]
    /// </summary>
    private static int ParseStrategy_LengthPrefix(byte[] data,
        ConcurrentDictionary<uint, string> idNameMap, int prefix, bool idBefore)
    {
        int found = 0;
        for (int i = 0; i + (idBefore ? 4 + prefix : prefix) < data.Length; i++)
        {
            try
            {
                int nameLen, nameStart;
                uint numericId;

                if (idBefore)
                {
                    numericId = BitConverter.ToUInt32(data, i);
                    if (!IsLikelyItemId(numericId)) continue;
                    nameLen   = prefix == 2 ? BitConverter.ToUInt16(data, i + 4) : data[i + 4];
                    nameStart = i + 4 + prefix;
                }
                else
                {
                    nameLen   = prefix == 2 ? BitConverter.ToUInt16(data, i) : data[i];
                    nameStart = i + prefix;
                    if (nameStart + nameLen + 4 > data.Length) continue;
                    numericId = BitConverter.ToUInt32(data, nameStart + nameLen);
                    if (!IsLikelyItemId(numericId)) continue;
                }

                if (nameLen < 3 || nameLen > 60) continue;
                if (nameStart + nameLen > data.Length) continue;

                string name = Encoding.UTF8.GetString(data, nameStart, nameLen);
                if (!IsValidName(name)) continue;

                RegisterMapping(numericId, name, idNameMap);
                found++;
            }
            catch { }
        }
        return found;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>
    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>
    /// Strategy C: VarInt-prefixed string array (ACTUAL Hytale protocol format).
    /// Hytale uses PacketIO.readVarString = VarInt-length + UTF-8 bytes.
    /// Registry packets are typically: [VarInt count][VarInt len][utf8]...
    /// where the array INDEX is the registry numeric ID.
    /// Also tries: [uint32 count][VarInt len][utf8]... variant.
    /// </summary>
    private static int ParseStrategy_VarIntStrings(byte[] data,
                                                    ConcurrentDictionary<uint, string> idNameMap)
    {
        int found = 0;
        // Try starting at every offset 0-16 to catch headers of varying sizes
        for (int startOffset = 0; startOffset <= Math.Min(16, data.Length - 4); startOffset++)
        {
            int attempt = TryVarIntStringArray(data, startOffset, idNameMap);
            if (attempt > found) found = attempt;
        }
        return found;
    }

    private static int TryVarIntStringArray(byte[] data, int offset,
                                             ConcurrentDictionary<uint, string> idNameMap)
    {
        if (offset >= data.Length - 4) return 0;
        // Try reading a count as VarInt
        if (!TryReadVarInt(data, offset, out uint count, out int countLen)) return 0;
        if (count < 1 || count > 10000) return 0;

        int pos   = offset + countLen;
        int found = 0;
        uint idx  = 0;

        while (pos < data.Length && idx < count)
        {
            // Read string length as VarInt
            if (!TryReadVarInt(data, pos, out uint strLen, out int lenBytes)) break;
            if (strLen == 0) { pos += lenBytes; idx++; continue; }  // empty entry, skip
            if (strLen > 128) break;  // sanity check

            int nameStart = pos + lenBytes;
            if (nameStart + (int)strLen > data.Length) break;

            try
            {
                string name = Encoding.UTF8.GetString(data, nameStart, (int)strLen).Trim();
                if (IsValidHytaleId(name))
                {
                    RegisterMapping(idx, name, idNameMap);
                    found++;
                }
            }
            catch { }

            pos = nameStart + (int)strLen;
            idx++;
        }
        return found >= 3 ? found : 0;  // require at least 3 valid entries to commit
    }

    private static bool IsValidHytaleId(string s)
    {
        if (s.Length < 3 || s.Length > 80) return false;
        if (!char.IsLetter(s[0])) return false;
        // Hytale ID format: "Weapon_Sword_Iron", "Tool_Pickaxe_Cobalt", "hytale:xxx"
        return s.All(c => char.IsLetterOrDigit(c) || c == '_' || c == ':');
    }

    private static bool TryReadVarInt(byte[] data, int offset, out uint value, out int bytesRead)
    {
        value = 0; bytesRead = 0;
        int shift = 0;
        while (offset + bytesRead < data.Length && bytesRead < 5)
        {
            byte b = data[offset + bytesRead];
            bytesRead++;
            value |= (uint)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
            shift += 7;
        }
        return false;
    }

    /// <summary>Strategy B: scan for ASCII literal runs of 4+ printable chars,
    /// find PascalCase or hytale:namespace strings inside.
    /// </summary>
    private static int ParseStrategy_AsciiScan(byte[] data,
                                                ConcurrentDictionary<uint, string> idNameMap)
    {
        int found = 0;
        int runStart = -1;
        for (int i = 0; i <= data.Length; i++)
        {
            bool printable = i < data.Length && data[i] >= 0x20 && data[i] < 0x7F;
            if (printable)
            {
                if (runStart < 0) runStart = i;
            }
            else
            {
                if (runStart >= 0 && i - runStart >= 4)
                {
                    try
                    {
                        string run = Encoding.ASCII.GetString(data, runStart, i - runStart).Trim();
                        found += ExtractNamesFromRun(run, idNameMap);
                    }
                    catch { }
                }
                runStart = -1;
            }
        }
        return found;
    }

    private static int ExtractNamesFromRun(string run,
                                            ConcurrentDictionary<uint, string> idNameMap)
    {
        int found = 0;
        foreach (Match m in NamespaceRx.Matches(run))
        {
            string ns = m.Value;
            if (LiteralNames.TryAdd(ns, true)) { LiveNameMap[ns] = ns; found++; }
        }
        foreach (Match m in PascalRx.Matches(run))
        {
            string s = m.Value;
            if (!IsValidName(s) || LiteralNames.ContainsKey(s)) continue;
            LiteralNames.TryAdd(s, true);
            string display = BuiltInNames.TryGetValue(s, out var d) ? d : s;
            LiveNameMap[s] = display;
            found++;
        }
        return found;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Dump raw packet bytes to disk for manual format analysis
    private static void DumpRawPacket(byte opcode, byte[] payload)
    {
        if (_dumpCount >= MaxDumps) return;
        try
        {
            if (!_dumpDirCreated)
            {
                Directory.CreateDirectory(DumpDir);
                _dumpDirCreated = true;
            }
            string fname = Path.Combine(DumpDir,
                $"reg_0x{opcode:X2}_{DateTime.Now:HHmmss_fff}_{payload.Length}b.bin");
            File.WriteAllBytes(fname, payload);
            _dumpCount++;
        }
        catch { }
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>Register a numeric-ID → name mapping.</summary>
    public static void RegisterMapping(uint numericId, string stringId,
                                        ConcurrentDictionary<uint, string>? idNameMap = null)
    {
        string display = BuiltInNames.TryGetValue(stringId, out var d) ? d : stringId;
        NumericIdToName[numericId] = display;
        LiveNameMap[stringId]      = display;
        idNameMap?.TryAdd(numericId, display);
    }

    /// <summary>Look up a display name for a numeric item ID.</summary>
    public static string? LookupName(uint numericId)
        => NumericIdToName.TryGetValue(numericId, out var n) ? n : null;

    /// <summary>All known names: numeric ID → display name.</summary>
    public static IReadOnlyDictionary<string, string> GetAllKnownNames() => LiveNameMap;

    // ─────────────────────────────────────────────────────────────────────────
    private static bool IsLikelyItemId(uint id) => id >= 1 && id <= 500_000;
    private static bool IsValidName(string s)
    {
        if (s.Length < 3 || s.Length > 60) return false;
        if (!char.IsUpper(s[0])) return false;
        if (s.Length > 1 && !char.IsLower(s[1]) && !char.IsUpper(s[1])) return false;
        if (!s.Any(char.IsLower)) return false;
        if (s.All(char.IsDigit)) return false;
        if (JunkRx.IsMatch(s)) return false;
        if (s.Distinct().Count() < 2) return false;
        return s.All(c => char.IsLetterOrDigit(c) || c == '_');
    }
}
