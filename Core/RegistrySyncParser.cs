using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using ZstdSharp;

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

    private static byte[] TryDecompressZstd(byte[] payload)
    {
        try
        {
            using var d = new ZstdSharp.Decompressor();
            var span = d.Unwrap(payload);
            var result = span.ToArray();

            Console.WriteLine($"[ZSTD] Decompressed {payload.Length} -> {result.Length} bytes");
            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ZSTD] Decompress failed: {ex.Message}");
            return payload;
        }
    }





    // ── Registry opcode range (decimal 40–85, community-confirmed login range) ─
    public const int RegistryOpcodeMin = 40;
    public const int RegistryOpcodeMax = 85;

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

    // ── Known Hytale item names (hytalemodding.dev + community) ──────────────
    public static readonly IReadOnlyDictionary<string, string> BuiltInNames =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Weapons
            ["DiamondSword"]     = "Diamond Sword",    ["IronSword"]       = "Iron Sword",
            ["StoneSword"]       = "Stone Sword",      ["WoodenSword"]     = "Wooden Sword",
            ["GoldenSword"]      = "Golden Sword",     ["NetherSword"]     = "Nether Sword",
            ["Bow"]              = "Bow",               ["Arrow"]           = "Arrow",
            ["Trident"]          = "Trident",           ["Crossbow"]        = "Crossbow",
            // Pickaxes
            ["DiamondPickaxe"]   = "Diamond Pickaxe",  ["IronPickaxe"]     = "Iron Pickaxe",
            ["StonePickaxe"]     = "Stone Pickaxe",    ["WoodenPickaxe"]   = "Wooden Pickaxe",
            ["GoldenPickaxe"]    = "Golden Pickaxe",   ["NetherPickaxe"]   = "Nether Pickaxe",
            // Axes
            ["DiamondAxe"]       = "Diamond Axe",      ["IronAxe"]         = "Iron Axe",
            ["StoneAxe"]         = "Stone Axe",        ["WoodenAxe"]       = "Wooden Axe",
            // Shovels & Hoes
            ["DiamondShovel"]    = "Diamond Shovel",   ["IronShovel"]      = "Iron Shovel",
            ["DiamondHoe"]       = "Diamond Hoe",      ["IronHoe"]         = "Iron Hoe",
            // Tools
            ["FishingRod"]       = "Fishing Rod",      ["Shears"]          = "Shears",
            ["FlintAndSteel"]    = "Flint and Steel",  ["Clock"]           = "Clock",
            ["Compass"]          = "Compass",
            // Armor – Diamond
            ["DiamondHelmet"]    = "Diamond Helmet",   ["DiamondChestplate"]= "Diamond Chestplate",
            ["DiamondLeggings"]  = "Diamond Leggings", ["DiamondBoots"]    = "Diamond Boots",
            // Armor – Iron
            ["IronHelmet"]       = "Iron Helmet",      ["IronChestplate"]  = "Iron Chestplate",
            ["IronLeggings"]     = "Iron Leggings",    ["IronBoots"]       = "Iron Boots",
            // Armor – other
            ["GoldenHelmet"]     = "Golden Helmet",    ["GoldenChestplate"]= "Golden Chestplate",
            ["GoldenLeggings"]   = "Golden Leggings",  ["GoldenBoots"]     = "Golden Boots",
            ["ChainmailHelmet"]  = "Chainmail Helmet", ["LeatherHelmet"]   = "Leather Helmet",
            ["LeatherChestplate"]= "Leather Chestplate",
            // Blocks
            ["Stone"]            = "Stone",            ["Cobblestone"]     = "Cobblestone",
            ["Dirt"]             = "Dirt",             ["Grass"]           = "Grass Block",
            ["Sand"]             = "Sand",             ["Gravel"]          = "Gravel",
            ["OakLog"]           = "Oak Log",          ["OakPlanks"]       = "Oak Planks",
            ["OakLeaves"]        = "Oak Leaves",       ["OakSapling"]      = "Oak Sapling",
            ["BirchLog"]         = "Birch Log",        ["SpruceLog"]       = "Spruce Log",
            ["JungleLog"]        = "Jungle Log",       ["AcaciaLog"]       = "Acacia Log",
            ["Torch"]            = "Torch",            ["Ladder"]          = "Ladder",
            ["Glass"]            = "Glass",            ["Chest"]           = "Chest",
            ["Furnace"]          = "Furnace",          ["CraftingTable"]   = "Crafting Table",
            ["Workbench"]        = "Workbench",        ["Anvil"]           = "Anvil",
            ["Bookshelf"]        = "Bookshelf",        ["Pumpkin"]         = "Pumpkin",
            ["Melon"]            = "Melon",
            // Ores
            ["CoalOre"]          = "Coal Ore",         ["IronOre"]         = "Iron Ore",
            ["GoldOre"]          = "Gold Ore",         ["DiamondOre"]      = "Diamond Ore",
            ["EmeraldOre"]       = "Emerald Ore",      ["LapisOre"]        = "Lapis Ore",
            ["NetherQuartzOre"]  = "Nether Quartz Ore",
            // Materials
            ["Coal"]             = "Coal",             ["IronIngot"]       = "Iron Ingot",
            ["GoldIngot"]        = "Gold Ingot",       ["Diamond"]         = "Diamond",
            ["Emerald"]          = "Emerald",          ["NetherQuartz"]    = "Nether Quartz",
            ["String"]           = "String",           ["Leather"]         = "Leather",
            ["Feather"]          = "Feather",          ["Bone"]            = "Bone",
            ["BoneMeal"]         = "Bone Meal",        ["Gunpowder"]       = "Gunpowder",
            ["Flint"]            = "Flint",            ["EnderPearl"]      = "Ender Pearl",
            ["EnderEye"]         = "Eye of Ender",     ["BlazePowder"]     = "Blaze Powder",
            ["BlazeRod"]         = "Blaze Rod",        ["Slimeball"]       = "Slimeball",
            ["Wool"]             = "Wool",             ["Stick"]           = "Stick",
            // Food
            ["Apple"]            = "Apple",            ["GoldenApple"]     = "Golden Apple",
            ["Bread"]            = "Bread",            ["Carrot"]          = "Carrot",
            ["GoldenCarrot"]     = "Golden Carrot",    ["Potato"]          = "Potato",
            ["BakedPotato"]      = "Baked Potato",     ["Beef"]            = "Raw Beef",
            ["CookedBeef"]       = "Cooked Beef",      ["Steak"]           = "Steak",
            ["Chicken"]          = "Raw Chicken",      ["CookedChicken"]   = "Cooked Chicken",
            ["Fish"]             = "Raw Fish",         ["CookedFish"]      = "Cooked Fish",
            ["MelonSlice"]       = "Melon Slice",      ["Porkchop"]        = "Raw Porkchop",
            ["CookedPorkchop"]   = "Cooked Porkchop",
            // Misc
            ["Minecart"]         = "Minecart",         ["Boat"]            = "Boat",
            ["Map"]              = "Map",              ["Book"]            = "Book",
            ["WrittenBook"]      = "Written Book",     ["Paper"]           = "Paper",
            ["Bowl"]             = "Bowl",             ["Bucket"]          = "Bucket",
            ["WaterBucket"]      = "Water Bucket",     ["LavaBucket"]      = "Lava Bucket",
            ["Saddle"]           = "Saddle",           ["SpawnEgg"]        = "Spawn Egg",
            ["Potion"]           = "Potion",           ["GlassBottle"]     = "Glass Bottle",
            ["ExperienceBottle"] = "Exp. Bottle",      ["NameTag"]         = "Name Tag",
            ["LeadRope"]         = "Lead",             ["Tripwire"]        = "Tripwire Hook",
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
        if (EntityUpdateOpcodes.Contains(opcode)) return false;

        SeenRegistryOpcodes.AddOrUpdate(opcode, 1, (_, v) => v + 1);

        DumpRawPacket(opcode, payload);

        byte[] data = TryDecompressZstd(payload);

        int found = 0;
        found += ParseStrategy_LengthPrefix(data, idNameMap, prefix: 2, idBefore: true);
        found += ParseStrategy_LengthPrefix(data, idNameMap, prefix: 1, idBefore: true);
        found += ParseStrategy_LengthPrefix(data, idNameMap, prefix: 2, idBefore: false);
        found += ParseStrategy_AsciiScan(data, idNameMap);

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
    /// Strategy B: scan for ASCII literal runs of 4+ printable chars,
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
