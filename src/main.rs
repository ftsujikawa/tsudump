#![allow(dead_code)]

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read};
use std::mem;
use std::os::raw::c_char;
use std::path::Path;
use std::str;

use gimli::{DebugAbbrev, DebugInfo, DebugLine, DebugStr, EndianSlice, LittleEndian, Reader, ReaderOffset};
use mach_o_sys::loader::*;

// Mach-O CPUタイプ定数
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x01000007; // CPU_TYPE_X86 | CPU_ARCH_ABI64
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100000c; // CPU_TYPE_ARM | CPU_ARCH_ABI64
const CPU_TYPE_ARM64_32: u32 = 0x0200000c; // CPU_TYPE_ARM | CPU_ARCH_ABI64_32

// Fat Binary（Universal Binary）定数
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca; // バイトスワップされたFAT_MAGIC

// Fat Binary ヘッダ構造
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FatHeader {
    magic: u32,
    nfat_arch: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FatArch {
    cputype: u32,
    cpusubtype: u32,
    offset: u32,
    size: u32,
    align: u32,
}

// CPUアーキテクチャを表す列挙型
#[derive(Debug, Clone, PartialEq)]
enum CpuArchitecture {
    X86_64,
    ARM64,
    ARM32,
    Unknown(u32),
}

impl CpuArchitecture {
    /// Mach-OヘッダのcputypeからCPUアーキテクチャを判定
    fn from_mach_cputype(cputype: i32) -> Self {
        // i32をu32に変換して処理
        let cputype_u32 = cputype as u32;
        match cputype_u32 {
            CPU_TYPE_X86_64 => CpuArchitecture::X86_64,
            CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => CpuArchitecture::ARM64,
            CPU_TYPE_ARM => CpuArchitecture::ARM32,
            _ => CpuArchitecture::Unknown(cputype_u32),
        }
    }
    
    /// アーキテクチャ名を文字列で取得
    fn name(&self) -> &'static str {
        match self {
            CpuArchitecture::X86_64 => "x86_64",
            CpuArchitecture::ARM64 => "arm64",
            CpuArchitecture::ARM32 => "arm32",
            CpuArchitecture::Unknown(_) => "unknown",
        }
    }
    
    /// アーキテクチャの詳細説明を取得
    fn description(&self) -> &'static str {
        match self {
            CpuArchitecture::X86_64 => "Intel x86-64 (64-bit)",
            CpuArchitecture::ARM64 => "ARM64 (Apple Silicon / AArch64)",
            CpuArchitecture::ARM32 => "ARM32 (32-bit ARM)",
            CpuArchitecture::Unknown(_) => "Unknown architecture",
        }
    }
    
    /// CPUタイプの名前を取得
    fn cpu_type_name(&self) -> &'static str {
        match self {
            CpuArchitecture::X86_64 => "CPU_TYPE_X86_64",
            CpuArchitecture::ARM64 => "CPU_TYPE_ARM64",
            CpuArchitecture::ARM32 => "CPU_TYPE_ARM",
            CpuArchitecture::Unknown(_) => "CPU_TYPE_UNKNOWN",
        }
    }
    
    /// 対応する逆アセンブラがあるかチェック
    fn has_disassembler(&self) -> bool {
        match self {
            CpuArchitecture::X86_64 | CpuArchitecture::ARM64 | CpuArchitecture::ARM32 => true,
            CpuArchitecture::Unknown(_) => false,
        }
    }
    
    /// 命令の標準長を取得（バイト）
    fn instruction_alignment(&self) -> usize {
        match self {
            CpuArchitecture::X86_64 => 1, // 可変長
            CpuArchitecture::ARM64 => 4,  // 固定4バイト
            CpuArchitecture::ARM32 => 4,  // 固定4バイト（Thumbは2バイトだが簡略化）
            CpuArchitecture::Unknown(_) => 4,
        }
    }
}

/// Fat Binaryから適切なアーキテクチャを選択してMach-Oバイナリを抽出
fn extract_from_fat_binary(buffer: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if buffer.len() < std::mem::size_of::<FatHeader>() {
        return Err("ファイルサイズが小さすぎます".into());
    }
    
    // Fat Headerをバイト配列から直接読み取り
    let magic = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let is_swapped = magic == FAT_CIGAM;
    
    if magic != FAT_MAGIC && magic != FAT_CIGAM {
        return Err(format!("Fat Binaryのマジックナンバーが不正です: 0x{:08x}", magic).into());
    }
    
    let nfat_arch = if is_swapped {
        u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]])
    } else {
        u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]])
    };
    
    // アーキテクチャ数の妄当性をチェック
    if nfat_arch == 0 || nfat_arch > 10 {
        return Err(format!("不正なアーキテクチャ数: {}", nfat_arch).into());
    }
    
    println!("Fat Binary検出: {} 個のアーキテクチャが含まれています", nfat_arch);
    
    let fat_arch_size = 20; // FatArchのサイズ（u32 × 5 = 20バイト）
    let fat_arch_start = 8; // FatHeaderのサイズ（u32 × 2 = 8バイト）
    
    // 各アーキテクチャをリストアップ
    for i in 0..nfat_arch {
        let arch_offset = fat_arch_start + (i as usize * fat_arch_size);
        if arch_offset + fat_arch_size > buffer.len() {
            println!("　アーキテクチャ {}: バッファ範囲外", i);
            continue;
        }
        
        // Fat Archをバイト配列から直接読み取り
        let arch_bytes = &buffer[arch_offset..arch_offset + fat_arch_size];
        let (cputype, _cpusubtype, offset, size, _align) = if is_swapped {
            (
                u32::from_le_bytes([arch_bytes[0], arch_bytes[1], arch_bytes[2], arch_bytes[3]]),
                u32::from_le_bytes([arch_bytes[4], arch_bytes[5], arch_bytes[6], arch_bytes[7]]),
                u32::from_le_bytes([arch_bytes[8], arch_bytes[9], arch_bytes[10], arch_bytes[11]]),
                u32::from_le_bytes([arch_bytes[12], arch_bytes[13], arch_bytes[14], arch_bytes[15]]),
                u32::from_le_bytes([arch_bytes[16], arch_bytes[17], arch_bytes[18], arch_bytes[19]])
            )
        } else {
            (
                u32::from_be_bytes([arch_bytes[0], arch_bytes[1], arch_bytes[2], arch_bytes[3]]),
                u32::from_be_bytes([arch_bytes[4], arch_bytes[5], arch_bytes[6], arch_bytes[7]]),
                u32::from_be_bytes([arch_bytes[8], arch_bytes[9], arch_bytes[10], arch_bytes[11]]),
                u32::from_be_bytes([arch_bytes[12], arch_bytes[13], arch_bytes[14], arch_bytes[15]]),
                u32::from_be_bytes([arch_bytes[16], arch_bytes[17], arch_bytes[18], arch_bytes[19]])
            )
        };
        
        let arch = CpuArchitecture::from_mach_cputype(cputype as i32);
        println!("　アーキテクチャ {}: {} (cputype: 0x{:x}, offset: 0x{:x}, size: {})", 
                 i, arch.name(), cputype, offset, size);
        
        // 有効なアーキテクチャをチェック（サイズが0ではなく、範囲内にある）
        if size > 0 && offset > 0 && offset as usize + size as usize <= buffer.len() {
            // アーキテクチャが既知のものかどうかをチェック
            if !matches!(arch, CpuArchitecture::Unknown(_)) {
                println!("アーキテクチャ {} ({}) を選択しました", i, arch.name());
                let extracted = buffer[offset as usize..(offset + size) as usize].to_vec();
                if extracted.len() >= 4 {
                    return Ok(extracted);
                }
            }
        } else {
            println!("　アーキテクチャ {}: 無効なデータ (offset: 0x{:x}, size: {})", i, offset, size);
        }
    }
    
    Err("有効なアーキテクチャが見つかりません".into())
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub seg_name: String,
    pub offset: u64,
    pub size: u64,
    pub addr: u64,
}

// dSYMファイルからデバッグ情報を読み込む関数
fn try_load_dsym_debug_info(original_path: &str) -> Option<(Vec<u8>, HashMap<String, SectionInfo>)> {
    let path = Path::new(original_path);
    let file_name = path.file_name()?.to_str()?;
    let parent_dir = path.parent()?;
    
    // a.out.dSYM/Contents/Resources/DWARF/a.out のパスを構築
    let dsym_path = parent_dir
        .join(format!("{}.dSYM", file_name))
        .join("Contents")
        .join("Resources")
        .join("DWARF")
        .join(file_name);
    
    if !dsym_path.exists() {
        return None;
    }
    
    println!("dSYMファイルからデバッグ情報を読み込み中: {}", dsym_path.display());
    
    // dSYMファイルを読み込み
    let mut file = File::open(&dsym_path).ok()?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).ok()?;
    
    // Fat Binaryの場合は適切なアーキテクチャを抽出
    let actual_buffer = match extract_from_fat_binary(&buffer) {
        Ok(extracted) => extracted,
        Err(_) => buffer,
    };
    
    // Mach-Oヘッダを読み取り
    if actual_buffer.len() < mem::size_of::<mach_header_64>() {
        return None;
    }
    
    let header = unsafe { read_header(&actual_buffer) };
    let is_64 = header.magic == MH_MAGIC_64 || header.magic == MH_CIGAM_64;
    
    // セクション情報を解析
    let sections = if is_64 {
        parse_load_commands_64(&actual_buffer, header.ncmds as usize)
    } else {
        parse_load_commands_32(&actual_buffer, header.ncmds as usize)
    };
    
    Some((actual_buffer, sections))
}



fn main() -> io::Result<()> {
    // ...（省略）
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("使用法: tsudump <ファイルパス> <コマンド>");
        println!("コマンド:");
        println!("  --header: Mach-Oヘッダ情報を表示");
        println!("  --arch: アーキテクチャ情報を詳細表示");
        println!("  --segments: セグメント情報を表示");
        println!("  --symbols: シンボルテーブルを表示");
        println!("  --disassemble: __textセクションを逆アセンブル（アーキテクチャ自動判別）");
        println!("  --dump-data: __dataセクションをダンプ");
        println!("  --debug-info: __debug_infoセクションを解析 (DWARF 2-5対応)");
        println!("  --debug-abbrev: __debug_abbrevセクションを解析 (DWARF 2-5対応)");
        println!("  --debug-aranges: __debug_arangesセクションを解析 (DWARF 2-5対応)");
        println!("  --debug-line: __debug_lineセクションを解析 (DWARF 2-5対応)");
        println!("  --debug-str: __debug_strセクションを表示 (DWARF 2-5)");
        println!("  --debug-str-hex: __debug_strセクションを16進ダンプ (DWARF 2-5)");
        println!("  --debug-str-offsets: __debug_str_offs__DWARFセクションを解析 (DWARF 5)");
        println!("  --debug-str-offsets-hex: __debug_str_offs__DWARFセクションを16進ダンプ (DWARF 5)");
        println!("  --debug-addr: __debug_addrセクションを解析 (DWARF 5)");
        println!("  --apple-names: __apple_namesセクションを16進ダンプ表示");
        println!("  --stubs: __stubsセクションを16進ダンプ表示");
        println!("  --stubs-follow: __stubs直後のセクションも自動ダンプ表示");
        println!("  --unwind-info: __unwind_infoセクションを16進ダンプ表示");
        println!("  --got: __gotセクションを16進ダンプ表示");
        return Ok(());
    }

    let file_path = &args[1];
    let command = &args[2];

    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    
    // Fat Binaryの場合は適切なアーキテクチャを抽出
    let actual_buffer = if magic == FAT_MAGIC || magic == FAT_CIGAM {
        match extract_from_fat_binary(&buffer) {
            Ok(extracted) => {
                println!("");
                extracted
            },
            Err(e) => {
                println!("エラー: Fat Binaryの処理に失敗しました: {}", e);
                return Ok(());
            }
        }
    } else {
        buffer
    };
    
    let magic = u32::from_le_bytes([actual_buffer[0], actual_buffer[1], actual_buffer[2], actual_buffer[3]]);
    let is_64 = magic == MH_MAGIC_64;
    enum MachHeader<'a> {
        Header32(&'a mach_o_sys::loader::mach_header),
        Header64(&'a mach_header_64),
    }
    let (sections, _ncmds, macho_header) = if is_64 {
        let header: &mach_header_64 = unsafe { &*(actual_buffer.as_ptr() as *const mach_header_64) };
        (parse_load_commands_64(&actual_buffer, header.ncmds as usize), header.ncmds as usize, MachHeader::Header64(header))
    } else if magic == MH_MAGIC {
        use mach_o_sys::loader::mach_header;
        let header: &mach_header = unsafe { &*(actual_buffer.as_ptr() as *const mach_header) };
        (parse_load_commands_32(&actual_buffer, header.ncmds as usize), header.ncmds as usize, MachHeader::Header32(header))
    } else {
        println!("エラー: 未対応または不正なMach-Oファイルです (magic=0x{:08x})", magic);
        return Ok(());
    };

    match command.as_str() {
        "--arch" => {
            // アーキテクチャ情報を詳細表示
            match macho_header {
                MachHeader::Header64(header64) => {
                    let arch = CpuArchitecture::from_mach_cputype(header64.cputype);
                    println!("\n=== アーキテクチャ情報 ===");
                    println!("アーキテクチャ: {} - {}", arch.name(), arch.description());
                    println!("CPUタイプ: {} (0x{:08x})", arch.cpu_type_name(), header64.cputype as u32);
                    println!("CPUサブタイプ: {} (0x{:08x})", header64.cpusubtype, header64.cpusubtype);
                    println!("命令アライメント: {} バイト", arch.instruction_alignment());
                    println!("逆アセンブル対応: {}", if arch.has_disassembler() { "✅ 対応" } else { "❌ 未対応" });
                    
                    // ファイルタイプ情報も表示
                    let filetype_str = match header64.filetype {
                        1 => "MH_OBJECT (オブジェクトファイル)",
                        2 => "MH_EXECUTE (実行可能ファイル)",
                        6 => "MH_DYLIB (動的ライブラリ)",
                        8 => "MH_BUNDLE (バンドル)",
                        10 => "MH_DSYM (デバッグシンボル)",
                        _ => "その他",
                    };
                    println!("ファイルタイプ: {} ({})", header64.filetype, filetype_str);
                    println!("フラグ: 0x{:08x}", header64.flags);
                },
                MachHeader::Header32(header32) => {
                    let arch = CpuArchitecture::from_mach_cputype(header32.cputype);
                    println!("\n=== アーキテクチャ情報 (32-bit) ===");
                    println!("アーキテクチャ: {} - {}", arch.name(), arch.description());
                    println!("CPUタイプ: {} (0x{:08x})", arch.cpu_type_name(), header32.cputype as u32);
                    println!("CPUサブタイプ: {} (0x{:08x})", header32.cpusubtype, header32.cpusubtype);
                    println!("命令アライメント: {} バイト", arch.instruction_alignment());
                    println!("逆アセンブル対応: {}", if arch.has_disassembler() { "✅ 対応" } else { "❌ 未対応" });
                    println!("⚠️  注意: 32-bit Mach-Oの逆アセンブルは現在未対応です");
                }
            }
            return Ok(());
        },
        "--cstring" => {
            match find_section_by_name(&sections, "__cstring") {
                Some(section) => display_cstring_section(&actual_buffer, section),
                None => println!("__cstringセクションが見つかりません"),
            }
            return Ok(());
        }
        "--unwind-info" => {
            match find_section_by_name(&sections, "__unwind_info") {
                Some(section) => display_unwind_info_section(&actual_buffer, section),
                None => println!("__unwind_infoセクションが見つかりません"),
            }
            return Ok(());
        }
        "--got" => {
            match find_section_by_name(&sections, "__got") {
                Some(section) => display_got_section(&actual_buffer, section),
                None => println!("__gotセクションが見つかりません"),
            }
            return Ok(());
        }
        "--stubs-follow" => {
            display_stubs_and_following_section(&actual_buffer, &sections);
            return Ok(());
        }
        "--stubs" => {
            match find_section_by_name(&sections, "__stubs") {
                Some(section) => {
                    match macho_header {
                        MachHeader::Header64(header64) => {
                            let arch = CpuArchitecture::from_mach_cputype(header64.cputype);
                            display_stubs_section(&actual_buffer, section, arch);
                        }
                        MachHeader::Header32(header32) => {
                            let arch = CpuArchitecture::from_mach_cputype(header32.cputype);
                            display_stubs_section(&actual_buffer, section, arch);
                        }
                    }
                }
                None => println!("__stubsセクションは無効です"),
            }
            return Ok(());
        }
        "--apple-names" => {
            match find_section_by_name(&sections, "__apple_names") {
                Some(section) => display_apple_names_section(&actual_buffer, section),
                None => println!("__apple_namesセクションが見つかりません"),
            }
            return Ok(());
        }
        "--header" => {
            match macho_header {
                MachHeader::Header64(header64) => display_macho_header(header64),
                MachHeader::Header32(_) => println!("32ビットMach-Oのヘッダ表示は未対応です。"),
            }
        },
        "--segments" => {
            println!("セグメント情報:");
            for section in sections.values() {
                println!(
                    "  セグメント: {}, セクション: {}, オフセット: 0x{:x}, サイズ: {}, アドレス: 0x{:x}",
                    section.seg_name, section.name, section.offset, section.size, section.addr
                );
            }
        }
        "--symbols" => display_symbols(&actual_buffer, &sections),
        "--disassemble" => {
            if let Some(text_section) = find_section_by_name(&sections, "__text") {
                match macho_header {
                    MachHeader::Header64(header64) => {
                        let arch = CpuArchitecture::from_mach_cputype(header64.cputype);
                        if arch.has_disassembler() {
                            disassemble_text_section(&actual_buffer, text_section, header64);
                        } else {
                            println!("❌ アーキテクチャ {} ({}) は逆アセンブルに対応していません", arch.name(), arch.description());
                            println!("対応アーキテクチャ: x86_64, ARM64, ARM32");
                        }
                    },
                    MachHeader::Header32(header32) => {
                        let arch = CpuArchitecture::from_mach_cputype(header32.cputype);
                        println!("❌ 32-bit Mach-O ({} - {}) の逆アセンブルは現在未対応です", arch.name(), arch.description());
                        println!("64-bit版のバイナリをご利用ください");
                    },
                }
            } else {
                println!("❌ __textセクションが見つかりません");
                println!("このファイルには実行可能コードが含まれていない可能性があります");
            }
        },
        "--dump-data" => {
            let data_sections: Vec<&SectionInfo> = find_all_sections_in_segment(&sections, "__DATA");
            let owned_sections: Vec<SectionInfo> = data_sections.into_iter().cloned().collect();
            dump_data_sections(&actual_buffer, &owned_sections);
        },
        "--debug-info" | "--debug-abbrev" | "--debug-aranges" | "--debug-line" | "--debug-str" | "--debug-str-hex" | "--debug-str-offsets" | "--debug-str-offsets-hex" | "--debug-addr" => {
            let endian = LittleEndian;

            // デバッグ情報の有無を確認し、必要に応じてdSYMファイルから読み込み
            let (debug_buffer, debug_sections) = {
                let has_debug_info = find_section_by_name(&sections, "__debug_info").is_some();
                
                if !has_debug_info {
                    // 元のファイルにデバッグ情報がない場合、dSYMファイルから読み込み
                    if let Some((dsym_buffer, dsym_sections)) = try_load_dsym_debug_info(file_path) {
                        (dsym_buffer, dsym_sections)
                    } else {
                        println!("デバッグ情報が見つかりません（元ファイルまたはdSYMファイル）");
                        (actual_buffer.clone(), sections.clone())
                    }
                } else {
                    (actual_buffer.clone(), sections.clone())
                }
            };

            let get_section_data = |name: &str| -> gimli::EndianSlice<LittleEndian> {
                match find_section_by_name(&debug_sections, name) {
                    Some(section) => {
                        let start = section.offset as usize;
                        let end = start + section.size as usize;
                        if end > debug_buffer.len() {
                            return EndianSlice::new(&[], endian);
                        }
                        EndianSlice::new(&debug_buffer[start..end], endian)
                    }
                    None => EndianSlice::new(&[], endian),
                }
            };

            let debug_info_data = get_section_data("__debug_info");
            let debug_abbrev_data = get_section_data("__debug_abbrev");
            let debug_line_data = get_section_data("__debug_line");
            let debug_str_data = get_section_data("__debug_str");
            let debug_aranges_data = get_section_data("__debug_aranges");
            
            // DWARF 5の新しいセクション
            let debug_str_offsets_data = get_section_data("__debug_str_offs__DWARF");
            let debug_addr_data = get_section_data("__debug_addr");
            let debug_line_str_data = get_section_data("__debug_line_str");

            let debug_info = DebugInfo::new(&debug_info_data, endian);
            let debug_abbrev = DebugAbbrev::new(&debug_abbrev_data, endian);
            let _debug_line = DebugLine::new(&debug_line_data, endian);
            let debug_str = DebugStr::new(&debug_str_data, endian);
            let debug_str_offsets = gimli::DebugStrOffsets::from(gimli::EndianSlice::new(&debug_str_offsets_data, endian));
            let debug_addr = gimli::DebugAddr::from(gimli::EndianSlice::new(&debug_addr_data, endian));
            let _debug_aranges = gimli::DebugAranges::new(&debug_aranges_data, endian);
            let debug_line_str = gimli::DebugLineStr::new(&debug_line_str_data, endian);

            // __TEXTセグメントのベースアドレスを取得
            let text_base_addr = find_all_sections_in_segment(&debug_sections, "__TEXT")
                .iter()
                .find(|s| s.name == "__text")
                .map(|s| s.addr)
                .unwrap_or(0);

            let result = match command.as_str() {
                "--debug-info" => {
                    parse_and_display_debug_info(debug_info, debug_abbrev, debug_str, debug_str_offsets, debug_addr, debug_line_str, text_base_addr, &debug_buffer, &debug_sections)
                }
                "--debug-abbrev" => {
                    if let Some(section) = find_section_by_name(&debug_sections, "__debug_abbrev") {
                        let mut units = debug_info.units();
                        if let Ok(Some(unit)) = units.next() {
                             parse_and_display_debug_abbrev(&debug_buffer, section, unit.version());
                        } else {
                            println!("__debug_infoからユニットを読み込めません");
                        }
                    } else {
                        println!("__debug_abbrevセクションが見つかりません");
                    }
                    Ok(())
                }
                "--debug-aranges" => {
                    if let Some(section) = find_section_by_name(&debug_sections, "__debug_aranges") {
                        parse_and_display_debug_aranges(&debug_buffer, section);
                    } else {
                        println!("__debug_arangesセクションが見つかりません");
                    }
                    Ok(())
                }
                "--debug-line" => {
                    display_debug_line_details_manual(&debug_buffer, &debug_sections);
                    Ok(())
                }
                "--debug-str" => {
                    if let Some(section) = find_section_by_name(&debug_sections, "__debug_str") {
                        display_debug_str(&debug_buffer, section);
                    } else {
                        println!("__debug_strセクションが見つかりません");
                    }
                    Ok(())
                }
                "--debug-str-hex" => {
                    if let Some(section) = find_section_by_name(&debug_sections, "__debug_str") {
                        display_debug_str_hexdump(&debug_buffer, section);
                    } else {
                        println!("__debug_strセクションが見つかりません");
                    }
                    Ok(())
                }
                "--debug-str-offsets" => {
                    if let Some(section) = find_section_by_name(&debug_sections, "__debug_str_offs__DWARF") {
                        parse_and_display_debug_str_offsets(&debug_buffer, section);
                    } else {
                        println!("__debug_str_offs__DWARFセクションが見つかりません");
                    }
                    Ok(())
                }
                "--debug-str-offsets-hex" => {
                    if let Some(section) = find_section_by_name(&debug_sections, "__debug_str_offs__DWARF") {
                        display_debug_str_offsets_hexdump(&debug_buffer, section);
                    } else {
                        println!("__debug_str_offs__DWARFセクションが見つかりません");
                    }
                    Ok(())
                }
                "--debug-addr" => {
                    if let Some(section) = find_section_by_name(&debug_sections, "__debug_addr") {
                        parse_and_display_debug_addr(&debug_buffer, section);
                    } else {
                        println!("__debug_addrセクションが見つかりません");
                    }
                    Ok(())
                }
                _ => unreachable!(),
            };

            if let Err(e) = result {
                println!("DWARF情報の解析中にエラーが発生しました: {}", e);
            }
            return Ok(());
        }
        _ => println!("不明なコマンドです: {}", command),
    }

    Ok(())
}

unsafe fn read_header(buffer: &[u8]) -> &mach_header_64 {
    &*(buffer.as_ptr() as *const mach_header_64)
}

fn parse_load_commands_64(buffer: &[u8], ncmds: usize) -> HashMap<String, SectionInfo> {
    let mut sections = HashMap::new();
    let header_size = mem::size_of::<mach_header_64>();
    let mut offset = header_size;

    for _ in 0..ncmds {
        if offset + mem::size_of::<load_command>() > buffer.len() {
            break;
        }
        let lc: &load_command = unsafe {
            &*(buffer.as_ptr().add(offset) as *const load_command)
        };

        if lc.cmd == LC_SEGMENT_64 as u32 {
            let seg_cmd: &segment_command_64 = unsafe {
                &*(buffer.as_ptr().add(offset) as *const segment_command_64)
            };

            let seg_name = unsafe {
                CStr::from_ptr(seg_cmd.segname.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .into_owned()
            };

            let mut section_offset = offset + mem::size_of::<segment_command_64>();
            for _i in 0..seg_cmd.nsects as usize {
                if section_offset + mem::size_of::<section_64>() > buffer.len() {
                    break;
                }
                let sect: &section_64 = unsafe {
                    &*(buffer.as_ptr().add(section_offset) as *const section_64)
                };

                let sect_name = unsafe {
                    CStr::from_ptr(sect.sectname.as_ptr() as *const c_char)
                        .to_string_lossy()
                        .into_owned()
                };

                let info = SectionInfo {
                    name: sect_name.clone(),
                    seg_name: seg_name.clone(),
                    offset: sect.offset as u64,
                    size: sect.size as u64,
                    addr: sect.addr,
                };
                sections.insert(sect_name, info);
                section_offset += mem::size_of::<section_64>();
            }
        }
        offset += lc.cmdsize as usize;
    }
    sections
}

fn parse_load_commands_32(buffer: &[u8], ncmds: usize) -> HashMap<String, SectionInfo> {
    use mach_o_sys::loader::{mach_header, segment_command, section, load_command};
    let mut sections = HashMap::new();
    let header_size = mem::size_of::<mach_header>();
    let mut offset = header_size;
    for _ in 0..ncmds {
        if offset + mem::size_of::<load_command>() > buffer.len() {
            break;
        }
        let lc: &load_command = unsafe {
            &*(buffer.as_ptr().add(offset) as *const load_command)
        };
        if lc.cmd == LC_SEGMENT as u32 {
            let seg_cmd: &segment_command = unsafe {
                &*(buffer.as_ptr().add(offset) as *const segment_command)
            };
            let seg_name = unsafe {
                CStr::from_ptr(seg_cmd.segname.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .into_owned()
            };
            let mut section_offset = offset + mem::size_of::<segment_command>();
            for _ in 0..seg_cmd.nsects as usize {
                if section_offset + mem::size_of::<section>() > buffer.len() {
                    break;
                }
                let sect: &section = unsafe {
                    &*(buffer.as_ptr().add(section_offset) as *const section)
                };
                let sect_name = unsafe {
                    CStr::from_ptr(sect.sectname.as_ptr() as *const c_char)
                        .to_string_lossy()
                        .into_owned()
                };
                let info = SectionInfo {
                    name: sect_name.clone(),
                    seg_name: seg_name.clone(),
                    offset: sect.offset as u64,
                    size: sect.size as u64,
                    addr: sect.addr as u64,
                };
                sections.insert(sect_name, info);
                section_offset += mem::size_of::<section>();
            }
        }
        offset += lc.cmdsize as usize;
    }
    sections
}

fn find_section_by_name<'a>(
    sections: &'a HashMap<String, SectionInfo>,
    name: &str,
) -> Option<&'a SectionInfo> {
    sections.values().find(|s| s.name == name)
}

fn find_all_sections_in_segment<'a>(
    sections: &'a HashMap<String, SectionInfo>,
    seg_name: &str,
) -> Vec<&'a SectionInfo> {
    sections.values().filter(|s| s.seg_name == seg_name).collect()
}


fn parse_and_display_debug_info<R: Reader>(
    debug_info: DebugInfo<R>,
    debug_abbrev: DebugAbbrev<R>,
    debug_str: DebugStr<R>,
    debug_str_offsets: gimli::DebugStrOffsets<R>,
    debug_addr: gimli::DebugAddr<R>,
    debug_line_str: gimli::DebugLineStr<R>,
    text_base_addr: u64,
    debug_buffer: &[u8],
    debug_sections: &HashMap<String, SectionInfo>,
) -> Result<(), Box<dyn Error>> {

    
    let mut units = debug_info.units();
    let mut previous_dwarf_version: Option<u16> = None;
    
    while let Some(unit) = units.next()? {
        let abbrevs = unit.abbreviations(&debug_abbrev)?;
        let dwarf_version = unit.version();
        
        // DWARFバージョンの変更を検出・報告
        if let Some(prev_version) = previous_dwarf_version {
            if prev_version != dwarf_version {
                println!("⚠️  DWARFバージョンが変更されました: {} → {}", prev_version, dwarf_version);
            }
        }
        previous_dwarf_version = Some(dwarf_version);
        
        // バージョン別の機能説明を表示
        let version_features = match dwarf_version {
            2 => "基本的なDWARF機能",
            3 => "名前空間、インポートモジュール、制限型サポート",
            4 => "型単位、部分単位、テンプレートエイリアスサポート",
            5 => "文字列オフセット、アドレステーブル、呼び出しサイト情報サポート",
            _ => "不明なバージョン",
        };
        
        println!("\n.debug_info: unit at <.debug_info+0x{:?}> (DWARF version {} - {})",
                 unit.offset(), dwarf_version, version_features);
        
        let mut entries = unit.entries(&abbrevs);
        let mut depth = 0;

        while let Some((delta_depth, entry)) = entries.next_dfs()? {
            depth += delta_depth;
            println!("<{}> <{:?}>", depth, entry.offset());

            let tag_name = get_die_tag_name(entry.tag().0 as u64, dwarf_version);
            println!("      TAG: {}", tag_name);

            // タグ別の特別な処理を行う
            let is_compile_unit = entry.tag() == gimli::DW_TAG_compile_unit;
            let is_subprogram = entry.tag() == gimli::DW_TAG_subprogram;
            let is_variable = entry.tag() == gimli::DW_TAG_variable;
            let is_formal_parameter = entry.tag() == gimli::DW_TAG_formal_parameter;
            let is_typedef = entry.tag() == gimli::DW_TAG_typedef;
            let is_structure_type = entry.tag() == gimli::DW_TAG_structure_type;
            let is_class_type = entry.tag() == gimli::DW_TAG_class_type;
            
            let mut low_pc: Option<u64> = None;
            let mut high_pc_value: Option<gimli::AttributeValue<R>> = None;
            let mut high_pc_attr_name: Option<gimli::DwAt> = None;
            let mut ranges_attr: Option<gimli::AttributeValue<R>> = None;
            let mut name_attr: Option<String> = None;
            let mut type_attr: Option<String> = None;

            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next()? {
                let attr_name = get_attr_name(attr.name().0 as u64);
                
                // 重要な属性を記録（すべてのタグで）
                if attr.name() == gimli::DW_AT_low_pc && (is_compile_unit || is_subprogram) {
                    match attr.value() {
                        gimli::AttributeValue::Addr(addr) => {
                            // アドレスが相対的な場合はベースアドレスを加算
                            low_pc = Some(if addr < 0x100000000 { addr + text_base_addr } else { addr });
                        },
                        gimli::AttributeValue::Udata(offset) => {
                            low_pc = Some(offset + text_base_addr);
                        },
                        gimli::AttributeValue::Data4(offset) => {
                            low_pc = Some(offset as u64 + text_base_addr);
                        },
                        gimli::AttributeValue::Data8(offset) => {
                            low_pc = Some(offset + text_base_addr);
                        },
                        gimli::AttributeValue::DebugAddrIndex(index) => {
                            // DWARF5のアドレスインデックスを解決
                            if let Ok(resolved_addr) = get_addr_from_index::<R>(index, debug_buffer, debug_sections) {
                                low_pc = Some(resolved_addr);
                            }
                        },
                        _ => {}
                    }
                } else if attr.name() == gimli::DW_AT_high_pc && (is_compile_unit || is_subprogram) {
                    high_pc_value = Some(attr.value());
                    high_pc_attr_name = Some(attr.name());
                } else if attr.name() == gimli::DW_AT_ranges && (is_compile_unit || is_subprogram) {
                    ranges_attr = Some(attr.value());
                } else if attr.name() == gimli::DW_AT_name {
                    // 名前属性を記録（すべてのタグで）
                    if dwarf_version >= 5 {
                        if let Ok(val_str) = dwarf_attr_to_string_with_dwarf5(attr.value(), &debug_str, &debug_str_offsets, &debug_addr, &debug_line_str, &unit, debug_buffer, debug_sections, &debug_info, &debug_abbrev) {
                            name_attr = Some(val_str);
                        }
                    } else {
                        if let Ok(val_str) = dwarf_attr_to_string_with_unit_resolution(attr.value(), &debug_str, &debug_info, &debug_abbrev) {
                            name_attr = Some(val_str);
                        }
                    }
                } else if attr.name() == gimli::DW_AT_type {
                    // 型属性を記録（変数、パラメータ、typedefなどで）
                    if dwarf_version >= 5 {
                        if let Ok(val_str) = dwarf_attr_to_string_with_dwarf5(attr.value(), &debug_str, &debug_str_offsets, &debug_addr, &debug_line_str, &unit, debug_buffer, debug_sections, &debug_info, &debug_abbrev) {
                            type_attr = Some(val_str);
                        }
                    } else {
                        if let Ok(val_str) = dwarf_attr_to_string_with_unit_resolution(attr.value(), &debug_str, &debug_info, &debug_abbrev) {
                            type_attr = Some(val_str);
                        }
                    }
                }

                // DW_AT_high_pcは後で特別処理するのでここではスキップ
                if !(is_compile_unit && attr.name() == gimli::DW_AT_high_pc) {
                    print!("        ATTR: {} ", attr_name);
                    // DWARF5の場合は新しい文字列抽出機能を使用
                    if dwarf_version >= 5 {
                        if let Ok(val_str) = dwarf_attr_to_string_with_dwarf5(attr.value(), &debug_str, &debug_str_offsets, &debug_addr, &debug_line_str, &unit, debug_buffer, debug_sections, &debug_info, &debug_abbrev) {
                            println!("({})", val_str);
                        } else if let Ok(val_str) = dwarf_attr_to_string_with_unit_resolution(attr.value(), &debug_str, &debug_info, &debug_abbrev) {
                            println!("({})", val_str);
                        } else if let Ok(val_str) = dwarf_attr_to_string_with_context_and_base(attr.name(), attr.value(), &debug_str, text_base_addr) {
                            println!("({})", val_str);
                        } else {
                            println!("(unhandled format)");
                        }
                    } else {
                        // DWARF4以前の処理
                        if let Ok(val_str) = dwarf_attr_to_string_with_unit_resolution(attr.value(), &debug_str, &debug_info, &debug_abbrev) {
                            println!("({})", val_str);
                        } else if let Ok(val_str) = dwarf_attr_to_string_with_context_and_base(attr.name(), attr.value(), &debug_str, text_base_addr) {
                            println!("({})", val_str);
                        } else {
                            println!("(unhandled format)");
                        }
                    }
                }
            }

            // タグ別の特別な処理と追加情報表示
            if is_compile_unit {
                if let (Some(low), Some(high_val), Some(_)) = (low_pc, high_pc_value, high_pc_attr_name) {
                    match high_val {
                        gimli::AttributeValue::Addr(addr) => {
                            println!("        ATTR: DW_AT_high_pc (0x{:x} - 絶対アドレス)", addr);
                        },
                        gimli::AttributeValue::Udata(offset) => {
                            let high_addr = low + offset;
                            println!("        ATTR: DW_AT_high_pc (0x{:x} - low_pc + 0x{:x})", high_addr, offset);
                        },
                        gimli::AttributeValue::Data4(offset) => {
                            let high_addr = low + offset as u64;
                            println!("        ATTR: DW_AT_high_pc (0x{:x} - low_pc + 0x{:x})", high_addr, offset);
                        },
                        gimli::AttributeValue::Data8(offset) => {
                            let high_addr = low + offset;
                            println!("        ATTR: DW_AT_high_pc (0x{:x} - low_pc + 0x{:x})", high_addr, offset);
                        },
                        _ => {
                            if let Ok(val_str) = dwarf_attr_to_string_with_context_and_base(gimli::DW_AT_high_pc, high_val, &debug_str, text_base_addr) {
                                println!("        ATTR: DW_AT_high_pc ({})", val_str);
                            }
                        }
                    }
                } else if let Some(low) = low_pc {
                    // DW_AT_high_pcが存在しない場合の詳細情報（DWARF5でよくある）
                    println!("        INFO: DW_AT_high_pc属性が存在しません (low_pc=0x{:x})", low);
                    if dwarf_version >= 5 {
                        println!("        INFO: DWARF5では DW_AT_ranges 属性でアドレス範囲を定義することが一般的です");
                    } else {
                        println!("        INFO: DWARF{}でDW_AT_high_pcが欠如しています - 不完全なデバッグ情報の可能性", dwarf_version);
                    }
                }
                
                // DW_AT_ranges属性の情報表示
                if let Some(ranges_val) = ranges_attr {
                    match ranges_val {
                        gimli::AttributeValue::RangeListsRef(offset) => {
                            println!("        INFO: DW_AT_ranges属性が存在します (offset: 0x{:x}) - __debug_ranges/__debug_rnglists参照", offset.0.into_u64());
                        },
                        gimli::AttributeValue::SecOffset(offset) => {
                            println!("        INFO: DW_AT_ranges属性が存在します (sec_offset: 0x{:x}) - __debug_ranges参照", offset.into_u64());
                        },
                        _ => {
                            if let Ok(val_str) = dwarf_attr_to_string_with_context_and_base(gimli::DW_AT_ranges, ranges_val, &debug_str, text_base_addr) {
                                println!("        INFO: DW_AT_ranges属性が存在します ({})", val_str);
                            }
                        }
                    }
                }
            } else if is_subprogram {
                // DW_TAG_subprogram（関数）の特別処理
                if let Some(name) = &name_attr {
                    println!("        関数名: {}", name);
                }
                if let (Some(low), Some(high_val), Some(_)) = (low_pc, high_pc_value, high_pc_attr_name) {
                    match high_val {
                        gimli::AttributeValue::Addr(addr) => {
                            println!("        関数範囲: 0x{:x} - 0x{:x} (サイズ: {} バイト)", low, addr, addr - low);
                        },
                        gimli::AttributeValue::Udata(offset) => {
                            let high_addr = low + offset;
                            println!("        関数範囲: 0x{:x} - 0x{:x} (サイズ: {} バイト)", low, high_addr, offset);
                        },
                        gimli::AttributeValue::Data4(offset) => {
                            let high_addr = low + offset as u64;
                            println!("        関数範囲: 0x{:x} - 0x{:x} (サイズ: {} バイト)", low, high_addr, offset);
                        },
                        _ => {}
                    }
                }
            } else if is_variable {
                // DW_TAG_variable（変数）の特別処理
                if let Some(name) = &name_attr {
                    if let Some(type_info) = &type_attr {
                        println!("        変数: {} (型: {})", name, type_info);
                    } else {
                        println!("        変数: {}", name);
                    }
                }
            } else if is_formal_parameter {
                // DW_TAG_formal_parameter（関数パラメータ）の特別処理
                if let Some(name) = &name_attr {
                    if let Some(type_info) = &type_attr {
                        println!("        パラメータ: {} (型: {})", name, type_info);
                    } else {
                        println!("        パラメータ: {}", name);
                    }
                }
            } else if is_typedef {
                // DW_TAG_typedef（型定義）の特別処理
                if let Some(name) = &name_attr {
                    if let Some(type_info) = &type_attr {
                        println!("        型定義: {} = {}", name, type_info);
                    } else {
                        println!("        型定義: {}", name);
                    }
                }
            } else if is_structure_type || is_class_type {
                // DW_TAG_structure_type / DW_TAG_class_type（構造体/クラス）の特別処理
                let type_name = if is_structure_type { "構造体" } else { "クラス" };
                if let Some(name) = &name_attr {
                    println!("        {}: {}", type_name, name);
                } else {
                    println!("        {} (無名)", type_name);
                }
            }
            
            // DWARF5特有の属性情報を表示
            if dwarf_version >= 5 {
                if name_attr.is_some() || type_attr.is_some() {
                    println!("        [DWARF5 文字列抽出機能適用済み]");
                }
            }
        }
    }
    Ok(())
}

// DWARF5文字列オフセットテーブルの独自実装構造体
#[derive(Debug)]
struct CustomStrOffsetsTable {
    unit_length: u32,
    version: u16,
    padding: u16,
    offsets: Vec<u32>,
}

impl CustomStrOffsetsTable {
    // __debug_str_offs__DWARFセクションから独自パース
    fn parse_from_section(section_data: &[u8]) -> Result<Self, String> {
        if section_data.len() < 8 {
            return Err("セクションサイズが小さすぎます".to_string());
        }
        
        // ヘッダー解析
        let unit_length = u32::from_le_bytes([
            section_data[0], section_data[1], section_data[2], section_data[3]
        ]);
        let version = u16::from_le_bytes([section_data[4], section_data[5]]);
        let padding = u16::from_le_bytes([section_data[6], section_data[7]]);
        
        // オフセットテーブル解析（8バイト以降）
        let mut offsets = Vec::new();
        let offset_data = &section_data[8..];
        
        for chunk in offset_data.chunks(4) {
            if chunk.len() == 4 {
                let offset = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                offsets.push(offset);
            }
        }
        
        Ok(CustomStrOffsetsTable {
            unit_length,
            version,
            padding,
            offsets,
        })
    }
    
    // インデックスから文字列オフセットを取得
    fn get_string_offset(&self, index: usize) -> Option<u32> {
        self.offsets.get(index).copied()
    }
}

// DWARF5行番号情報の独自解決関数
fn try_resolve_debug_line_with_data<R: Reader>(
    line_ref: gimli::DebugLineOffset<R::Offset>,
    debug_buffer: &[u8],
    debug_sections: &HashMap<String, SectionInfo>,
) -> Result<String, String> {
    let offset_value = line_ref.0.into_u64() as usize;
    
    // __debug_lineセクションを取得
    let line_section = match find_section_by_name(debug_sections, "__debug_line") {
        Some(section) => section,
        None => return Err("__debug_lineセクションが見つかりません".to_string()),
    };
    
    // セクションデータを抽出（オフセット検証付き）
    let start_offset = line_section.offset as usize;
    let section_size = line_section.size as usize;
    
    // DWARF5オフセット検証: デバッグ情報を追加
    if start_offset >= debug_buffer.len() || section_size == 0 {
        return Err(format!("セクションデータが無効です (offset: 0x{:x}, size: {}, buffer_len: {})", 
                          start_offset, section_size, debug_buffer.len()));
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, debug_buffer.len());
    let section_data = &debug_buffer[start_offset..actual_end];
    
    // DWARF5オフセット検証: セクションデータの整合性をチェック
    if section_data.len() != section_size && actual_end == debug_buffer.len() {
        eprintln!("⚠️  __debug_lineセクションが切り詰められました: 期待サイズ={}, 実際サイズ={}", 
                 section_size, section_data.len());
    }
    
    // 指定されたオフセットが有効範囲内かチェック
    if offset_value >= section_data.len() {
        return Err(format!("オフセット0x{:x}が範囲外です (セクションサイズ: {})", offset_value, section_data.len()));
    }
    
    // DWARF5の行番号テーブルヘッダーを簡易解析
    let header_data = &section_data[offset_value..];
    if header_data.len() < 12 {
        return Err("行番号テーブルヘッダーが不完全です".to_string());
    }
    
    // 行番号テーブルの長さ（最初の4バイト）
    let unit_length = u32::from_le_bytes([header_data[0], header_data[1], header_data[2], header_data[3]]);
    
    // DWARF形式（次の2バイト）
    let version = u16::from_le_bytes([header_data[4], header_data[5]]);
    
    // ヘッダー長（次の4バイト、DWARF5では8バイト）
    let header_length = if version >= 5 {
        // DWARF5では8バイトのヘッダー長
        if header_data.len() < 16 {
            return Err("DWARF5行番号ヘッダーが不完全です".to_string());
        }
        u64::from_le_bytes([
            header_data[6], header_data[7], header_data[8], header_data[9],
            header_data[10], header_data[11], header_data[12], header_data[13]
        ])
    } else {
        u32::from_le_bytes([header_data[6], header_data[7], header_data[8], header_data[9]]) as u64
    };
    
    Ok(format!("0x{:x} (.debug_line: unit_length={}, version={}, header_length={})", 
              offset_value, unit_length, version, header_length))
}

// DWARF5アドレスインデックスの独自解決関数
fn try_resolve_addr_index_with_data<R: Reader>(
    index: gimli::DebugAddrIndex<R::Offset>,
    _unit: &gimli::UnitHeader<R>,
    debug_buffer: &[u8],
    debug_sections: &HashMap<String, SectionInfo>,
) -> Result<String, String> {
    let index_value = index.0.into_u64() as usize;
    
    // __debug_addrセクションを取得
    let addr_section = match find_section_by_name(debug_sections, "__debug_addr") {
        Some(section) => section,
        None => return Err("__debug_addrセクションが見つかりません".to_string()),
    };
    
    // セクションデータを抽出（オフセット検証付き）
    let start_offset = addr_section.offset as usize;
    let section_size = addr_section.size as usize;
    
    // DWARF5オフセット検証: デバッグ情報を追加
    if start_offset >= debug_buffer.len() || section_size == 0 {
        return Err(format!("セクションデータが無効です (offset: 0x{:x}, size: {}, buffer_len: {})", 
                          start_offset, section_size, debug_buffer.len()));
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, debug_buffer.len());
    let section_data = &debug_buffer[start_offset..actual_end];
    
    // DWARF5オフセット検証: セクションデータの整合性をチェック
    if section_data.len() != section_size && actual_end == debug_buffer.len() {
        eprintln!("⚠️  __debug_addrセクションが切り詰められました: 期待サイズ={}, 実際サイズ={}", 
                 section_size, section_data.len());
    }
    
    // DWARF5デバッグ情報: セクション情報を表示（初回のみ）
    static mut ADDR_SECTION_INFO_SHOWN: bool = false;
    unsafe {
        if !ADDR_SECTION_INFO_SHOWN {
            eprintln!("🔍 __debug_addrセクション情報: offset=0x{:x}, size={}, 利用可能アドレス数={}", 
                     start_offset, section_size, section_data.len() / 8);
            ADDR_SECTION_INFO_SHOWN = true;
        }
    }
    
    // アドレステーブルから指定されたインデックスのアドレスを取得
    // DWARF5のアドレステーブルは通常8バイトのアドレスエントリの配列
    let address_size = 8; // 64ビットアドレス
    let required_offset = index_value * address_size;
    
    // DWARF5オフセット検証: アドレス計算の詳細チェック
    if required_offset + address_size > section_data.len() {
        return Err(format!("インデックス{}が範囲外です (required_offset: 0x{:x}, address_size: {}, section_size: {})", 
                          index_value, required_offset, address_size, section_data.len()));
    }
    
    // DWARF5オフセット検証: アドレステーブルの構造チェック
    if section_data.len() % address_size != 0 {
        eprintln!("⚠️  __debug_addrセクションサイズがアドレスサイズの倍数ではありません: {} % {} = {}", 
                 section_data.len(), address_size, section_data.len() % address_size);
    }
    
    // 8バイトのアドレス値を読み取り（リトルエンディアン）
    let mut addr_bytes = [0u8; 8];
    addr_bytes.copy_from_slice(&section_data[required_offset..required_offset + address_size]);
    let address = u64::from_le_bytes(addr_bytes);
    
    Ok(format!("0x{:x}", address))
}

// UnitRef参照解決関数
fn resolve_unit_ref<R: Reader>(
    unit_ref: gimli::UnitOffset<R::Offset>,
    debug_info: &DebugInfo<R>,
    debug_abbrev: &DebugAbbrev<R>,
    debug_str: &DebugStr<R>,
) -> Result<String, Box<dyn Error>> {
    // 現在のユニットを取得
    let mut units = debug_info.units();
    while let Some(unit) = units.next()? {
        let abbrevs = unit.abbreviations(debug_abbrev)?;
        
        // 指定されたオフセットのエントリを検索
        let mut entries = unit.entries(&abbrevs);
        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.offset() == unit_ref {
                // 参照先のDIEを見つけた
                let tag_name = get_die_tag_name(entry.tag().0 as u64, unit.version());
                
                // 名前属性を取得
                let mut name = None;
                let mut type_name = None;
                
                let mut attrs = entry.attrs();
                while let Some(attr) = attrs.next()? {
                    if attr.name() == gimli::DW_AT_name {
                        match attr.value() {
                            gimli::AttributeValue::String(s) => {
                                name = Some(s.to_string_lossy()?.into_owned());
                            },
                            gimli::AttributeValue::DebugStrRef(offset) => {
                                if let Ok(s) = debug_str.get_str(offset) {
                                    name = Some(s.to_string_lossy()?.into_owned());
                                }
                            },
                            _ => {}
                        }
                    } else if attr.name() == gimli::DW_AT_type {
                        type_name = Some(format!("{:?}", attr.value()));
                    }
                }
                
                // 結果を構築
                let mut result = format!("{}", tag_name);
                if let Some(n) = name {
                    result.push_str(&format!(" \"{}\"", n));
                }
                if let Some(t) = type_name {
                    result.push_str(&format!(" (type: {})", t));
                }
                
                return Ok(result);
            }
        }
    }
    
    Err("参照先のDIEが見つかりません".into())
}

// DWARF5アドレスインデックスから実際のアドレス値を取得する関数
fn get_addr_from_index<R: Reader>(
    index: gimli::DebugAddrIndex<R::Offset>,
    debug_buffer: &[u8],
    debug_sections: &HashMap<String, SectionInfo>,
) -> Result<u64, String> {
    let index_value = index.0.into_u64() as usize;
    
    // __debug_addrセクションを取得
    let addr_section = match find_section_by_name(debug_sections, "__debug_addr") {
        Some(section) => section,
        None => return Err("__debug_addrセクションが見つかりません".to_string()),
    };
    
    // セクションデータを抽出
    let start_offset = addr_section.offset as usize;
    let section_size = addr_section.size as usize;
    
    if start_offset >= debug_buffer.len() || section_size == 0 {
        return Err(format!("セクションデータが無効です (offset: 0x{:x}, size: {}, buffer_len: {})", 
                          start_offset, section_size, debug_buffer.len()));
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, debug_buffer.len());
    let section_data = &debug_buffer[start_offset..actual_end];
    
    // アドレステーブルから指定されたインデックスのアドレスを取得
    let address_size = 8; // 64ビットアドレス
    let required_offset = index_value * address_size;
    
    if required_offset + address_size > section_data.len() {
        return Err(format!("インデックス{}が範囲外です", index_value));
    }
    
    // 8バイトのアドレス値を読み取り（リトルエンディアン）
    let mut addr_bytes = [0u8; 8];
    addr_bytes.copy_from_slice(&section_data[required_offset..required_offset + address_size]);
    let address = u64::from_le_bytes(addr_bytes);
    
    Ok(address)
}

// DWARF5文字列オフセットインデックスの独自解決関数
fn try_resolve_str_offsets_index_with_data<R: Reader>(
    debug_str: &DebugStr<R>,
    index: gimli::DebugStrOffsetsIndex<R::Offset>,
    _unit: &gimli::UnitHeader<R>,
    debug_buffer: &[u8],
    debug_sections: &HashMap<String, SectionInfo>,
) -> Result<String, String> {
    // 独自実装による文字列インデックス解決
    let index_value = index.0.into_u64() as usize;
    
    // __debug_str_offs__DWARFセクションを取得
    let str_offsets_section = match find_section_by_name(debug_sections, "__debug_str_offs__DWARF") {
        Some(section) => section,
        None => return Err("__debug_str_offs__DWARFセクションが見つかりません".to_string()),
    };
    
    // セクションデータを抽出（オフセット検証付き）
    let start_offset = str_offsets_section.offset as usize;
    let section_size = str_offsets_section.size as usize;
    
    // DWARF5オフセット検証: デバッグ情報を追加
    if start_offset >= debug_buffer.len() || section_size == 0 {
        return Err(format!("セクションデータが無効です (offset: 0x{:x}, size: {}, buffer_len: {})", 
                          start_offset, section_size, debug_buffer.len()));
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, debug_buffer.len());
    let section_data = &debug_buffer[start_offset..actual_end];
    
    // DWARF5オフセット検証: セクションデータの整合性をチェック
    if section_data.len() != section_size && actual_end == debug_buffer.len() {
        eprintln!("⚠️  __debug_str_offs__DWARFセクションが切り詰められました: 期待サイズ={}, 実際サイズ={}", 
                 section_size, section_data.len());
    }
    
    // DWARF5デバッグ情報: セクション情報を表示（初回のみ）
    static mut STR_OFFSETS_SECTION_INFO_SHOWN: bool = false;
    unsafe {
        if !STR_OFFSETS_SECTION_INFO_SHOWN {
            eprintln!("🔍 __debug_str_offs__DWARFセクション情報: offset=0x{:x}, size={}", 
                     start_offset, section_size);
            STR_OFFSETS_SECTION_INFO_SHOWN = true;
        }
    }
    
    // 独自実装でオフセットテーブルをパース
    let str_offsets_table = match CustomStrOffsetsTable::parse_from_section(section_data) {
        Ok(table) => table,
        Err(e) => return Err(format!("オフセットテーブル解析失敗: {}", e)),
    };
    
    // インデックスから文字列オフセットを取得
    let string_offset = match str_offsets_table.get_string_offset(index_value) {
        Some(offset) => offset,
        None => return Err(format!("インデックス{}が範囲外です (最大: {})", index_value, str_offsets_table.offsets.len())),
    };
    
    // 文字列オフセットから実際の文字列を取得
    // gimliの型システムに合わせてオフセットを作成
    let str_offset = gimli::DebugStrOffset(R::Offset::from_u64(string_offset as u64).map_err(|_| "オフセット変換失敗")?);
    match debug_str.get_str(str_offset) {
        Ok(s) => {
            match s.to_string_lossy() {
                Ok(owned_string) => Ok(format!("{:?}", owned_string.into_owned())),
                Err(_) => Err(format!("文字列変換失敗 (offset: 0x{:x})", string_offset)),
            }
        },
        Err(_) => Err(format!("文字列取得失敗 (offset: 0x{:x})", string_offset)),
    }
}

// 後方互換性のための関数（現在は使用されない）
fn try_resolve_str_offsets_index<R: Reader>(
    _debug_str_offsets: &gimli::DebugStrOffsets<R>,
    _debug_str: &DebugStr<R>,
    index: gimli::DebugStrOffsetsIndex<R::Offset>,
    unit: &gimli::UnitHeader<R>,
) -> Result<String, String> {
    let format_info = format!("{:?}", unit.format());
    let version_info = unit.version();
    let index_value = index.0.into_u64() as usize;
    
    Err(format!("独自実装準備完了 (DWARF{}, format: {}, index: {}) - セクションデータが必要", 
               version_info, format_info, index_value))
}

// ユニット参照を解決する関数（具体的表示版）



// DWARF5の文字列抽出を行う関数（実用版）
fn dwarf_attr_to_string_with_dwarf5<R: Reader>(
    val: gimli::AttributeValue<R>,
    debug_str: &DebugStr<R>,
    _debug_str_offsets: &gimli::DebugStrOffsets<R>,
    _debug_addr: &gimli::DebugAddr<R>,
    debug_line_str: &gimli::DebugLineStr<R>,
    _unit: &gimli::UnitHeader<R>,
    debug_buffer: &[u8],
    debug_sections: &HashMap<String, SectionInfo>,
    debug_info: &DebugInfo<R>,
    debug_abbrev: &DebugAbbrev<R>,
) -> Result<String, Box<dyn Error>> {
    match val {
        gimli::AttributeValue::DebugStrOffsetsIndex(index) => {
            // DWARF5の文字列オフセットインデックス - 独自実装で解決
            match try_resolve_str_offsets_index_with_data(debug_str, index, _unit, debug_buffer, debug_sections) {
                Ok(resolved_string) => Ok(resolved_string),
                Err(err_msg) => Ok(format!("str_offsets_index[{:?}] (DWARF5文字列インデックス - __debug_str_offs__DWARF解決: {})", 
                                          index.0, err_msg))
            }
        },
        gimli::AttributeValue::DebugAddrIndex(index) => {
            // DWARF5のアドレスインデックス - 独自実装で解決
            match try_resolve_addr_index_with_data(index, _unit, debug_buffer, debug_sections) {
                Ok(resolved_addr) => Ok(resolved_addr),
                Err(err_msg) => Ok(format!("addr_index[{:?}] (DWARF5アドレスインデックス - __debug_addr解決: {})", index.0, err_msg))
            }
        },
        gimli::AttributeValue::DebugLineRef(line_ref) => {
            // DWARF5の行番号情報 - 独自実装で解決
            match try_resolve_debug_line_with_data::<R>(line_ref, debug_buffer, debug_sections) {
                Ok(resolved_info) => Ok(resolved_info),
                Err(err_msg) => Ok(format!("line_ref: 0x{:x} (__debug_line解決: {})", line_ref.0.into_u64(), err_msg))
            }
        },
        gimli::AttributeValue::DebugLineStrRef(offset) => {
            // .debug_line_strセクションから文字列を取得
            match debug_line_str.get_str(offset) {
                Ok(s) => Ok(format!("{:?}", s.to_string_lossy()?.into_owned())),
                Err(_) => Ok(format!("line_str_ref[0x{:x}] (文字列取得失敗)", offset.0.into_u64()))
            }
        },
        gimli::AttributeValue::UnitRef(unit_ref) => {
            // DWARF5でも実際の参照解決を実行
            match resolve_unit_ref(unit_ref, debug_info, debug_abbrev, debug_str) {
                Ok(resolved) => Ok(resolved),
                Err(_) => Ok(format!("unit_ref: UnitOffset(0x{:x}) -> [DWARF5参照解決失敗]", unit_ref.0.into_u64()))
            }
        },
        _ => dwarf_attr_to_string(val, debug_str)
    }
}

// ユニット参照を解決できるバージョンの属性値文字列化関数
fn dwarf_attr_to_string_with_unit_resolution<R: Reader>(
    val: gimli::AttributeValue<R>,
    debug_str: &DebugStr<R>,
    debug_info: &DebugInfo<R>,
    debug_abbrev: &DebugAbbrev<R>,
) -> Result<String, Box<dyn Error>> {
    let s = match val {
        gimli::AttributeValue::String(s) => format!("{:?}", s.to_string_lossy()?.into_owned()),
        gimli::AttributeValue::DebugStrRef(offset) => {
            format!("{:?}", debug_str.get_str(offset)?.to_string_lossy()?.into_owned())
        }
        gimli::AttributeValue::Udata(u) => format!("{}", u),
        gimli::AttributeValue::Sdata(s) => format!("{}", s),
        gimli::AttributeValue::Data1(d) => format!("0x{:x}", d),
        gimli::AttributeValue::Data2(d) => format!("0x{:x}", d),
        gimli::AttributeValue::Data4(d) => format!("0x{:x}", d),
        gimli::AttributeValue::Data8(d) => format!("0x{:x}", d),
        gimli::AttributeValue::Addr(addr) => format!("0x{:x}", addr),
        gimli::AttributeValue::Flag(f) => format!("{}", f),
        gimli::AttributeValue::Language(lang) => {
            let lang_code = lang.0 as u64;
            format!("{} - {}", get_language_name(lang_code), get_language_description(lang_code))
        },
        gimli::AttributeValue::UnitRef(unit_ref) => {
            // 実際にユニット参照を解決
            match resolve_unit_ref(unit_ref, debug_info, debug_abbrev, debug_str) {
                Ok(resolved) => resolved,
                Err(_) => format!("unit_ref: UnitOffset(0x{:x}) -> [解決エラー]", unit_ref.0.into_u64())
            }
        },
        gimli::AttributeValue::DebugInfoRef(debug_info_ref) => format!("debug_info_ref: {:?}", debug_info_ref),
        gimli::AttributeValue::SecOffset(offset) => format!("sec_offset: {:?}", offset),
        gimli::AttributeValue::Exprloc(expr) => {
            let slice = expr.0.to_slice()?;
            format!("exprloc: {} bytes", slice.len())
        },
        gimli::AttributeValue::Block(block) => {
            let slice = block.to_slice()?;
            format!("block: {} bytes", slice.len())
        },
        _ => "<unhandled>".to_string(),
    };
    Ok(s)
}

fn dwarf_attr_to_string<R: Reader>(
    val: gimli::AttributeValue<R>,
    debug_str: &DebugStr<R>,
) -> Result<String, Box<dyn Error>> {
    let s = match val {
        gimli::AttributeValue::String(s) => format!("{:?}", s.to_string_lossy()?.into_owned()),
        gimli::AttributeValue::DebugStrRef(offset) => {
            format!("{:?}", debug_str.get_str(offset)?.to_string_lossy()?.into_owned())
        }
        // DWARF5の新しい文字列フォーム対応
        gimli::AttributeValue::DebugStrOffsetsIndex(index) => {
            // str_offsets_indexの場合、可能であれば実際の文字列を取得を試行
            // 失敗した場合はインデックス情報を表示
            format!("str_offsets_index[{:?}] (DWARF5 - 文字列解決には__debug_str_offs__DWARFが必要)", index.0)
        }
        gimli::AttributeValue::DebugLineStrRef(offset) => {
            // .debug_line_strセクションへの参照
            format!("line_str_ref[0x{:x}] (DWARF5 line string)", offset.0.into_u64())
        }
        gimli::AttributeValue::Udata(u) => format!("{}", u),
        gimli::AttributeValue::Sdata(s) => format!("{}", s),
        gimli::AttributeValue::Data1(d) => format!("0x{:x}", d),
        gimli::AttributeValue::Data2(d) => format!("0x{:x}", d),
        gimli::AttributeValue::Data4(d) => format!("0x{:x}", d),
        gimli::AttributeValue::Data8(d) => format!("0x{:x}", d),
        gimli::AttributeValue::Addr(addr) => format!("0x{:x}", addr),
        gimli::AttributeValue::Flag(f) => format!("{}", f),
        gimli::AttributeValue::Language(lang) => {
            let lang_code = lang.0 as u64;
            format!("{} - {}", get_language_name(lang_code), get_language_description(lang_code))
        },
        gimli::AttributeValue::UnitRef(unit_ref) => {
            format!("unit_ref: UnitOffset(0x{:x}) -> [参照解決は dwarf_attr_to_string_with_unit_resolution で実装済み]", unit_ref.0.into_u64())
        },
        gimli::AttributeValue::DebugInfoRef(debug_info_ref) => format!("debug_info_ref: {:?}", debug_info_ref),
        gimli::AttributeValue::SecOffset(offset) => format!("sec_offset: {:?}", offset),
        gimli::AttributeValue::Exprloc(expr) => {
            let slice = expr.0.to_slice()?;
            format!("exprloc: {} bytes", slice.len())
        },
        gimli::AttributeValue::Block(block) => {
            let slice = block.to_slice()?;
            format!("block: {} bytes", slice.len())
        },
        // DWARF5の追加フォーム対応
        gimli::AttributeValue::DebugAddrIndex(index) => {
            format!("addr_index[{:?}] (DWARF5 address index)", index.0)
        },
        gimli::AttributeValue::DebugLocListsIndex(index) => {
            format!("loclists_index[{:?}] (DWARF5 location list index)", index.0)
        },
        gimli::AttributeValue::DebugRngListsIndex(index) => {
            format!("rnglists_index[{:?}] (DWARF5 range list index)", index.0)
        },
        gimli::AttributeValue::DebugTypesRef(type_ref) => {
            format!("types_ref: 0x{:x} (DWARF4 type reference)", type_ref.0.into_u64())
        },
        gimli::AttributeValue::DebugMacinfoRef(macinfo_ref) => {
            format!("macinfo_ref: 0x{:x} (macro info reference)", macinfo_ref.0.into_u64())
        },
        gimli::AttributeValue::DebugMacroRef(macro_ref) => {
            format!("macro_ref: 0x{:x} (DWARF5 macro reference)", macro_ref.0.into_u64())
        },
        gimli::AttributeValue::RangeListsRef(ranges_ref) => {
            format!("ranges_ref: 0x{:x} (range list reference)", ranges_ref.0.into_u64())
        },
        gimli::AttributeValue::LocationListsRef(loc_ref) => {
            format!("loc_ref: 0x{:x} (location list reference)", loc_ref.0.into_u64())
        },
        gimli::AttributeValue::Encoding(encoding) => {
            format!("encoding: 0x{:x}", encoding.0)
        },
        gimli::AttributeValue::DecimalSign(sign) => {
            format!("decimal_sign: 0x{:x}", sign.0)
        },
        gimli::AttributeValue::Endianity(endian) => {
            format!("endianity: 0x{:x}", endian.0)
        },
        gimli::AttributeValue::Accessibility(access) => {
            format!("accessibility: 0x{:x}", access.0)
        },
        gimli::AttributeValue::Visibility(vis) => {
            format!("visibility: 0x{:x}", vis.0)
        },
        gimli::AttributeValue::Virtuality(virt) => {
            format!("virtuality: 0x{:x}", virt.0)
        },
        gimli::AttributeValue::CallingConvention(cc) => {
            format!("calling_convention: 0x{:x}", cc.0)
        },
        gimli::AttributeValue::Inline(inline_val) => {
            format!("inline: 0x{:x}", inline_val.0)
        },
        gimli::AttributeValue::Ordering(order) => {
            format!("ordering: 0x{:x}", order.0)
        },
        gimli::AttributeValue::FileIndex(file_idx) => {
            format!("file_index: {}", file_idx)
        },
        gimli::AttributeValue::DebugLineRef(line_ref) => {
            format!("0x{:x} (.debug_line section offset)", line_ref.0.into_u64())
        },
        _ => "<unhandled>".to_string(),
    };
    Ok(s)
}

fn dwarf_attr_to_string_with_context<R: Reader>(
    attr_name: gimli::DwAt,
    val: gimli::AttributeValue<R>,
    debug_str: &DebugStr<R>,
) -> Result<String, Box<dyn Error>> {
    dwarf_attr_to_string_with_context_and_base(attr_name, val, debug_str, 0)
}

fn dwarf_attr_to_string_with_context_and_base<R: Reader>(
    attr_name: gimli::DwAt,
    val: gimli::AttributeValue<R>,
    debug_str: &DebugStr<R>,
    text_base_addr: u64,
) -> Result<String, Box<dyn Error>> {
    // 特定の属性に対して特別な処理を行う
    let attr_code = attr_name.0 as u64;
    match attr_code {
        0x13 => { // DW_AT_language
            // 言語属性の場合は、値を言語コードとして解釈し、コンパイラ文字列も表示
            match val {
                gimli::AttributeValue::Language(lang) => {
                    let lang_code = lang.0 as u64;
                    Ok(format!("{} - {}", get_language_name(lang_code), get_language_description(lang_code)))
                },
                gimli::AttributeValue::Udata(u) => {
                    Ok(format!("{} - {}", get_language_name(u), get_language_description(u)))
                },
                gimli::AttributeValue::Data1(d) => {
                    let lang_code = d as u64;
                    Ok(format!("{} - {}", get_language_name(lang_code), get_language_description(lang_code)))
                },
                gimli::AttributeValue::Data2(d) => {
                    let lang_code = d as u64;
                    Ok(format!("{} - {}", get_language_name(lang_code), get_language_description(lang_code)))
                },
                gimli::AttributeValue::Data4(d) => {
                    let lang_code = d as u64;
                    Ok(format!("{} - {}", get_language_name(lang_code), get_language_description(lang_code)))
                },
                _ => dwarf_attr_to_string(val, debug_str),
            }
        },
        0x11 | 0x12 => { // DW_AT_high_pc (0x13) | DW_AT_low_pc (0x12)
            // アドレス属性の場合は、値をアドレスとして解釈
            match val {
                gimli::AttributeValue::Addr(addr) => {
                    let final_addr = if addr < 0x100000000 && text_base_addr > 0 {
                        addr + text_base_addr
                    } else {
                        addr
                    };
                    Ok(format!("0x{:x}", final_addr))
                },
                gimli::AttributeValue::Udata(u) => {
                    // DW_AT_high_pcの値が言語コードの範囲内にある場合の特別処理
                    if attr_code == 0x13 && u >= 0x01 && u <= 0x2f {
                        // 言語コードの範囲内の場合、警告を表示
                        Ok(format!("0x{:x} (警告: この値は言語コード {} のようです)", u, get_language_name(u)))
                    } else {
                        let final_addr = if attr_code == 0x12 && text_base_addr > 0 {
                            u + text_base_addr
                        } else if attr_code == 0x13 && text_base_addr > 0 {
                            // DW_AT_high_pcの場合、値が小さければオフセット、大きければ絶対アドレス
                            if u < 0x100000000 { u + text_base_addr } else { u }
                        } else {
                            u
                        };
                        Ok(format!("0x{:x}", final_addr))
                    }
                },
                gimli::AttributeValue::Data1(d) => {
                    let final_addr = if (attr_code == 0x12 || attr_code == 0x13) && text_base_addr > 0 {
                        d as u64 + text_base_addr
                    } else {
                        d as u64
                    };
                    Ok(format!("0x{:x}", final_addr))
                },
                gimli::AttributeValue::Data2(d) => {
                    let final_addr = if (attr_code == 0x12 || attr_code == 0x13) && text_base_addr > 0 {
                        d as u64 + text_base_addr
                    } else {
                        d as u64
                    };
                    Ok(format!("0x{:x}", final_addr))
                },
                gimli::AttributeValue::Data4(d) => {
                    let final_addr = if (attr_code == 0x12 || attr_code == 0x13) && text_base_addr > 0 {
                        d as u64 + text_base_addr
                    } else {
                        d as u64
                    };
                    Ok(format!("0x{:x}", final_addr))
                },
                gimli::AttributeValue::Data8(d) => {
                    let final_addr = if (attr_code == 0x12 || attr_code == 0x13) && text_base_addr > 0 {
                        d + text_base_addr
                    } else {
                        d
                    };
                    Ok(format!("0x{:x}", final_addr))
                },
                gimli::AttributeValue::DebugAddrIndex(addr_index) => {
                    // DWARF 5のアドレスインデックス形式 - 独自実装で解決
                    // コンテキスト関数では簡易的な処理を行う
                    Ok(format!("addr_index[{:?}] (DWARF5アドレスインデックス)", addr_index.0))
                },
                gimli::AttributeValue::DebugLineRef(line_ref) => {
                    // DW_AT_stmt_listなどの行番号情報参照 - 実際の値を16進数で表示
                    Ok(format!("0x{:x} (.debug_line section offset)", line_ref.0.into_u64()))
                },
                gimli::AttributeValue::Language(lang) => {
                    // 誤って言語として解釈された場合、生の値を取得
                    Ok(format!("0x{:x}", lang.0 as u64))
                },
                _ => dwarf_attr_to_string(val, debug_str)
            }
        },
        // DWARF 5の新しい属性
        0x69 => { // DW_AT_str_offsets_base
            match val {
                gimli::AttributeValue::SecOffset(_) => Ok(format!("str_offsets_base: <sec_offset>")),
                gimli::AttributeValue::Udata(u) => Ok(format!("str_offsets_base: 0x{:x}", u)),
                _ => dwarf_attr_to_string(val, debug_str),
            }
        },
        0x6a => { // DW_AT_addr_base
            match val {
                gimli::AttributeValue::SecOffset(_) => Ok(format!("addr_base: <sec_offset>")),
                gimli::AttributeValue::Udata(u) => Ok(format!("addr_base: 0x{:x}", u)),
                _ => dwarf_attr_to_string(val, debug_str),
            }
        },
        0x6b => { // DW_AT_rnglists_base
            match val {
                gimli::AttributeValue::SecOffset(_) => Ok(format!("rnglists_base: <sec_offset>")),
                gimli::AttributeValue::Udata(u) => Ok(format!("rnglists_base: 0x{:x}", u)),
                _ => dwarf_attr_to_string(val, debug_str),
            }
        },
        0x82 => { // DW_AT_loclists_base
            match val {
                gimli::AttributeValue::SecOffset(_) => Ok(format!("loclists_base: <sec_offset>")),
                gimli::AttributeValue::Udata(u) => Ok(format!("loclists_base: 0x{:x}", u)),
                _ => dwarf_attr_to_string(val, debug_str),
            }
        },
        // DWARF 5の新しいフォーム処理
        _ => {
            match val {
                // DWARF 5の新しいフォーム
                gimli::AttributeValue::DebugStrOffsetsIndex(index) => {
                    Ok(format!("str_offsets_index[{:?}] (requires __debug_str_offs__DWARF)", index.0))
                },
                gimli::AttributeValue::DebugAddrIndex(index) => {
                    Ok(format!("addr_index[{:?}] (requires .debug_addr)", index.0))
                },
                gimli::AttributeValue::DebugLocListsIndex(index) => {
                    Ok(format!("loclists_index[{:?}] (requires .debug_loclists)", index.0))
                },
                gimli::AttributeValue::DebugRngListsIndex(index) => {
                    Ok(format!("rnglists_index[{:?}] (requires .debug_rnglists)", index.0))
                },
                _ => dwarf_attr_to_string(val, debug_str),
            }
        }
    }
}

fn display_debug_line_details_manual(buffer: &[u8], sections: &HashMap<String, SectionInfo>) {
    println!("\n=== __debug_line 詳細解析 ===");
    
    let debug_line_section = match find_section_by_name(sections, "__debug_line") {
        Some(section) => section,
        None => {
            println!("__debug_lineセクションが見つかりません");
            return;
        }
    };
    
    let start_offset = debug_line_section.offset as usize;
    let section_size = debug_line_section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("エラー: __debug_lineセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("セクションサイズ: {} バイト", section_data.len());
    
    let mut offset = 0;
    let mut unit_count = 0;
    
    while offset + 12 < section_data.len() && unit_count < 5 {
        unit_count += 1;
        println!("\n--- ライン番号プログラム {} ---", unit_count);
        
        // ヘッダーを解析
        let unit_length = u32::from_le_bytes([
            section_data[offset], section_data[offset + 1],
            section_data[offset + 2], section_data[offset + 3]
        ]);
        offset += 4;
        
        if unit_length == 0 || unit_length as usize > section_data.len() - offset {
            println!("  無効なユニット長: {}", unit_length);
            break;
        }
        
        let version = u16::from_le_bytes([
            section_data[offset], section_data[offset + 1]
        ]);
        offset += 2;
        
        // DWARF 5では新しいヘッダーフォーマット
        let (header_length, address_size, segment_selector_size) = if version >= 5 {
            let address_size = section_data[offset];
            offset += 1;
            let segment_selector_size = section_data[offset];
            offset += 1;
            let header_length = u32::from_le_bytes([
                section_data[offset], section_data[offset + 1],
                section_data[offset + 2], section_data[offset + 3]
            ]);
            offset += 4;
            (header_length, address_size, segment_selector_size)
        } else {
            let header_length = u32::from_le_bytes([
                section_data[offset], section_data[offset + 1],
                section_data[offset + 2], section_data[offset + 3]
            ]);
            offset += 4;
            (header_length, 8u8, 0u8) // デフォルト値
        };
        
        let min_instruction_length = section_data[offset];
        offset += 1;
        
        // DWARF 4以降では maximum_operations_per_instruction フィールドが追加
        let max_ops_per_instruction = if version >= 4 {
            let val = section_data[offset];
            offset += 1;
            val
        } else {
            1
        };
        
        let default_is_stmt = section_data[offset] != 0;
        offset += 1;
        
        let line_base = section_data[offset] as i8;
        offset += 1;
        
        let line_range = section_data[offset];
        offset += 1;
        
        let opcode_base = section_data[offset];
        offset += 1;
        
        println!("  ユニット長: {} バイト", unit_length);
        println!("  バージョン: {} (DWARF {})", version, version);
        if version >= 5 {
            println!("  アドレスサイズ: {} バイト", address_size);
            println!("  セグメントセレクタサイズ: {} バイト", segment_selector_size);
        }
        println!("  ヘッダー長: {} バイト", header_length);
        println!("  最小命令長: {}", min_instruction_length);
        if version >= 4 {
            println!("  命令あたり最大操作数: {}", max_ops_per_instruction);
        }
        println!("  デフォルトis_stmt: {}", default_is_stmt);
        println!("  行ベース: {}", line_base);
        println!("  行範囲: {}", line_range);
        println!("  オペコードベース: {}", opcode_base);
        
        // 標準オペコード長テーブルをスキップ
        for _ in 1..opcode_base {
            if offset >= section_data.len() {
                break;
            }
            offset += 1;
        }
        
        // ディレクトリテーブルを解析
        println!("\n  ディレクトリテーブル:");
        let mut dir_count = 0;
        while offset < section_data.len() && section_data[offset] != 0 && dir_count < 10 {
            let (dir_name, consumed) = extract_null_terminated_string(&section_data[offset..]);
            println!("    {}: {}", dir_count, dir_name);
            offset += consumed;
            dir_count += 1;
        }
        if offset < section_data.len() && section_data[offset] == 0 {
            offset += 1; // ディレクトリテーブル終端のnull
        }
        
        // ファイル名テーブルを解析（バージョン別）
        println!("\n  ファイル名テーブル:");
        let (_directories, file_names) = if version >= 5 {
            parse_dwarf5_file_table(section_data, &mut offset)
        } else {
            parse_dwarf2_4_file_table(section_data, &mut offset)
        };
        
        for (i, file_name) in file_names.iter().enumerate() {
            println!("    {}: {}", i + 1, file_name);
            if i >= 19 {
                println!("    ... (残りのファイルは省略)");
                break;
            }
        }
        
        // ライン番号プログラムを解析
        let program_start = offset;
        let program_end = std::cmp::min(start_offset + 4 + unit_length as usize, section_data.len());
        
        if program_start < program_end {
            let program_data = &section_data[program_start..program_end];
            println!("\n  ライン番号プログラム ({} バイト):", program_data.len());
            parse_line_number_program(program_data, &file_names, line_base, line_range, opcode_base);
        }
        
        // 次のユニットへ
        offset = start_offset + 4 + unit_length as usize - start_offset;
        if offset >= section_data.len() {
            break;
        }
    }
    
    if unit_count == 0 {
        println!("ライン番号プログラムが見つかりませんでした");
    }
}

fn read_uleb128(buf: &[u8]) -> (u64, usize) {
    let mut result = 0;
    let mut shift = 0;
    let mut i = 0;
    loop {
        if i >= buf.len() {
            return (result, i);
        }
        let byte = buf[i];
        i += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (result, i)
}

fn disassemble_text_section(buffer: &[u8], section: &SectionInfo, header: &mach_header_64) {
    println!("\n=== __TEXTセクション逆アセンブル ===");
    println!("仮想アドレス: 0x{:016x}", section.addr);
    println!("サイズ: {} バイト", section.size);
    println!("ファイルオフセット: 0x{:08x}", section.offset);
    
    // CPUアーキテクチャを判定
    let arch = CpuArchitecture::from_mach_cputype(header.cputype);
    println!("アーキテクチャ: {} - {}", arch.name(), arch.description());
    println!("CPUタイプ: {} (0x{:08x})", arch.cpu_type_name(), header.cputype as u32);
    println!("命令アライメント: {} バイト", arch.instruction_alignment());
    
    if !arch.has_disassembler() {
        println!("⚠️  未対応アーキテクチャです。逆アセンブルをスキップします。");
        return;
    }
    
    println!("{}", "=".repeat(80));

    let start_offset = section.offset as usize;
    let end_offset = start_offset + std::cmp::min(section.size as usize, 400); // 最初の400バイトまで

    if start_offset >= buffer.len() {
        println!("エラー: セクションオフセットがファイルサイズを超えています");
        return;
    }

    let actual_end = std::cmp::min(end_offset, buffer.len());
    let mut addr = section.addr;
    let mut i = start_offset;

    while i < actual_end {
        // CPUアーキテクチャに応じて適切な逆アセンブラを選択
        let (instruction, inst_len) = match arch {
            CpuArchitecture::X86_64 => {
                simple_disasm_x86_64(&buffer[i..actual_end], addr)
            },
            CpuArchitecture::ARM64 => {
                simple_disasm_arm64(&buffer[i..actual_end], addr)
            },
            CpuArchitecture::ARM32 => {
                simple_disasm_arm32(&buffer[i..actual_end], addr)
            },
            CpuArchitecture::Unknown(cputype) => {
                (format!("不明なアーキテクチャ: {} (cputype: 0x{:x}) - 逆アセンブル不可", arch.name(), cputype), arch.instruction_alignment())
            },
        };

        
        // アドレスと命令バイト・命令名を簡潔に表示（常に64ビット幅）
        print!("0x{:016x}: ", addr);
        let bytes_to_show = std::cmp::min(inst_len, std::cmp::min(6, actual_end - i));
        for j in 0..bytes_to_show {
            print!("{:02x} ", buffer[i + j]);
        }
        print!("  {}\n", instruction);
        
        // 命令の長さ分だけ進む
        addr += inst_len as u64;
        i += inst_len;
    }
    
    println!("{}", "=".repeat(80));
}

fn dump_data_sections(_buffer: &[u8], sections: &[SectionInfo]) {
    if sections.is_empty() {
        println!("\n警告: __DATAセグメントにセクションが見つかりませんでした");
        return;
    }
    
    println!("\n=== __DATAセグメント ダンプ ===");
    
    for section in sections {
        println!("\n--- {} セクション ---", section.name);
        println!("仮想アドレス: 0x{:016x}", section.addr);
        println!("サイズ: {} バイト", section.size);
        println!("ファイルオフセット: 0x{:08x}", section.offset);
        
        // 16進ダンプ関連のロジック削除済み
        // セクション情報のみ表示
        println!("");

    }
    println!("{}", "=".repeat(80));
}


fn display_stubs_symbols(buffer: &[u8], sections: &HashMap<String, SectionInfo>) {
    use mach_o_sys::loader::{symtab_command, LC_SYMTAB};
    use mach_o_sys::nlist::nlist_64;

    println!("\n=== __stubsセクションに属するシンボル一覧 ===");

    // __stubsセクションのセクション番号を取得
    let stubs_sect_idx = sections.values().enumerate().find_map(|(idx, s)| {
        if s.name == "__stubs" { Some(idx + 1) } else { None }
    });
    if stubs_sect_idx.is_none() {
        println!("(セクション__stubsが見つかりません)");
        return;
    }
    let stubs_sect_idx = stubs_sect_idx.unwrap() as u8;

    // Mach-Oヘッダ直後からロードコマンドを探索
    let header_size = mem::size_of::<mach_o_sys::loader::mach_header_64>();
    let mut offset = header_size;
    let mut found = false;

    while offset + mem::size_of::<mach_o_sys::loader::load_command>() <= buffer.len() {
        let lc: &mach_o_sys::loader::load_command = unsafe {
            &*(buffer.as_ptr().add(offset) as *const mach_o_sys::loader::load_command)
        };
        if lc.cmd == LC_SYMTAB as u32 {
            let symtab: &symtab_command = unsafe {
                &*(buffer.as_ptr().add(offset) as *const symtab_command)
            };
            found = true;
            let symbol_size = mem::size_of::<nlist_64>();
            let symtab_start = symtab.symoff as usize;
            let symtab_end = symtab_start + symtab.nsyms as usize * symbol_size;
            let strtab_start = symtab.stroff as usize;
            let strtab_end = strtab_start + symtab.strsize as usize;
            if symtab_end > buffer.len() || strtab_end > buffer.len() {
                println!("(シンボルテーブルまたはストリングテーブルが範囲外です)");
                break;
            }
            let symtab_slice = &buffer[symtab_start..symtab_end];
            let strtab = &buffer[strtab_start..strtab_end];
            for i in 0..(symtab.nsyms as usize) {
                let symbol_offset = i * symbol_size;
                let nlist: &mut nlist_64 = unsafe {
                    &mut *(symtab_slice.as_ptr().add(symbol_offset) as *mut nlist_64)
                };
                let n_strx = unsafe { nlist.n_un.n_strx() } as usize;
                let n_type = nlist.n_type;
                let n_sect = nlist.n_sect;
                let n_value = nlist.n_value;
                if n_sect != stubs_sect_idx {
                    continue;
                }
                let symbol_name = if n_strx == 0 {
                    "<無名>".to_string()
                } else if n_strx < strtab.len() {
                    let name_bytes = &strtab[n_strx..];
                    match name_bytes.iter().position(|&b| b == 0) {
                        Some(0) => "<空>".to_string(),
                        Some(len) => String::from_utf8_lossy(&name_bytes[..len]).to_string(),
                        None => String::from_utf8_lossy(name_bytes).to_string(),
                    }
                } else {
                    "<無効>".to_string()
                };
                let type_str = match n_type & 0x0e {
                    0x0e => "SECT",
                    0x00 => "UNDF",
                    0x02 => "ABS",
                    0x0c => "PBUD",
                    0x0a => "INDR",
                    _ => "OTHER",
                };
                let ext = if n_type & 0x01 != 0 { "EXT" } else { "LOC" };
                println!("{:5} 0x{:016x} {:>5} {:>4} {:>9} {}",
                    i, n_value, type_str, ext, n_sect, symbol_name);
            }
            println!("------------------------------------------------------------");
            break;
        }
        offset += lc.cmdsize as usize;
    }
    if !found {
        println!("(シンボルテーブルが見つかりませんでした)");
    }
}

// __cstringセクションの内容を抽出・表示する関数
fn display_cstring_section(buffer: &[u8], section: &SectionInfo) {
    println!("\n=== __cstring セクション内容 ===");
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    if start_offset >= buffer.len() || section_size == 0 {
        println!("エラー: __cstringセクションのデータが無効です");
        return;
    }
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];

    // 16進ダンプ表示
    println!("\n[16進ダンプ]");
    let max_dump = std::cmp::min(section_data.len(), 512); // 最大512バイト表示
    for (i, chunk) in section_data[..max_dump].chunks(16).enumerate() {
        print!("  {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!(" | ");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' };
            print!("{}", c);
        }
        println!(" |");
    }
    if section_data.len() > max_dump {
        println!("  ... (省略。全体: {} バイト)", section_data.len());
    }

    // 文字列抽出表示
    println!("\n[ヌル終端文字列一覧]");
    let mut offset = 0;
    let mut string_count = 0;
    let max_strings = 1000;
    while offset < section_data.len() && string_count < max_strings {
        let (string_value, consumed) = extract_null_terminated_string(&section_data[offset..]);
        if !string_value.is_empty() {
            println!("  {}: [0x{:04x}] {}", string_count, offset, string_value);
            string_count += 1;
        }
        offset += consumed;
        if consumed == 0 {
            break;
        }
    }
    if string_count == 0 {
        println!("  (文字列が見つかりませんでした)");
    }
}

/// Mach-Oシンボルテーブルを詳細テーブル形式で表示
fn display_symbols(buffer: &[u8], sections: &HashMap<String, SectionInfo>) {
    use mach_o_sys::loader::{symtab_command, LC_SYMTAB};
    use mach_o_sys::nlist::nlist_64;

    println!("------------------------------------------------------------");
    println!("  idx   アドレス            種別  外部  セクション  シンボル名");
    println!("------------------------------------------------------------");

    let header_size = mem::size_of::<mach_o_sys::loader::mach_header_64>();
    let mut offset = header_size;
    let mut found = false;

    while offset + mem::size_of::<mach_o_sys::loader::load_command>() <= buffer.len() {
        let lc: &mach_o_sys::loader::load_command = unsafe {
            &*(buffer.as_ptr().add(offset) as *const mach_o_sys::loader::load_command)
        };
        if lc.cmd == LC_SYMTAB as u32 {
            let symtab: &symtab_command = unsafe {
                &*(buffer.as_ptr().add(offset) as *const symtab_command)
            };
            found = true;
            let symbol_size = mem::size_of::<nlist_64>();
            let symtab_start = symtab.symoff as usize;
            let symtab_end = symtab_start + symtab.nsyms as usize * symbol_size;
            let strtab_start = symtab.stroff as usize;
            let strtab_end = strtab_start + symtab.strsize as usize;
            if symtab_end > buffer.len() || strtab_end > buffer.len() {
                println!("(シンボルテーブルまたはストリングテーブルが範囲外です)");
                break;
            }
            let symtab_slice = &buffer[symtab_start..symtab_end];
            let strtab = &buffer[strtab_start..strtab_end];
            for i in 0..(symtab.nsyms as usize) {
                let symbol_offset = i * symbol_size;
                if symbol_offset + symbol_size > symtab_slice.len() {
                    println!("シンボル{}が範囲外です", i);
                    break;
                }
                
                // nlist_64構造体を安全に読み取り（バイト配列から直接読み取り）
                let symbol_bytes = &symtab_slice[symbol_offset..symbol_offset + symbol_size];
                
                // リトルエンディアンで32ビット値を読み取り
                let n_strx = u32::from_le_bytes([
                    symbol_bytes[0], symbol_bytes[1], symbol_bytes[2], symbol_bytes[3]
                ]) as usize;
                let n_type = symbol_bytes[4];
                let n_sect = symbol_bytes[5];
                // n_desc (2バイト) は6-7番目
                let n_value = u64::from_le_bytes([
                    symbol_bytes[8], symbol_bytes[9], symbol_bytes[10], symbol_bytes[11],
                    symbol_bytes[12], symbol_bytes[13], symbol_bytes[14], symbol_bytes[15]
                ]);
                
                // シンボル名を取得（改善版）
                let symbol_name = if n_strx == 0 {
                    "<無名>".to_string()
                } else if n_strx < strtab.len() {
                    // 文字列テーブルから null終端文字列を安全に取得
                    let remaining_bytes = &strtab[n_strx..];
                    if let Some(null_pos) = remaining_bytes.iter().position(|&b| b == 0) {
                        if null_pos == 0 {
                            "<空文字列>".to_string()
                        } else {
                            // null終端までの文字列を取得
                            let name_bytes = &remaining_bytes[..null_pos];
                            String::from_utf8_lossy(name_bytes).to_string()
                        }
                    } else {
                        // null終端が見つからない場合は残り全体を使用
                        let name_str = String::from_utf8_lossy(remaining_bytes).to_string();
                        if name_str.trim().is_empty() {
                            "<null終端なし空>".to_string()
                        } else {
                            name_str
                        }
                    }
                } else {
                    format!("<範囲外:strx={}/{}>", n_strx, strtab.len())
                };
                let type_str = match n_type & 0x0e {
                    0x0e => "SECT",
                    0x00 => "UNDF",
                    0x02 => "ABS",
                    0x0c => "PBUD",
                    0x0a => "INDR",
                    _ => "OTHER",
                };
                let ext = if n_type & 0x01 != 0 { "EXT" } else { "LOC" };
                println!("{:5} 0x{:016x} {:>5} {:>4} {:>9} {}",
                    i, n_value, type_str, ext, n_sect, symbol_name);
            }
            println!("------------------------------------------------------------");
            break;
        }
        offset += lc.cmdsize as usize;
    }
    if !found {
        println!("(シンボルテーブルが見つかりませんでした)");
    }

    println!("\n=== __stubsセクションに属するシンボル一覧 ===");

    // __stubsセクションのセクション番号を取得
    let stubs_sect_idx = sections.values().enumerate().find_map(|(idx, s)| {
        if s.name == "__stubs" { Some(idx + 1) } else { None }
    });
    if stubs_sect_idx.is_none() {
        println!("(セクション__stubsが見つかりません)");
        return;
    }
    let stubs_sect_idx = stubs_sect_idx.unwrap() as u8;

    // Mach-Oヘッダ直後からロードコマンドを探索
    let header_size = mem::size_of::<mach_o_sys::loader::mach_header_64>();
    let mut offset = header_size;
    let mut found = false;

    while offset + mem::size_of::<mach_o_sys::loader::load_command>() <= buffer.len() {
        let lc: &mach_o_sys::loader::load_command = unsafe {
            &*(buffer.as_ptr().add(offset) as *const mach_o_sys::loader::load_command)
        };
        if lc.cmd == LC_SYMTAB as u32 {
            let symtab: &symtab_command = unsafe {
                &*(buffer.as_ptr().add(offset) as *const symtab_command)
            };
            found = true;
            let symbol_size = mem::size_of::<nlist_64>();
            let symtab_start = symtab.symoff as usize;
            let symtab_end = symtab_start + symtab.nsyms as usize * symbol_size;
            let strtab_start = symtab.stroff as usize;
            let strtab_end = strtab_start + symtab.strsize as usize;
            if symtab_end > buffer.len() || strtab_end > buffer.len() {
                println!("(シンボルテーブルまたはストリングテーブルが範囲外です)");
                break;
            }
            let symtab_slice = &buffer[symtab_start..symtab_end];
            let strtab = &buffer[strtab_start..strtab_end];
            for i in 0..(symtab.nsyms as usize) {
                let symbol_offset = i * symbol_size;
                let nlist: &mut nlist_64 = unsafe {
                    &mut *(symtab_slice.as_ptr().add(symbol_offset) as *mut nlist_64)
                };
                let n_strx = unsafe { nlist.n_un.n_strx() } as usize;
                let n_type = nlist.n_type;
                let n_sect = nlist.n_sect;
                let n_value = nlist.n_value;
                if n_sect != stubs_sect_idx { continue; }
                let symbol_name = if n_strx == 0 {
                    "<無名>".to_string()
                } else if n_strx < strtab.len() {
                    let name_bytes = &strtab[n_strx..];
                    match name_bytes.iter().position(|&b| b == 0) {
                        Some(0) => "<空>".to_string(),
                        Some(len) => String::from_utf8_lossy(&name_bytes[..len]).to_string(),
                        None => String::from_utf8_lossy(name_bytes).to_string(),
                    }
                } else {
                    "<無効>".to_string()
                };
                let type_str = match n_type & 0x0e {
                    0x00 => "UNDF",
                    0x0e => "SECT",
                    0x02 => "ABS",
                    0x0c => "PBUD",
                    0x0a => "INDR",
                    _ => "OTHER",
                };
                let ext = if n_type & 0x01 != 0 { "EXT" } else { "LOC" };
                println!("{:5} 0x{:016x} {:>5} {:>4} {:>9} {}",
                    i, n_value, type_str, ext, n_sect, symbol_name);
            }
            println!("------------------------------------------------------------");
            break;
        }
        offset += lc.cmdsize as usize;
    }
    if !found {
        println!("(シンボルテーブルが見つかりませんでした)");
    }
}




// null終端文字列を抽出するヘルパー関数
fn get_string_from_table(buffer: &[u8], _stroff: u32, _strsize: u32, str_index: u32) -> String {
    let start = str_index as usize;
    if start >= buffer.len() {
        return "<無効>".to_string();
    }
    let end = std::cmp::min(start + 256, buffer.len()); // 最大256文字まで
    // ヌル終端文字列を探す
    let mut actual_end = start;
    for i in start..end {
        if buffer[i] == 0 {
            actual_end = i;
            break;
        }
        actual_end = i + 1;
    }
    if actual_end <= start {
        return "<空>".to_string();
    }
    match std::str::from_utf8(&buffer[start..actual_end]) {
        Ok(s) => s.to_string(),
        Err(_) => format!("<バイナリ:{:02x}...>", buffer[start]),
    }
}

// null終端文字列を抽出するヘルパー関数
fn extract_null_terminated_string(data: &[u8]) -> (String, usize) {
    let mut string = String::new();
    let mut offset = 0;
    while offset < data.len() {
        let byte = data[offset];
        if byte == 0 {
            break;
        }
        string.push(byte as char);
        offset += 1;
    }
    (string, offset + 1)
}

// ModRMバイトの解析ヘルパー関数
fn parse_modrm_length(modrm: u8, code: &[u8], offset: usize) -> usize {
    let mod_bits = (modrm & 0xc0) >> 6;
    let rm = modrm & 0x07;
    
    match mod_bits {
        0b00 => {
            if offset + 1 < code.len() {
                let sib = code[offset + 1];
                let base = sib & 0x07;
                if base == 0b101 {
                    6 // ModRM + SIB + disp32
                } else {
                    2 // ModRM + SIB
                }
            } else {
                2
            }
        },
        0b01 => {
            if rm == 0b100 {
                3 // ModRM + SIB + disp8
            } else {
                2 // ModRM + disp8
            }
        },
        0b10 => {
            if rm == 0b100 {
                6 // ModRM + SIB + disp32
            } else {
                5 // ModRM + disp32
            }
        },
        0b11 => 1, // レジスタ直接
        _ => 1,
    }
}

fn simple_disasm_x86_64(code: &[u8], addr: u64) -> (String, usize) {
    if code.is_empty() {
        return ("???".to_string(), 1);
    }
    
    let mut offset = 0;
    let mut rex_prefix = false;
    let mut operand_size_override = false;
    let mut _address_size_override = false;
    let mut _rep_prefix = false;
    let mut _repne_prefix = false;
    
    // プレフィックスを順次チェック
    while offset < code.len() {
        match code[offset] {
            // オペランドサイズオーバーライド
            0x66 => {
                operand_size_override = true;
                offset += 1;
            },
            // アドレスサイズオーバーライド
            0x67 => {
                _address_size_override = true;
                offset += 1;
            },
            // REPプレフィックス
            0xf3 => {
                _rep_prefix = true;
                offset += 1;
            },
            // REPNEプレフィックス
            0xf2 => {
                _repne_prefix = true;
                offset += 1;
            },
            // REXプレフィックス
            0x40..=0x4f => {
                rex_prefix = true;
                offset += 1;
            },
            // セグメントオーバーライド
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {
                offset += 1;
            },
            // ロック
            0xf0 => {
                offset += 1;
            },
            _ => break,
        }
    }
    
    if offset >= code.len() {
        return ("prefix only (incomplete)".to_string(), offset);
    }
    
    let opcode = code[offset];
    let mut length = offset + 1;
    
    match opcode {
        // MOV r/m64, r64 (REX.W + 89)
        0x89 => {
            if offset + 1 < code.len() {
                let modrm_len = parse_modrm_length(code[offset + 1], code, offset + 1);
                length += modrm_len;
                let size = if rex_prefix {
                    "r64"
                } else if operand_size_override {
                    "r16"
                } else {
                    "r32"
                };
                (format!("mov {}, {}", size, size), length)
            } else {
                ("mov (incomplete)".to_string(), length)
            }
        },
        
        // MOV r64, r/m64 (REX.W + 8B)
        0x8b => {
            if offset + 1 < code.len() {
                let modrm_len = parse_modrm_length(code[offset + 1], code, offset + 1);
                length += modrm_len;
                let size = if rex_prefix {
                    "r64"
                } else if operand_size_override {
                    "r16"
                } else {
                    "r32"
                };
                (format!("mov {}, {}/m{}", size, size, if rex_prefix { "64" } else if operand_size_override { "16" } else { "32" }), length)
            } else {
                ("mov (incomplete)".to_string(), length)
            }
        },
        
        // ADD/SUB r/m64, imm8 (REX.W + 83)
        0x83 => {
            if offset + 1 < code.len() {
                let modrm_len = parse_modrm_length(code[offset + 1], code, offset + 1);
                length += modrm_len;
                if length < code.len() {
                    let reg = (code[offset + 1] & 0x38) >> 3;
                    let imm = code[length];
                    length += 1;
                    let size = if rex_prefix {
                        "r64"
                    } else if operand_size_override {
                        "r16"
                    } else {
                        "r32"
                    };
                    match reg {
                        0 => (format!("add {}, 0x{:02x}", size, imm), length),
                        5 => (format!("sub {}, 0x{:02x}", size, imm), length),
                        _ => (format!("alu {}, 0x{:02x}", size, imm), length),
                    }
                } else {
                    ("alu (incomplete)".to_string(), length)
                }
            } else {
                ("alu (incomplete)".to_string(), length)
            }
        },
        
        // LEA r64, m (REX.W + 8D)
        0x8d => {
            if offset + 1 < code.len() {
                let modrm_len = parse_modrm_length(code[offset + 1], code, offset + 1);
                length += modrm_len;
                ("lea r64, [mem]".to_string(), length)
            } else {
                ("lea (incomplete)".to_string(), length)
            }
        },
        
        // MOV r/m64, imm32 (REX.W + C7)
        0xc7 => {
            if offset + 1 < code.len() {
                let modrm_len = parse_modrm_length(code[offset + 1], code, offset + 1);
                length += modrm_len;
                if length + 4 <= code.len() {
                    let imm = u32::from_le_bytes([
                        code[length], code[length+1], code[length+2], code[length+3],
                    ]);
                    length += 4;
                    (format!("mov {}, 0x{:08x}", if rex_prefix { "r64" } else { "r32" }, imm), length)
                } else {
                    ("mov imm (incomplete)".to_string(), length)
                }
            } else {
                ("mov imm (incomplete)".to_string(), length)
            }
        },
        
        // XOR r32, r32 (31)
        0x31 => {
            if offset + 1 < code.len() {
                let modrm_len = parse_modrm_length(code[offset + 1], code, offset + 1);
                length += modrm_len;
                ("xor r32, r32".to_string(), length)
            } else {
                ("xor (incomplete)".to_string(), length)
            }
        },
        
        // XOR r64, r64 (REX.W + 31) - handled above with REX prefix
        
        // Push/Pop operations
        0x50..=0x54 | 0x56..=0x57 => (format!("push r{}", opcode - 0x50), length),
        0x55 => ("push rbp".to_string(), length),
        0x58..=0x5c | 0x5e..=0x5f => (format!("pop r{}", opcode - 0x58), length),
        0x5d => ("pop rbp".to_string(), length),
        
        // Control flow
        0xc3 => ("ret".to_string(), length),
        0xe8 => {
            if length + 4 <= code.len() {
                let offset_val = i32::from_le_bytes([code[length], code[length+1], code[length+2], code[length+3]]);
                let target = (addr as i64 + length as i64 + 4 + offset_val as i64) as u64;
                length += 4;
                (format!("call 0x{:x}", target), length)
            } else {
                ("call (incomplete)".to_string(), length)
            }
        },
        0xe9 => {
            if length + 4 <= code.len() {
                let offset_val = i32::from_le_bytes([code[length], code[length+1], code[length+2], code[length+3]]);
                let target = (addr as i64 + length as i64 + 4 + offset_val as i64) as u64;
                length += 4;
                (format!("jmp 0x{:x}", target), length)
            } else {
                ("jmp (incomplete)".to_string(), length)
            }
        },
        
        // Two-byte opcodes
        0x0f => {
            if length < code.len() {
                match code[length] {
                    0x1f => {
                        length += 1;
                        if length < code.len() {
                            let modrm_len = parse_modrm_length(code[length], code, length);
                            length += modrm_len;
                            ("nop (multi-byte)".to_string(), length)
                        } else {
                            ("0f 1f (incomplete)".to_string(), length)
                        }
                    },
                    0x84 => {
                        length += 1;
                        if length + 4 <= code.len() {
                            let offset_val = i32::from_le_bytes([code[length], code[length+1], code[length+2], code[length+3]]);
                            let target = (addr as i64 + length as i64 + 4 + offset_val as i64) as u64;
                            length += 4;
                            (format!("je 0x{:x}", target), length)
                        } else {
                            ("je (incomplete)".to_string(), length)
                        }
                    },
                    0x85 => {
                        length += 1;
                        if length + 4 <= code.len() {
                            let offset_val = i32::from_le_bytes([code[length], code[length+1], code[length+2], code[length+3]]);
                            let target = (addr as i64 + length as i64 + 4 + offset_val as i64) as u64;
                            length += 4;
                            (format!("jne 0x{:x}", target), length)
                        } else {
                            ("jne (incomplete)".to_string(), length)
                        }
                    },
                    _ => {
                        length += 1;
                        (format!("0f {:02x}", code[length-1]), length)
                    },
                }
            } else {
                ("0f (incomplete)".to_string(), length)
            }
        },        0x90 => ("nop".to_string(), length),
        0xcc => ("int3".to_string(), length),
        0xb0..=0xbf => {
            // MOV reg, imm8/imm32/imm64
            if rex_prefix && (opcode & 0x08) != 0 {
                // 64-bit immediate
                if length + 8 <= code.len() {
                    let imm = u64::from_le_bytes([
                        code[length], code[length+1], code[length+2], code[length+3],
                        code[length+4], code[length+5], code[length+6], code[length+7],
                    ]);
                    length += 8;
                    (format!("mov r{}, 0x{:016x}", opcode & 0x07, imm), length)
                } else {
                    ("mov r64, imm64 (incomplete)".to_string(), length)
                }
            } else if (opcode & 0x08) != 0 {
                // 32-bit immediate
                if length + 4 <= code.len() {
                    let imm = u32::from_le_bytes([
                        code[length], code[length+1], code[length+2], code[length+3],
                    ]);
                    length += 4;
                    (format!("mov r{}, 0x{:08x}", opcode & 0x07, imm), length)
                } else {
                    ("mov r32, imm32 (incomplete)".to_string(), length)
                }
            } else {
                // 8-bit immediate
                if length < code.len() {
                    let imm = code[length];
                    length += 1;
                    (format!("mov r{}b, 0x{:02x}", opcode & 0x07, imm), length)
                } else {
                    ("mov r8, imm8 (incomplete)".to_string(), length)
                }
            }
        },
        _ => (format!("db 0x{:02x}", opcode), length),
    }
}

// ARM64命令の簡易逆アセンブル
fn simple_disasm_arm64(code: &[u8], addr: u64) -> (String, usize) {
    if code.len() < 4 {
        return ("incomplete instruction".to_string(), code.len());
    }
    
    // ARM64命令は4バイト固定長（リトルエンディアン）
    let inst = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
    
    // 基本的なARM64命令パターンを解析
    let instruction = match inst {
        // AND (register) - 0x8a000000 | rm << 16 | rn << 5 | rd
        i if (i & 0xff2003e0) == 0x8a000000 => {
            let rm = (i >> 16) & 0x1f;
            let rn = (i >> 5) & 0x1f;
            let rd = i & 0x1f;
            format!("and x{}, x{}, x{}", rd, rn, rm)
        },
        // ORR (register) - 0xaa000000 | rm << 16 | rn << 5 | rd
        i if (i & 0xff2003e0) == 0xaa000000 => {
            let rm = (i >> 16) & 0x1f;
            let rn = (i >> 5) & 0x1f;
            let rd = i & 0x1f;
            format!("orr x{}, x{}, x{}", rd, rn, rm)
        },
        // EOR (register) - 0xca000000 | rm << 16 | rn << 5 | rd
        i if (i & 0xff2003e0) == 0xca000000 => {
            let rm = (i >> 16) & 0x1f;
            let rn = (i >> 5) & 0x1f;
            let rd = i & 0x1f;
            format!("eor x{}, x{}, x{}", rd, rn, rm)
        },
        // CMP (immediate) - SUBS xzr, xn, #imm12
        i if (i & 0xffc003ff) == 0xf10003ff => {
            let imm12 = (i >> 10) & 0xfff;
            let rn = (i >> 5) & 0x1f;
            format!("cmp x{}, #{}", rn, imm12)
        },
        // ADRP - 0x90000000 | immlo << 29 | immhi << 5 | rd
        i if (i & 0x9f000000) == 0x90000000 => {
            let immlo = (i >> 29) & 0x3;
            let immhi = (i >> 5) & 0x7ffff;
            let rd = i & 0x1f;
            let imm = ((immhi << 14) | (immlo << 12)) as i64;
            let page = ((addr as i64) & !0xfff) + imm;
            format!("adrp x{}, 0x{:x}", rd, page)
        },
        // CBZ - 0xb4000000 | imm19 << 5 | rt
        i if (i & 0x7f000000) == 0x34000000 => {
            let imm19 = (i >> 5) & 0x7ffff;
            let rt = i & 0x1f;
            let offset = ((imm19 << 2) as i32) | if (imm19 & 0x40000) != 0 { !0x7ffff + 1 } else { 0 };
            let target = (addr as i64 + offset as i64) as u64;
            format!("cbz x{}, 0x{:x}", rt, target)
        },
        // CBNZ - 0x35000000
        i if (i & 0x7f000000) == 0x35000000 => {
            let imm19 = (i >> 5) & 0x7ffff;
            let rt = i & 0x1f;
            let offset = ((imm19 << 2) as i32) | if (imm19 & 0x40000) != 0 { !0x7ffff + 1 } else { 0 };
            let target = (addr as i64 + offset as i64) as u64;
            format!("cbnz x{}, 0x{:x}", rt, target)
        },
        // NOP (0xd503201f)
        0xd503201f => "nop".to_string(),
        
        // RET (0xd65f03c0)
        0xd65f03c0 => "ret".to_string(),
        
        // BRK #imm16 (0xd4200000 | imm16 << 5)
        i if (i & 0xffe0001f) == 0xd4200000 => {
            let imm16 = (i >> 5) & 0xffff;
            format!("brk #{}", imm16)
        },
        
        // B (unconditional branch) - 0x14000000 | imm26
        i if (i & 0xfc000000) == 0x14000000 => {
            let imm26 = (i & 0x03ffffff) as i32;
            let offset = if imm26 & 0x02000000 != 0 {
                imm26 | (-67108864i32) // 符号拡張 (0xfc000000)
            } else {
                imm26
            };
            let target = (addr as i64 + (offset * 4) as i64) as u64;
            format!("b 0x{:x}", target)
        },
        
        // BL (branch with link) - 0x94000000 | imm26
        i if (i & 0xfc000000) == 0x94000000 => {
            let imm26 = (i & 0x03ffffff) as i32;
            let offset = if imm26 & 0x02000000 != 0 {
                imm26 | (-67108864i32) // 符号拡張 (0xfc000000)
            } else {
                imm26
            };
            let target = (addr as i64 + (offset * 4) as i64) as u64;
            format!("bl 0x{:x}", target)
        },
        
        // MOV (register) - 0xaa0003e0 | rm << 16 | rd
        i if (i & 0xffe0ffe0) == 0xaa0003e0 => {
            let rm = (i >> 16) & 0x1f;
            let rd = i & 0x1f;
            format!("mov x{}, x{}", rd, rm)
        },
        
        // ADD immediate - 0x91000000 | imm12 << 10 | rn << 5 | rd
        i if (i & 0xffc00000) == 0x91000000 => {
            let imm12 = (i >> 10) & 0xfff;
            let rn = (i >> 5) & 0x1f;
            let rd = i & 0x1f;
            format!("add x{}, x{}, #{}", rd, rn, imm12)
        },
        
        // SUB immediate - 0xd1000000 | imm12 << 10 | rn << 5 | rd
        i if (i & 0xffc00000) == 0xd1000000 => {
            let imm12 = (i >> 10) & 0xfff;
            let rn = (i >> 5) & 0x1f;
            let rd = i & 0x1f;
            format!("sub x{}, x{}, #{}", rd, rn, imm12)
        },
        
        // LDR (immediate) - 0xf9400000 | imm12 << 10 | rn << 5 | rt
        i if (i & 0xffc00000) == 0xf9400000 => {
            let imm12 = (i >> 10) & 0xfff;
            let rn = (i >> 5) & 0x1f;
            let rt = i & 0x1f;
            let offset = imm12 * 8; // 8バイト単位
            format!("ldr x{}, [x{}, #{}]", rt, rn, offset)
        },
        
        // STR (immediate) - 0xf9000000 | imm12 << 10 | rn << 5 | rt
        i if (i & 0xffc00000) == 0xf9000000 => {
            let imm12 = (i >> 10) & 0xfff;
            let rn = (i >> 5) & 0x1f;
            let rt = i & 0x1f;
            let offset = imm12 * 8;
            format!("str x{}, [x{}, #{}]", rt, rn, offset)
        },
        
        // STP (store pair) - 0xa9000000 | imm7 << 15 | rt2 << 10 | rn << 5 | rt
        i if (i & 0xffc00000) == 0xa9000000 => {
            let imm7 = ((i >> 15) & 0x7f) as i32;
            let offset = if imm7 & 0x40 != 0 {
                ((imm7 | (-128i32)) * 8) as i32 // 符号拡張 (0xffffff80)
            } else {
                (imm7 * 8) as i32
            };
            let rt2 = (i >> 10) & 0x1f;
            let rn = (i >> 5) & 0x1f;
            let rt = i & 0x1f;
            format!("stp x{}, x{}, [x{}, #{}]", rt, rt2, rn, offset)
        },
        
        // LDP (load pair) - 0xa9400000 | imm7 << 15 | rt2 << 10 | rn << 5 | rt
        i if (i & 0xffc00000) == 0xa9400000 => {
            let imm7 = ((i >> 15) & 0x7f) as i32;
            let offset = if imm7 & 0x40 != 0 {
                ((imm7 | (-128i32)) * 8) as i32 // 符号拡張 (0xffffff80)
            } else {
                (imm7 * 8) as i32
            };
            let rt2 = (i >> 10) & 0x1f;
            let rn = (i >> 5) & 0x1f;
            let rt = i & 0x1f;
            format!("ldp x{}, x{}, [x{}, #{}]", rt, rt2, rn, offset)
        },
        
        // MOVZ - 0xd2800000 | imm16 << 5 | rd
        i if (i & 0xff800000) == 0xd2800000 => {
            let imm16 = (i >> 5) & 0xffff;
            let rd = i & 0x1f;
            let shift = ((i >> 21) & 0x3) * 16;
            format!("movz x{}, #{:#x}, lsl #{}", rd, imm16, shift)
        },
        // MOVK - 0xf2800000 | imm16 << 5 | rd
        i if (i & 0xff800000) == 0xf2800000 => {
            let imm16 = (i >> 5) & 0xffff;
            let rd = i & 0x1f;
            let shift = ((i >> 21) & 0x3) * 16;
            format!("movk x{}, #{:#x}, lsl #{}", rd, imm16, shift)
        },
        // MOVN - 0x92800000 | imm16 << 5 | rd
        i if (i & 0xff800000) == 0x92800000 => {
            let imm16 = (i >> 5) & 0xffff;
            let rd = i & 0x1f;
            let shift = ((i >> 21) & 0x3) * 16;
            format!("movn x{}, #{:#x}, lsl #{}", rd, imm16, shift)
        },
        // BR (register) - 0xd61f0000 | rn << 5
        i if (i & 0xfffffc1f) == 0xd61f0000 => {
            let rn = (i >> 5) & 0x1f;
            format!("br x{}", rn)
        },
        // B.cond (conditional branch) - 0x54000000 | imm19 << 5 | cond
        i if (i & 0xff000010) == 0x54000000 => {
            let imm19 = (i >> 5) & 0x7ffff;
            let cond = i & 0xf;
            let offset = ((imm19 << 2) as i32) | if (imm19 & 0x40000) != 0 { !0x7ffff + 1 } else { 0 };
            let target = (addr as i64 + offset as i64) as u64;
            let cond_str = match cond {
                0x0 => "eq", 0x1 => "ne", 0x2 => "cs", 0x3 => "cc",
                0x4 => "mi", 0x5 => "pl", 0x6 => "vs", 0x7 => "vc",
                0x8 => "hi", 0x9 => "ls", 0xa => "ge", 0xb => "lt",
                0xc => "gt", 0xd => "le", 0xe => "al", _ => "nv"
            };
            format!("b.{} 0x{:x}", cond_str, target)
        },
        // STR (immediate) - 0xf9000000 | imm12 << 10 | rn << 5 | rt
        i if (i & 0xffc00000) == 0xf9000000 => {
            let imm12 = (i >> 10) & 0xfff;
            let rn = (i >> 5) & 0x1f;
            let rt = i & 0x1f;
            format!("str x{}, [x{}, #{}]", rt, rn, imm12 * 8)
        },
        // CMP (register) - SUBS xzr, xn, xm
        i if (i & 0xff20ffe0) == 0xeb00001f => {
            let xn = (i >> 5) & 0x1f;
            let xm = (i >> 16) & 0x1f;
            format!("cmp x{}, x{}", xn, xm)
        },
        
        _ => format!(".word 0x{:08x}", inst),
    };
    
    (instruction, 4)
}

// ARM32命令の簡易逆アセンブル
fn simple_disasm_arm32(code: &[u8], addr: u64) -> (String, usize) {
    if code.len() < 4 {
        return ("incomplete instruction".to_string(), code.len());
    }
    
    // ARM32命令は4バイト固定長（リトルエンディアン）
    let inst = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
    
    // 条件コードを取得
    let cond = (inst >> 28) & 0xf;
    let cond_str = match cond {
        0x0 => "eq", 0x1 => "ne", 0x2 => "cs", 0x3 => "cc",
        0x4 => "mi", 0x5 => "pl", 0x6 => "vs", 0x7 => "vc",
        0x8 => "hi", 0x9 => "ls", 0xa => "ge", 0xb => "lt",
        0xc => "gt", 0xd => "le", 0xe => "", 0xf => "nv",
        _ => "",
    };
    
    // 基本的なARM32命令パターンを解析
    let instruction = match inst & 0x0fffffff {
        // NOP (mov r0, r0)
        i if i == 0x01a00000 => format!("nop{}", cond_str),
        // BX lr (0x012fff1e)
        0x012fff1e => format!("bx{} lr", cond_str),
        // PUSH (STMFD sp!, {...})
        _i if (inst & 0xffff0000) == 0xe92d0000 => {
            let reglist = inst & 0xffff;
            format!("push{} {{{:#06x}}}", cond_str, reglist)
        },
        // POP (LDMFD sp!, {...})
        _i if (inst & 0xffff0000) == 0xe8bd0000 => {
            let reglist = inst & 0xffff;
            format!("pop{} {{{:#06x}}}", cond_str, reglist)
        },
        // LDM/STM (0xe8xxxxxx)
        _i if (inst & 0xf8000000) == 0xe8000000 => {
            let l = (inst >> 20) & 1;
            let rn = (inst >> 16) & 0xf;
            let reglist = inst & 0xffff;
            if l == 1 {
                format!("ldm{} r{}, {{{:#06x}}}", cond_str, rn, reglist)
            } else {
                format!("stm{} r{}, {{{:#06x}}}", cond_str, rn, reglist)
            }
        },
        // BX (0x012fff10 or 0x012fff11)
        _i if (inst & 0x0ffffff0) == 0x012fff10 => {
            let rm = inst & 0xf;
            format!("bx{} r{}", cond_str, rm)
        },
        // BLX (immediate, 0xfa000000)
        _i if (inst & 0xfe000000) == 0xfa000000 => {
            let offset = (inst & 0x00ffffff) as i32;
            let sign_extended = if offset & 0x00800000 != 0 {
                offset | (-16777216i32)
            } else {
                offset
            };
            let target = (addr as i64 + (sign_extended * 4) as i64 + 8) as u64;
            format!("blx{} 0x{:x}", cond_str, target)
        },
        // CMP (immediate)
        _i if ((inst >> 21) & 0xf) == 0xa && ((inst >> 25) & 0x7) == 0x1 => {
            let rn = (inst >> 16) & 0xf;
            let imm = inst & 0xff;
            let rot = (inst >> 8) & 0xf;
            let rotated_imm = imm.rotate_right(rot * 2);
            format!("cmp{} r{}, #{}", cond_str, rn, rotated_imm)
        },
        // CMP (register)
        _i if ((inst >> 21) & 0xf) == 0xa && ((inst >> 25) & 0x7) == 0x0 => {
            let rn = (inst >> 16) & 0xf;
            let rm = inst & 0xf;
            format!("cmp{} r{}, r{}", cond_str, rn, rm)
        },
        _ => {
            match (inst >> 25) & 0x7 {
                // データ処理命令 (bits 27-25 = 000)
                0x0 => {
                    let opcode = (inst >> 21) & 0xf;
                    let s = (inst >> 20) & 1;
                    let rn = (inst >> 16) & 0xf;
                    let rd = (inst >> 12) & 0xf;
                    let op_str = match opcode {
                        0x0 => "and", 0x1 => "eor", 0x2 => "sub", 0x3 => "rsb",
                        0x4 => "add", 0x5 => "adc", 0x6 => "sbc", 0x7 => "rsc",
                        0x8 => "tst", 0x9 => "teq", 0xa => "cmp", 0xb => "cmn",
                        0xc => "orr", 0xd => "mov", 0xe => "bic", 0xf => "mvn",
                        _ => "unknown",
                    };
                    let s_str = if s == 1 { "s" } else { "" };
                    if (inst >> 25) & 1 == 1 {
                        // 即値オペランド
                        let imm = inst & 0xff;
                        let rot = (inst >> 8) & 0xf;
                        let rotated_imm = imm.rotate_right(rot * 2);
                        format!("{}{}{} r{}, r{}, #{}", op_str, cond_str, s_str, rd, rn, rotated_imm)
                    } else {
                        // レジスタオペランド
                        let rm = inst & 0xf;
                        format!("{}{}{} r{}, r{}, r{}", op_str, cond_str, s_str, rd, rn, rm)
                    }
                },
                // 分岐命令 (bits 27-25 = 101)
                0x5 => {
                    let l = (inst >> 24) & 1;
                    let offset = (inst & 0x00ffffff) as i32;
                    let sign_extended = if offset & 0x00800000 != 0 {
                        offset | (-16777216i32) // 符号拡張 (0xff000000)
                    } else {
                        offset
                    };
                    let target = (addr as i64 + (sign_extended * 4) as i64 + 8) as u64;
                    if l == 1 {
                        format!("bl{} 0x{:x}", cond_str, target)
                    } else {
                        format!("b{} 0x{:x}", cond_str, target)
                    }
                },
                // ロード/ストア命令 (bits 27-26 = 01)
                0x2 | 0x3 => {
                    let l = (inst >> 20) & 1;
                    let rn = (inst >> 16) & 0xf;
                    let rd = (inst >> 12) & 0xf;
                    if l == 1 {
                        format!("ldr{} r{}, [r{}]", cond_str, rd, rn)
                    } else {
                        format!("str{} r{}, [r{}]", cond_str, rd, rn)
                    }
                },
                _ => format!(".word 0x{:08x}", inst),
            }
        },
    };
    (instruction, 4)
}

fn display_macho_header(header: &mach_header_64) {
    println!("\n=== Mach-Oヘッダー情報 ===");
    
    // マジックナンバー
    let magic_str = match header.magic {
        0xfeedfacf => "MH_MAGIC_64 (リトルエンディアン)",
        0xcffaedfe => "MH_CIGAM_64 (ビッグエンディアン)",
        0xfeedface => "MH_MAGIC (リトルエンディアン)",
        0xcefaedfe => "MH_CIGAM (ビッグエンディアン)",
        _ => "不明",
    };
    println!("マジックナンバー: {} (0x{:08x})", magic_str, header.magic);
    
    // CPUタイプ（正しいMach-O定数を使用）
    let cpu_str = match header.cputype {
        1 => "VAX",
        6 => "MC680x0",
        7 => "Intel x86 (i386)",
        10 => "MC98000",
        11 => "HPPA",
        12 => "ARM",
        13 => "MC88000",
        14 => "SPARC",
        15 => "Intel i860",
        16 => "PowerPC",
        18 => "PowerPC 64",
        16777223 => "Intel x86_64",  // 0x01000007 = CPU_TYPE_X86_64
        16777228 => "ARM64",         // 0x0100000c = CPU_TYPE_ARM64
        _ => "不明",
    };
    println!("CPUタイプ: {} ({})", cpu_str, header.cputype);
    
    // CPUサブタイプ（正しいMach-O定数を使用）
    let subtype_str = match (header.cputype, header.cpusubtype & 0xFFFFFF) { // マスクして能力フラグを除去
        // x86_64サブタイプ
        (16777223, 3) => "x86_64 All",
        (16777223, 4) => "x86_64 Haswell",
        (16777223, 8) => "x86_64 Haswell",
        // ARM64サブタイプ
        (16777228, 0) => "ARM64 All",
        (16777228, 1) => "ARM64 v8",
        (16777228, 2) => "ARM64e",
        // i386サブタイプ
        (7, 3) => "i386 All",
        (7, 4) => "i386 486",
        (7, 5) => "i386 586",
        (7, 8) => "i386 Pentium III",
        (7, 9) => "i386 Pentium M",
        (7, 10) => "i386 Pentium 4",
        (7, 11) => "i386 Itanium",
        (7, 12) => "i386 Xeon",
        // ARM32サブタイプ
        (12, 0) => "ARM All",
        (12, 5) => "ARM v4T",
        (12, 6) => "ARM v6",
        (12, 7) => "ARM v5TEJ",
        (12, 8) => "ARM XSCALE",
        (12, 9) => "ARM v7",
        (12, 10) => "ARM v7F",
        (12, 11) => "ARM v7S",
        (12, 12) => "ARM v7K",
        (12, 14) => "ARM v8",
        // PowerPCサブタイプ
        (16, 0) => "PowerPC All",
        (16, 1) => "PowerPC 601",
        (16, 2) => "PowerPC 602",
        (16, 3) => "PowerPC 603",
        (16, 4) => "PowerPC 603e",
        (16, 5) => "PowerPC 603ev",
        (16, 6) => "PowerPC 604",
        (16, 7) => "PowerPC 604e",
        (16, 8) => "PowerPC 620",
        (16, 9) => "PowerPC 750",
        (16, 10) => "PowerPC 7400",
        (16, 11) => "PowerPC 7450",
        (16, 100) => "PowerPC 970",
        _ => "不明",
    };
    // CPUサブタイプの詳細情報も表示
    let capability_flags = header.cpusubtype & 0xFF000000u32 as i32;
    println!("CPUサブタイプ: {} (0x{:08x})", subtype_str, header.cpusubtype);
    if capability_flags != 0 {
        println!("  能力フラグ: 0x{:08x}", capability_flags);
        if capability_flags & (0x80000000u32 as i32) != 0 {
            println!("    - LIB64: 64ビットライブラリサポート");
        }
    }
    
    // ファイルタイプ
    let filetype_str = match header.filetype {
        1 => "オブジェクトファイル",
        2 => "実行可能ファイル",
        3 => "固定仮想メモリ共有ライブラリ",
        4 => "コアファイル",
        5 => "プリロード実行可能ファイル",
        6 => "動的共有ライブラリ",
        7 => "動的リンカー",
        8 => "バンドル",
        9 => "動的共有ライブラリスタブ",
        10 => "コンパニオンファイル",
        11 => "dsymファイル",
        12 => "kextバンドル",
        33554432 => "実行可能ファイル (バイトオーダー問題)", // 0x02000000 (実際の読み取り値)
        _ => "不明",
    };
    println!("ファイルタイプ: {} ({})", filetype_str, header.filetype);
    
    println!("ロードコマンド数: {}", header.ncmds);
    println!("ロードコマンドサイズ: {} バイト", header.sizeofcmds);
    
    // フラグ
    println!("フラグ: 0x{:08x}", header.flags);
    if header.flags & 0x1 != 0 { println!("  - NOUNDEFS: 未定義シンボルなし"); }
    if header.flags & 0x2 != 0 { println!("  - INCRLINK: インクリメンタルリンク出力"); }
    if header.flags & 0x4 != 0 { println!("  - DYLDLINK: 動的リンカーで使用"); }
    if header.flags & 0x8 != 0 { println!("  - BINDATLOAD: ロード時にバインド"); }
    if header.flags & 0x10 != 0 { println!("  - PREBOUND: プリバインド済み"); }
    if header.flags & 0x20 != 0 { println!("  - SPLIT_SEGS: 分割セグメント"); }
    if header.flags & 0x40 != 0 { println!("  - LAZY_INIT: 遅延初期化"); }
    if header.flags & 0x80 != 0 { println!("  - TWOLEVEL: 2レベル名前空間"); }
    if header.flags & 0x100 != 0 { println!("  - FORCE_FLAT: フラット名前空間強制"); }
    if header.flags & 0x200 != 0 { println!("  - NOMULTIDEFS: 多重定義禁止"); }
    if header.flags & 0x400 != 0 { println!("  - NOFIXPREBINDING: プリバインド修正無効"); }
    if header.flags & 0x800 != 0 { println!("  - PREBINDABLE: プリバインド可能"); }
    if header.flags & 0x1000 != 0 { println!("  - ALLMODSBOUND: 全モジュールバインド済み"); }
    if header.flags & 0x2000 != 0 { println!("  - SUBSECTIONS_VIA_SYMBOLS: シンボル経由サブセクション"); }
    if header.flags & 0x4000 != 0 { println!("  - CANONICAL: 正規化済み"); }
    if header.flags & 0x8000 != 0 { println!("  - WEAK_DEFINES: 弱い定義あり"); }
    if header.flags & 0x10000 != 0 { println!("  - BINDS_TO_WEAK: 弱いシンボルへバインド"); }
    if header.flags & 0x20000 != 0 { println!("  - ALLOW_STACK_EXECUTION: スタック実行許可"); }
    if header.flags & 0x40000 != 0 { println!("  - ROOT_SAFE: root安全"); }
    if header.flags & 0x80000 != 0 { println!("  - SETUID_SAFE: setuid安全"); }
    if header.flags & 0x100000 != 0 { println!("  - NO_REEXPORTED_DYLIBS: 再エクスポートライブラリなし"); }
    if header.flags & 0x200000 != 0 { println!("  - PIE: 位置独立実行可能"); }
    if header.flags & 0x400000 != 0 { println!("  - DEAD_STRIPPABLE_DYLIB: デッドストリップ可能ライブラリ"); }
    if header.flags & 0x800000 != 0 { println!("  - HAS_TLV_DESCRIPTORS: TLVディスクリプタあり"); }
    if header.flags & 0x1000000 != 0 { println!("  - NO_HEAP_EXECUTION: ヒープ実行禁止"); }
    if header.flags & 0x2000000 != 0 { println!("  - APP_EXTENSION_SAFE: アプリ拡張安全"); }
    if header.flags & 0x4000000 != 0 { println!("  - NLIST_OUTOFSYNC_WITH_DYLDINFO: nlistがdyldinfoと非同期"); }
    if header.flags & 0x8000000 != 0 { println!("  - SIM_SUPPORT: シミュレーターサポート"); }
    
}

fn load_command_to_string(load_command: u32) -> String {
    match load_command {
        0x1 => "LC_SEGMENT".to_string(),
        0x2 => "LC_SYMTAB".to_string(),
        0x3 => "LC_SYMSEG".to_string(),
        0x4 => "LC_THREAD".to_string(),
        0x5 => "LC_UNIXTHREAD".to_string(),
        0x6 => "LC_LOADFVMLIB".to_string(),
        0x7 => "LC_IDFVMLIB".to_string(),
        0x8 => "LC_IDENT".to_string(),
        0x9 => "LC_FVMFILE".to_string(),
        0xa => "LC_PREPAGE".to_string(),
        0xb => "LC_DYSYMTAB".to_string(),
        0xc => "LC_LOAD_DYLIB".to_string(),
        0xd => "LC_ID_DYLIB".to_string(),
        0xe => "LC_LOAD_DYLINKER".to_string(),
        0xf => "LC_ID_DYLINKER".to_string(),
        0x10 => "LC_PREBOUND_DYLIB".to_string(),
        0x11 => "LC_ROUTINES".to_string(),
        0x12 => "LC_SUB_FRAMEWORK".to_string(),
        0x13 => "LC_SUB_UMBRELLA".to_string(),
        0x14 => "LC_SUB_CLIENT".to_string(),
        0x15 => "LC_TWOLEVEL_HINTS".to_string(),
        0x16 => "LC_PREBIND_CKSUM".to_string(),
        0x17 => "LC_LOAD_WEAK_DYLIB".to_string(),
        0x18 => "LC_SEGMENT_64".to_string(),
        0x19 => "LC_ROUTINES_64".to_string(),
        0x1a => "LC_UUID".to_string(),
        0x1b => "LC_RPATH".to_string(),
        0x1c => "LC_CODE_SIGNATURE".to_string(),
        0x1d => "LC_SEGMENT_SPLIT_INFO".to_string(),
        0x1e => "LC_REEXPORT_DYLIB".to_string(),
        0x1f => "LC_LAZY_LOAD_DYLIB".to_string(),
        0x20 => "LC_ENCRYPTION_INFO".to_string(),
        0x21 => "LC_DYLD_INFO".to_string(),
        0x22 => "LC_DYLD_INFO_ONLY".to_string(),
        0x23 => "LC_LOAD_UPWARD_DYLIB".to_string(),
        0x24 => "LC_VERSION_MIN_MACOSX".to_string(),
        0x25 => "LC_VERSION_MIN_IPHONEOS".to_string(),
        0x26 => "LC_FUNCTION_STARTS".to_string(),
        0x27 => "LC_DYLD_ENVIRONMENT".to_string(),
        0x28 => "LC_MAIN".to_string(),
        0x29 => "LC_DATA_IN_CODE".to_string(),
        0x2a => "LC_SOURCE_VERSION".to_string(),
        0x2b => "LC_DYLIB_CODE_SIGN_DRS".to_string(),
        0x2c => "LC_ENCRYPTION_INFO_64".to_string(),
        0x2d => "LC_LINKER_OPTION".to_string(),
        0x2e => "LC_LINKER_OPTIMIZATION_HINT".to_string(),
        0x2f => "LC_VERSION_MIN_TVOS".to_string(),
        0x30 => "LC_VERSION_MIN_WATCHOS".to_string(),
        0x31 => "LC_NOTE".to_string(),
        0x32 => "LC_BUILD_VERSION".to_string(),
        0x33 => "LC_DYLD_EXPORTS_TRIE".to_string(),
        0x34 => "LC_DYLD_CHAINED_FIXUPS".to_string(),
        _ => "不明".to_string(),
    }
}

fn get_die_tag_name(abbrev_code: u64, version: u16) -> &'static str {
    match version {
        1 => { // DWARF1
            match abbrev_code {
                0x01 => "DW_TAG_padding",
                0x02 => "DW_TAG_array_type",
                0x03 => "DW_TAG_class_type",
                0x04 => "DW_TAG_entry_point",
                0x05 => "DW_TAG_enumeration_type",
                0x06 => "DW_TAG_formal_parameter",
                0x08 => "DW_TAG_imported_declaration",
                0x0a => "DW_TAG_label",
                0x0b => "DW_TAG_lexical_block",
                0x0d => "DW_TAG_member",
                0x0f => "DW_TAG_pointer_type",
                0x10 => "DW_TAG_reference_type",
                0x11 => "DW_TAG_compile_unit",
                0x12 => "DW_TAG_string_type",
                0x13 => "DW_TAG_structure_type",
                0x15 => "DW_TAG_subroutine_type",
                0x16 => "DW_TAG_typedef",
                0x17 => "DW_TAG_union_type",
                0x18 => "DW_TAG_unspecified_parameters",
                0x19 => "DW_TAG_variant",
                0x1a => "DW_TAG_common_block",
                0x1b => "DW_TAG_common_inclusion",
                0x1c => "DW_TAG_inheritance",
                0x1d => "DW_TAG_inlined_subroutine",
                0x1e => "DW_TAG_module",
                0x1f => "DW_TAG_ptr_to_member_type",
                0x20 => "DW_TAG_set_type",
                0x21 => "DW_TAG_subrange_type",
                0x22 => "DW_TAG_with_stmt",
                0x23 => "DW_TAG_access_declaration",
                0x24 => "DW_TAG_base_type",
                0x25 => "DW_TAG_catch_block",
                0x26 => "DW_TAG_const_type",
                0x27 => "DW_TAG_constant",
                0x28 => "DW_TAG_enumerator",
                0x29 => "DW_TAG_file_type",
                0x2a => "DW_TAG_friend",
                0x2b => "DW_TAG_namelist",
                0x2c => "DW_TAG_namelist_item",
                0x2d => "DW_TAG_packed_type",
                0x2e => "DW_TAG_subprogram",
                0x2f => "DW_TAG_template_type_parameter",
                0x30 => "DW_TAG_template_value_parameter",
                0x31 => "DW_TAG_thrown_type",
                0x32 => "DW_TAG_try_block",
                0x33 => "DW_TAG_variant_part",
                0x34 => "DW_TAG_variable",
                0x35 => "DW_TAG_volatile_type",
                _ => "DW_TAG_unknown",
            }
        }
        2 | 3 | 4 | 5 => { // DWARF 2, 3, 4, 5
            match abbrev_code {
                0x01 => "DW_TAG_array_type",
                0x02 => "DW_TAG_class_type",
                0x03 => "DW_TAG_entry_point",
                0x04 => "DW_TAG_enumeration_type",
                0x05 => "DW_TAG_formal_parameter",
                0x08 => "DW_TAG_imported_declaration",
                0x0a => "DW_TAG_label",
                0x0b => "DW_TAG_lexical_block",
                0x0d => "DW_TAG_member",
                0x0f => "DW_TAG_pointer_type",
                0x10 => "DW_TAG_reference_type",
                0x11 => "DW_TAG_compile_unit",
                0x12 => "DW_TAG_string_type",
                0x13 => "DW_TAG_structure_type",
                0x15 => "DW_TAG_subroutine_type",
                0x16 => "DW_TAG_typedef",
                0x17 => "DW_TAG_union_type",
                0x18 => "DW_TAG_unspecified_parameters",
                0x19 => "DW_TAG_variant",
                0x1a => "DW_TAG_common_block",
                0x1b => "DW_TAG_common_inclusion",
                0x1c => "DW_TAG_inheritance",
                0x1d => "DW_TAG_inlined_subroutine",
                0x1e => "DW_TAG_module",
                0x1f => "DW_TAG_ptr_to_member_type",
                0x20 => "DW_TAG_set_type",
                0x21 => "DW_TAG_subrange_type",
                0x22 => "DW_TAG_with_stmt",
                0x23 => "DW_TAG_access_declaration",
                0x24 => "DW_TAG_base_type",
                0x25 => "DW_TAG_catch_block",
                0x26 => "DW_TAG_const_type",
                0x27 => "DW_TAG_constant",
                0x28 => "DW_TAG_enumerator",
                0x29 => "DW_TAG_file_type",
                0x2a => "DW_TAG_friend",
                0x2b => "DW_TAG_namelist",
                0x2c => "DW_TAG_namelist_item",
                0x2d => "DW_TAG_packed_type",
                0x2e => "DW_TAG_subprogram",
                0x2f => "DW_TAG_template_type_parameter",
                0x30 => "DW_TAG_template_value_parameter",
                0x31 => "DW_TAG_thrown_type",
                0x32 => "DW_TAG_try_block",
                0x33 => "DW_TAG_variant_part",
                0x34 => "DW_TAG_variable",
                0x35 => "DW_TAG_volatile_type",
                
                // DWARF 3 additions
                0x36 => "DW_TAG_dwarf_procedure",
                0x37 => "DW_TAG_restrict_type",
                0x38 => "DW_TAG_interface_type",
                0x39 => "DW_TAG_namespace",
                0x3a => "DW_TAG_imported_module",
                0x3b => "DW_TAG_unspecified_type",
                
                // DWARF 4 additions
                0x3c => "DW_TAG_partial_unit",
                0x3d => "DW_TAG_imported_unit",
                0x3f => "DW_TAG_condition",
                0x40 => "DW_TAG_shared_type",
                0x41 => "DW_TAG_type_unit",
                0x42 => "DW_TAG_rvalue_reference_type",
                0x43 => "DW_TAG_template_alias",
                
                // DWARF 5 additions
                0x44 => "DW_TAG_coarray_type",
                0x45 => "DW_TAG_generic_subrange",
                0x46 => "DW_TAG_dynamic_type",
                0x47 => "DW_TAG_atomic_type",
                0x48 => "DW_TAG_call_site",
                0x49 => "DW_TAG_call_site_parameter",
                0x4a => "DW_TAG_skeleton_unit",
                0x4b => "DW_TAG_immutable_type",
                
                _ => "DW_TAG_unknown",
            }
        }
        _ => "Unknown DWARF version",
    }
}

fn get_attr_name(attr_name_code: u64) -> &'static str {
    match attr_name_code {
        // DWARF 2
        0x01 => "DW_AT_sibling",
        0x02 => "DW_AT_location",
        0x03 => "DW_AT_name",
        0x09 => "DW_AT_ordering",
        0x0b => "DW_AT_byte_size",
        0x0c => "DW_AT_bit_offset",
        0x0d => "DW_AT_bit_size",
        0x10 => "DW_AT_stmt_list",
        0x11 => "DW_AT_low_pc",
        0x12 => "DW_AT_high_pc",
        0x13 => "DW_AT_language",
        0x15 => "DW_AT_discr",
        0x16 => "DW_AT_discr_value",
        0x17 => "DW_AT_visibility",
        0x18 => "DW_AT_import",
        0x19 => "DW_AT_string_length",
        0x1a => "DW_AT_common_reference",
        0x1b => "DW_AT_comp_dir",
        0x1c => "DW_AT_const_value",
        0x1d => "DW_AT_containing_type",
        0x1e => "DW_AT_default_value",
        0x20 => "DW_AT_inline",
        0x21 => "DW_AT_is_optional",
        0x22 => "DW_AT_lower_bound",
        0x25 => "DW_AT_producer",
        0x26 => "DW_AT_prototyped",
        0x28 => "DW_AT_return_addr",
        0x29 => "DW_AT_start_scope",
        0x2a => "DW_AT_stride_size",
        0x2b => "DW_AT_upper_bound",
        0x2c => "DW_AT_abstract_origin",
        0x2d => "DW_AT_accessibility",
        0x2e => "DW_AT_address_class",
        0x2f => "DW_AT_artificial",
        0x30 => "DW_AT_base_types",
        0x31 => "DW_AT_calling_convention",
        0x32 => "DW_AT_count",
        0x33 => "DW_AT_data_member_location",
        0x34 => "DW_AT_decl_column",
        0x35 => "DW_AT_decl_file",
        0x36 => "DW_AT_decl_line",
        0x37 => "DW_AT_declaration",
        0x38 => "DW_AT_discr_list",
        0x39 => "DW_AT_encoding",
        0x3a => "DW_AT_external",
        0x3b => "DW_AT_frame_base",
        0x3c => "DW_AT_friend",
        0x3d => "DW_AT_identifier_case",
        0x3e => "DW_AT_macro_info",
        0x3f => "DW_AT_namelist_item",
        0x40 => "DW_AT_priority",
        0x41 => "DW_AT_segment",
        0x42 => "DW_AT_specification",
        0x43 => "DW_AT_static_link",
        0x44 => "DW_AT_type",
        0x45 => "DW_AT_use_location",
        0x46 => "DW_AT_variable_parameter",
        0x47 => "DW_AT_virtuality",
        0x48 => "DW_AT_vtable_elem_location",
        // DWARF 3
        0x49 => "DW_AT_allocated",
        0x4a => "DW_AT_associated",
        0x4b => "DW_AT_data_location",
        0x4c => "DW_AT_byte_stride",
        0x4d => "DW_AT_entry_pc",
        0x4e => "DW_AT_use_UTF8",
        0x4f => "DW_AT_extension",
        0x50 => "DW_AT_ranges",
        0x51 => "DW_AT_trampoline",
        0x52 => "DW_AT_call_column",
        0x53 => "DW_AT_call_file",
        0x54 => "DW_AT_call_line",
        0x55 => "DW_AT_description",
        0x56 => "DW_AT_binary_scale",
        0x57 => "DW_AT_decimal_scale",
        0x58 => "DW_AT_small",
        0x59 => "DW_AT_decimal_sign",
        0x5a => "DW_AT_digit_count",
        0x5b => "DW_AT_picture_string",
        0x5c => "DW_AT_mutable",
        0x5d => "DW_AT_threads_scaled",
        0x5e => "DW_AT_explicit",
        0x5f => "DW_AT_object_pointer",
        0x60 => "DW_AT_endianity",
        0x61 => "DW_AT_elemental",
        0x62 => "DW_AT_pure",
        0x63 => "DW_AT_recursive",
        // DWARF 4
        0x64 => "DW_AT_signature",
        0x65 => "DW_AT_main_subprogram",
        0x66 => "DW_AT_data_bit_offset",
        0x67 => "DW_AT_const_expr",
        0x68 => "DW_AT_enum_class",
        0x69 => "DW_AT_linkage_name",
        // DWARF 5
        0x6a => "DW_AT_string_length_bit_size",
        0x6b => "DW_AT_string_length_byte_size",
        0x6c => "DW_AT_rank",
        0x6d => "DW_AT_str_offsets_base",
        0x6e => "DW_AT_addr_base",
        0x6f => "DW_AT_rnglists_base",
        0x70 => "DW_AT_dwo_name",
        0x71 => "DW_AT_reference",
        0x72 => "DW_AT_rvalue_reference",
        0x73 => "DW_AT_macros",
        0x74 => "DW_AT_call_all_calls",
        0x75 => "DW_AT_call_all_source_calls",
        0x76 => "DW_AT_call_all_tail_calls",
        0x77 => "DW_AT_call_return_pc",
        0x78 => "DW_AT_call_value",
        0x79 => "DW_AT_call_origin",
        0x7a => "DW_AT_call_parameter",
        0x7b => "DW_AT_call_pc",
        0x7c => "DW_AT_call_tail_call",
        0x7d => "DW_AT_call_target",
        0x7e => "DW_AT_call_target_clobbered",
        0x7f => "DW_AT_call_data_location",
        0x80 => "DW_AT_call_data_value",
        0x81 => "DW_AT_noreturn",
        0x82 => "DW_AT_alignment",
        0x83 => "DW_AT_export_symbols",
        0x84 => "DW_AT_deleted",
        0x85 => "DW_AT_defaulted",
        0x86 => "DW_AT_loclists_base",
        // GNU extensions
        0x2101 => "DW_AT_sf_names",
        0x2102 => "DW_AT_src_info",
        0x2103 => "DW_AT_mac_info",
        0x2104 => "DW_AT_src_coords",
        0x2105 => "DW_AT_body_begin",
        0x2106 => "DW_AT_body_end",
        0x2107 => "DW_AT_GNU_vector",
        0x2108 => "DW_AT_GNU_guarded_by",
        0x2109 => "DW_AT_GNU_pt_guarded_by",
        0x210a => "DW_AT_GNU_guarded",
        0x210b => "DW_AT_GNU_pt_guarded",
        0x210c => "DW_AT_GNU_locks_excluded",
        0x210d => "DW_AT_GNU_exclusive_locks_required",
        0x210e => "DW_AT_GNU_shared_locks_required",
        0x210f => "DW_AT_GNU_odr_signature",
        0x2110 => "DW_AT_GNU_template_name",
        0x2111 => "DW_AT_GNU_call_site_value",
        0x2112 => "DW_AT_GNU_call_site_data_value",
        0x2113 => "DW_AT_GNU_call_site_target",
        0x2114 => "DW_AT_GNU_call_site_target_clobbered",
        0x2115 => "DW_AT_GNU_tail_call",
        0x2116 => "DW_AT_GNU_all_tail_call_sites",
        0x2117 => "DW_AT_GNU_all_call_sites",
        0x2118 => "DW_AT_GNU_all_source_call_sites",
        0x2119 => "DW_AT_GNU_macros",
        0x211a => "DW_AT_GNU_deleted",
        0x211b => "DW_AT_GNU_dwo_name",
        0x211c => "DW_AT_GNU_dwo_id",
        0x211d => "DW_AT_GNU_ranges_base",
        0x211e => "DW_AT_GNU_addr_base",
        0x211f => "DW_AT_GNU_pubnames",
        0x2120 => "DW_AT_GNU_pubtypes",
        0x2121 => "DW_AT_GNU_discriminator",
        0x2122 => "DW_AT_GNU_locviews",
        0x2123 => "DW_AT_GNU_entry_view",
        
        // Apple extensions
        0x3fe1 => "DW_AT_APPLE_optimized",
        0x3fe2 => "DW_AT_APPLE_flags",
        0x3fe3 => "DW_AT_APPLE_isa",
        0x3fe4 => "DW_AT_APPLE_block",
        0x3fe5 => "DW_AT_APPLE_major_runtime_vers",
        0x3fe6 => "DW_AT_APPLE_runtime_class",
        0x3fe7 => "DW_AT_APPLE_omit_frame_ptr",
        0x3fe8 => "DW_AT_APPLE_property_name",
        0x3fe9 => "DW_AT_APPLE_property_getter",
        0x3fea => "DW_AT_APPLE_property_setter",
        0x3feb => "DW_AT_APPLE_property_attribute",
        0x3fec => "DW_AT_APPLE_objc_complete_type",
        0x3fed => "DW_AT_APPLE_property",
        
        // LLVM extensions
        0x3fee => "DW_AT_LLVM_include_path",
        0x3fef => "DW_AT_LLVM_config_macros",
        0x3ff0 => "DW_AT_LLVM_sysroot",
        0x3ff1 => "DW_AT_LLVM_tag_offset",
        0x3ff2 => "DW_AT_LLVM_apinotes",
        0x3ff3 => "DW_AT_LLVM_active_lane",
        0x3ff4 => "DW_AT_LLVM_augmentation",
        0x3ff5 => "DW_AT_LLVM_lanes",
        0x3ff6 => "DW_AT_LLVM_lane_pc",
        0x3ff7 => "DW_AT_LLVM_vector_size",
        _ => "Unknown or custom attribute",
    }
}

fn get_language_name(lang_code: u64) -> &'static str {
    match lang_code {
        0x0001 => "DW_LANG_C89",
        0x0002 => "DW_LANG_C",
        0x0003 => "DW_LANG_Ada83",
        0x0004 => "DW_LANG_C_plus_plus",
        0x0005 => "DW_LANG_Cobol74",
        0x0006 => "DW_LANG_Cobol85",
        0x0007 => "DW_LANG_Fortran77",
        0x0008 => "DW_LANG_Fortran90",
        0x0009 => "DW_LANG_Pascal83",
        0x000a => "DW_LANG_Modula2",
        0x000b => "DW_LANG_Java",
        0x000c => "DW_LANG_C99",
        0x000d => "DW_LANG_Ada95",
        0x000e => "DW_LANG_Fortran95",
        0x000f => "DW_LANG_PLI",
        0x0010 => "DW_LANG_ObjC",
        0x0011 => "DW_LANG_ObjC_plus_plus",
        0x0012 => "DW_LANG_UPC",
        0x0013 => "DW_LANG_D",
        0x0014 => "DW_LANG_Python",
        0x0015 => "DW_LANG_OpenCL",
        0x0016 => "DW_LANG_Go",
        0x0017 => "DW_LANG_Modula3",
        0x0018 => "DW_LANG_Haskell",
        0x0019 => "DW_LANG_C_plus_plus_03",
        0x001a => "DW_LANG_C_plus_plus_11",
        0x001b => "DW_LANG_OCaml",
        0x001c => "DW_LANG_Rust",
        0x001d => "DW_LANG_C11",
        0x001e => "DW_LANG_Swift",
        0x001f => "DW_LANG_Julia",
        0x0020 => "DW_LANG_Dylan",
        0x0021 => "DW_LANG_C_plus_plus_14",
        0x0022 => "DW_LANG_Fortran03",
        0x0023 => "DW_LANG_Fortran08",
        0x0024 => "DW_LANG_RenderScript",
        0x0025 => "DW_LANG_BLISS",
        0x0026 => "DW_LANG_Kotlin",
        0x0027 => "DW_LANG_Zig",
        0x0028 => "DW_LANG_Crystal",
        0x0029 => "DW_LANG_C_plus_plus_17",
        0x002a => "DW_LANG_C_plus_plus_20",
        0x002b => "DW_LANG_C17",
        0x002c => "DW_LANG_Fortran18",
        0x002d => "DW_LANG_Ada2005",
        0x002e => "DW_LANG_Ada2012",
        0x8001 => "DW_LANG_Mips_Assembler",
        0x8002 => "DW_LANG_GOOGLE_RenderScript",
        0x8003 => "DW_LANG_SUN_Assembler",
        _ => "Unknown Language",
    }
}

fn get_language_description(lang_code: u64) -> &'static str {
    match lang_code {
        0x0001 => "C89コンパイラ (ANSI C 1989)",
        0x0002 => "Cコンパイラ (K&R C または C90)",
        0x0003 => "Ada83コンパイラ",
        0x0004 => "C++コンパイラ (初期版)",
        0x0005 => "COBOL74コンパイラ",
        0x0006 => "COBOL85コンパイラ",
        0x0007 => "Fortran77コンパイラ",
        0x0008 => "Fortran90コンパイラ",
        0x0009 => "Pascal83コンパイラ",
        0x000a => "Modula-2コンパイラ",
        
        // DWARF 3
        0x000b => "Javaコンパイラ (javac)",
        0x000c => "C99コンパイラ (ISO C 1999)",
        0x000d => "Ada95コンパイラ",
        0x000e => "Fortran95コンパイラ",
        0x000f => "PL/Iコンパイラ",
        0x0010 => "Objective-Cコンパイラ (clang/gcc)",
        0x0011 => "Objective-C++コンパイラ",
        0x0012 => "UPCコンパイラ (Unified Parallel C)",
        0x0013 => "Dコンパイラ (dmd/gdc/ldc)",
        
        // DWARF 4
        0x0014 => "Pythonインタープリター/コンパイラ (CPython/PyPy)",
        0x0015 => "OpenCLコンパイラ",
        0x0016 => "Goコンパイラ (gc/gccgo)",
        0x0017 => "Modula-3コンパイラ",
        0x0018 => "Haskellコンパイラ (GHC)",
        0x0019 => "C++03コンパイラ (ISO C++ 2003)",
        0x001a => "C++11コンパイラ (ISO C++ 2011)",
        0x001b => "OCamlコンパイラ",
        
        // DWARF 5
        0x001c => "Rustコンパイラ (rustc)",
        0x001d => "C11コンパイラ (ISO C 2011)",
        0x001e => "Swiftコンパイラ (swiftc)",
        0x001f => "Juliaコンパイラ/JIT",
        0x0020 => "Dylanコンパイラ",
        0x0021 => "C++14コンパイラ (ISO C++ 2014)",
        0x0022 => "Fortran03コンパイラ (ISO Fortran 2003)",
        0x0023 => "Fortran08コンパイラ (ISO Fortran 2008)",
        0x0024 => "RenderScriptコンパイラ (Android)",
        0x0025 => "BLISSコンパイラ",
        0x0026 => "Kotlinコンパイラ (kotlinc)",
        0x0027 => "Zigコンパイラ (zig)",
        0x0028 => "Crystalコンパイラ",
        0x0029 => "C++17コンパイラ (ISO C++ 2017)",
        0x002a => "C++20コンパイラ (ISO C++ 2020)",
        0x002b => "C17コンパイラ (ISO C 2018)",
        0x002c => "Fortran18コンパイラ (ISO Fortran 2018)",
        0x002d => "Ada2005コンパイラ (ISO Ada 2005)",
        0x002e => "Ada2012コンパイラ (ISO Ada 2012)",
        
        _ => "不明なコンパイラ",
    }
}

fn get_form_name(form_code: u64) -> &'static str {
    match form_code {
        // DWARF 2
        0x01 => "DW_FORM_addr",
        0x03 => "DW_FORM_block2",
        0x04 => "DW_FORM_block4",
        0x05 => "DW_FORM_data2",
        0x06 => "DW_FORM_data4",
        0x07 => "DW_FORM_data8",
        0x08 => "DW_FORM_string",
        0x09 => "DW_FORM_block",
        0x0a => "DW_FORM_block1",
        0x0b => "DW_FORM_data1",
        0x0c => "DW_FORM_flag",
        0x0d => "DW_FORM_sdata",
        0x0e => "DW_FORM_strp",
        0x0f => "DW_FORM_udata",
        0x10 => "DW_FORM_ref_addr",
        0x11 => "DW_FORM_ref1",
        0x12 => "DW_FORM_ref2",
        0x13 => "DW_FORM_ref4",
        0x14 => "DW_FORM_ref8",
        0x15 => "DW_FORM_ref_udata",
        0x16 => "DW_FORM_indirect",
        
        // DWARF 3
        0x17 => "DW_FORM_sec_offset",
        0x18 => "DW_FORM_exprloc",
        0x19 => "DW_FORM_flag_present",
        
        // DWARF 4
        0x1a => "DW_FORM_strx",
        0x1b => "DW_FORM_addrx",
        0x1c => "DW_FORM_ref_sup4",
        0x1d => "DW_FORM_strp_sup",
        0x1e => "DW_FORM_data16",
        0x1f => "DW_FORM_line_strp",
        
        // DWARF 5
        0x20 => "DW_FORM_ref_sig8",
        0x21 => "DW_FORM_implicit_const",
        0x22 => "DW_FORM_loclistx",
        0x23 => "DW_FORM_rnglistx",
        0x24 => "DW_FORM_ref_sup8",
        0x25 => "DW_FORM_strx1",
        0x26 => "DW_FORM_strx2",
        0x27 => "DW_FORM_strx3",
        0x28 => "DW_FORM_strx4",
        0x29 => "DW_FORM_addrx1",
        0x2a => "DW_FORM_addrx2",
        0x2b => "DW_FORM_addrx3",
        0x2c => "DW_FORM_addrx4",
        
        _ => "DW_FORM_unknown",
    }
}

fn parse_and_display_debug_abbrev(buffer: &[u8], section: &SectionInfo, version: u16) {
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;

    if start_offset >= buffer.len() || section_size == 0 {
        println!("エラー: __debug_abbrevセクションのデータが無効です");
        return;
    }

    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];

    println!("Abbrev table for offset: 0x{:08x}", 0);

    let mut offset = 0;

    while offset < section_data.len() {
        let (abbrev_code, consumed) = read_uleb128(&section_data[offset..]);
        offset += consumed;

        if abbrev_code == 0 {
            if offset >= section_data.len() || section_data[offset..].iter().all(|&b| b == 0) {
                break;
            }
            continue;
        }

        if offset >= section_data.len() {
            break;
        }

        let (tag_code, consumed) = read_uleb128(&section_data[offset..]);
        offset += consumed;
        let tag_name = get_die_tag_name(tag_code, version);
        
        let (has_children_val, consumed) = read_uleb128(&section_data[offset..]);
        offset += consumed;
        let has_children = if has_children_val != 0 { "DW_CHILDREN_yes" } else { "DW_CHILDREN_no" };

        println!("[{}] {}\t{}", abbrev_code, tag_name, has_children);

        loop {
            if offset >= section_data.len() {
                break;
            }

            let (attr_name_code, consumed) = read_uleb128(&section_data[offset..]);
            offset += consumed;

            let (attr_form_code, consumed) = read_uleb128(&section_data[offset..]);
            offset += consumed;

            if attr_name_code == 0 && attr_form_code == 0 {
                break;
            }

            let attr_name = get_attr_name(attr_name_code);
            let form_name = get_form_name(attr_form_code);

            println!("\t{}\t{}", attr_name, form_name);
        }
        
        println!();
    }
}

fn parse_and_display_debug_aranges(buffer: &[u8], section: &SectionInfo) {
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("    エラー: __debug_arangesセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("    === __debug_aranges 詳細解析 ===");
    
    // アドレス範囲テーブルヘッダーを解析
    let unit_length = u32::from_le_bytes([
        section_data[0], section_data[1], section_data[2], section_data[3]
    ]);
    let version = u16::from_le_bytes([
        section_data[4], section_data[5]
    ]);
    let debug_info_offset = u32::from_le_bytes([
        section_data[6], section_data[7], section_data[8], section_data[9]
    ]);
    let address_size = section_data[10];
    let segment_size = section_data[11];
    
    println!("    ユニット長: {} バイト", unit_length);
    println!("    バージョン: {}", version);
    println!("    debug_infoオフセット: 0x{:08x}", debug_info_offset);
    println!("    アドレスサイズ: {} バイト", address_size);
    println!("    セグメントサイズ: {} バイト", segment_size);
    
    // アドレス範囲エントリを全件表示
    let mut offset = 12;
    let mut range_count = 0;
    
    // パディングをスキップ
    while offset % (address_size as usize * 2) != 0 && offset < section_data.len() {
        offset += 1;
    }
    
    println!("\n    --- アドレス範囲エントリ ---");
    
    while offset + (address_size as usize * 2) <= section_data.len() {
        let start_addr = if address_size == 8 {
            u64::from_le_bytes([
                section_data[offset], section_data[offset + 1],
                section_data[offset + 2], section_data[offset + 3],
                section_data[offset + 4], section_data[offset + 5],
                section_data[offset + 6], section_data[offset + 7]
            ])
        } else {
            u32::from_le_bytes([
                section_data[offset], section_data[offset + 1],
                section_data[offset + 2], section_data[offset + 3]
            ]) as u64
        };
        offset += address_size as usize;
        
        let length = if address_size == 8 {
            u64::from_le_bytes([
                section_data[offset], section_data[offset + 1],
                section_data[offset + 2], section_data[offset + 3],
                section_data[offset + 4], section_data[offset + 5],
                section_data[offset + 6], section_data[offset + 7]
            ])
        } else {
            u32::from_le_bytes([
                section_data[offset], section_data[offset + 1],
                section_data[offset + 2], section_data[offset + 3]
            ]) as u64
        };
        offset += address_size as usize;
        
        if start_addr == 0 && length == 0 {
            println!("    {}: 終端エントリ", range_count + 1);
            break;
        }
        
        println!("    {}: 0x{:08x} - 0x{:08x} (長さ: {} バイト)",
                 range_count + 1, start_addr, start_addr + length, length);
        
        range_count += 1;
    }
    
    if range_count == 0 {
        println!("    (アドレス範囲エントリが見つかりませんでした)");
    }
}

// 未実装のdebug関数群（プレースホルダー）
fn parse_and_display_debug_ranges(_buffer: &[u8], section: &SectionInfo) {
    println!("    __debug_ranges: {} バイト (未実装)", section.size);
}

fn parse_and_display_debug_loc(_buffer: &[u8], section: &SectionInfo) {
    println!("    __debug_loc: {} バイト (未実装)", section.size);
}

fn parse_and_display_debug_pubnames(_buffer: &[u8], section: &SectionInfo) {
    println!("    __debug_pubnames: {} バイト (未実装)", section.size);
}

fn parse_and_display_debug_pubtypes(_buffer: &[u8], section: &SectionInfo) {
    println!("    __debug_pubtypes: {} バイト (未実装)", section.size);
}

fn parse_and_display_debug_frame(_buffer: &[u8], section: &SectionInfo) {
    println!("    __debug_frame: {} バイト (未実装)", section.size);
}

fn parse_and_display_eh_frame(_buffer: &[u8], section: &SectionInfo) {
    println!("    __eh_frame: {} バイト (未実装)", section.size);
}

fn display_stubs_and_following_section(buffer: &[u8], sections: &HashMap<String, SectionInfo>) {

    // __stubsセクション取得
    let stubs_section = match find_section_by_name(sections, "__stubs") {
        Some(s) => s,
        None => {
            println!("__stubsセクションが見つかりません");
            return;
        }
    };
    println!("\n=== __stubs セクション内容 ===");
    display_section_hexdump(buffer, stubs_section);

    // ファイルオフセット順で__stubs直後のセクションを探す
    let stubs_end = stubs_section.offset as u64 + stubs_section.size;
    let mut following: Option<&SectionInfo> = None;
    let mut min_offset = u64::MAX;
    for s in sections.values() {
        if s.offset as u64 >= stubs_end && (s.offset as u64) < min_offset && s.offset != stubs_section.offset {
            min_offset = s.offset as u64;
            following = Some(s);
        }
    }
    if let Some(sec) = following {
        println!("\n=== __stubs直後のセクション [{}] ({}) ===", sec.name, sec.seg_name);
        display_section_hexdump(buffer, sec);
    } else {
        println!("__stubs直後のセクションは見つかりませんでした");
    }
}

// DWARF5 __debug_str_offs__DWARFセクション専用の16進ダンプ関数
fn display_debug_str_offsets_hexdump(buffer: &[u8], section: &SectionInfo) {
    println!("DWARF5 __debug_str_offs__DWARFセクション 16進ダンプ");
    println!("セクション: {} (セグメント: {})", section.name, section.seg_name);
    println!("  ファイルオフセット: 0x{:08x}", section.offset);
    println!("  サイズ: {} バイト", section.size);
    
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    if start_offset >= buffer.len() || section_size == 0 {
        println!("  エラー: セクションデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    // DWARF5の文字列オフセットテーブルの構造を解析
    if section_data.len() < 8 {
        println!("  エラー: セクションサイズが小さすぎます");
        return;
    }
    
    // ヘッダー情報を表示
    println!("\n--- ヘッダー情報 ---");
    let unit_length = u32::from_le_bytes([
        section_data[0], section_data[1], section_data[2], section_data[3]
    ]);
    let version = u16::from_le_bytes([section_data[4], section_data[5]]);
    let padding = u16::from_le_bytes([section_data[6], section_data[7]]);
    
    println!("  ユニット長: {} バイト (0x{:08x})", unit_length, unit_length);
    println!("  バージョン: {} (0x{:04x})", version, version);
    println!("  パディング: 0x{:04x}", padding);
    
    // 16進ダンプ表示
    println!("\n--- 16進ダンプ ---");
    let max_dump = std::cmp::min(section_data.len(), 1024); // 最大1024バイト表示
    for (i, chunk) in section_data[..max_dump].chunks(16).enumerate() {
        print!("    {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!(" | ");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' };
            print!("{}", c);
        }
        println!(" |");
    }
    
    // オフセットテーブルの解釈（8バイト以降）
    if section_data.len() > 8 {
        println!("\n--- 文字列オフセットテーブル解釈 ---");
        let offset_data = &section_data[8..];
        let mut offset_index = 0;
        
        // 4バイト単位でオフセットを読み取り
        for chunk in offset_data.chunks(4) {
            if chunk.len() == 4 {
                let offset = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                println!("  [{}]: 0x{:08x} ({})", offset_index, offset, offset);
                offset_index += 1;
                
                // 最大20個のオフセットを表示
                if offset_index >= 20 {
                    break;
                }
            }
        }
        
        if offset_data.len() > 80 { // 20 * 4バイト
            println!("  ... (省略。残り: {} バイト)", offset_data.len() - 80);
        }
    }
    
    if section_data.len() > max_dump {
        println!("\n... (16進ダンプ省略。全体: {} バイト)", section_data.len());
    }
}

// DWARF __debug_strセクション専用の16進ダンプ関数
fn display_debug_str_hexdump(buffer: &[u8], section: &SectionInfo) {
    println!("DWARF __debug_strセクション 16進ダンプ");
    println!("セクション: {} (セグメント: {})", section.name, section.seg_name);
    println!("  ファイルオフセット: 0x{:08x}", section.offset);
    println!("  サイズ: {} バイト", section.size);
    
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    if start_offset >= buffer.len() || section_size == 0 {
        println!("  エラー: セクションデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    // 16進ダンプ表示
    println!("\n--- 16進ダンプ ---");
    let max_dump = std::cmp::min(section_data.len(), 2048); // 最大2048バイト表示
    for (i, chunk) in section_data[..max_dump].chunks(16).enumerate() {
        print!("    {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!(" | ");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' };
            print!("{}", c);
        }
        println!(" |");
    }
    
    // 文字列解析（NULL終端文字列を抽出）
    println!("\n--- 文字列解析 ---");
    let mut string_count = 0;
    let mut current_offset = 0;
    let mut current_string = Vec::new();
    
    for (i, &byte) in section_data.iter().enumerate() {
        if byte == 0 {
            // NULL終端文字列の終了
            if !current_string.is_empty() {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    if s.trim().len() > 0 { // 空文字列以外を表示
                        println!("  [0x{:04x}]: \"{}\"", current_offset, s);
                        string_count += 1;
                        
                        // 最大20個の文字列を表示
                        if string_count >= 20 {
                            break;
                        }
                    }
                }
                current_string.clear();
            }
            current_offset = i + 1;
        } else {
            if current_string.is_empty() {
                current_offset = i;
            }
            current_string.push(byte);
        }
    }
    
    // 残りの文字列があれば表示
    if !current_string.is_empty() && string_count < 20 {
        if let Ok(s) = String::from_utf8(current_string) {
            if s.trim().len() > 0 {
                println!("  [0x{:04x}]: \"{}\"", current_offset, s);
                string_count += 1;
            }
        }
    }
    
    if string_count >= 20 {
        println!("  ... (省略。最大20個の文字列を表示)");
    }
    
    if section_data.len() > max_dump {
        println!("\n... (16進ダンプ省略。全体: {} バイト)", section_data.len());
    }
    
    println!("\n文字列総数: {} 個 (表示: {} 個)", 
             section_data.iter().filter(|&&b| b == 0).count(),
             string_count);
}

// DWARF __debug_strセクションの内容を文字列として表示
fn display_debug_str(buffer: &[u8], section: &SectionInfo) {
    println!("DWARF __debug_strセクション 文字列表示");
    println!("セクション: {} (セグメント: {})", section.name, section.seg_name);
    println!("  ファイルオフセット: 0x{:08x}", section.offset);
    println!("  サイズ: {} バイト", section.size);
    
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    if start_offset >= buffer.len() || section_size == 0 {
        println!("  エラー: セクションデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("\n--- 文字列一覧 ---");
    let mut string_count = 0;
    let mut current_offset = 0;
    let mut current_string = Vec::new();
    let mut total_strings = 0;
    
    // 全ての文字列を抽出
    let mut all_strings = Vec::new();
    
    for (i, &byte) in section_data.iter().enumerate() {
        if byte == 0 {
            // NULL終端文字列の終了
            if !current_string.is_empty() {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    if s.trim().len() > 0 { // 空文字列以外を記録
                        all_strings.push((current_offset, s));
                        total_strings += 1;
                    }
                }
                current_string.clear();
            }
            current_offset = i + 1;
        } else {
            if current_string.is_empty() {
                current_offset = i;
            }
            current_string.push(byte);
        }
    }
    
    // 残りの文字列があれば追加
    if !current_string.is_empty() {
        if let Ok(s) = String::from_utf8(current_string) {
            if s.trim().len() > 0 {
                all_strings.push((current_offset, s));
                total_strings += 1;
            }
        }
    }
    
    // 文字列を表示（最大50個）
    for (offset, string) in all_strings.iter().take(50) {
        println!("  [0x{:04x}]: \"{}\"", offset, string);
        string_count += 1;
    }
    
    if total_strings > 50 {
        println!("  ... (省略。残り {} 個の文字列)", total_strings - 50);
    }
    
    // 統計情報
    println!("\n--- 統計情報 ---");
    println!("  文字列総数: {} 個", total_strings);
    println!("  表示数: {} 個", string_count);
    
    // 長い文字列トップ5を表示
    let mut long_strings: Vec<_> = all_strings.iter()
        .filter(|(_, s)| s.len() > 20)
        .collect();
    long_strings.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    
    if !long_strings.is_empty() {
        println!("\n--- 長い文字列 (トップ5) ---");
        for (offset, string) in long_strings.iter().take(5) {
            let display_str = if string.len() > 80 {
                format!("{}...", &string[..77])
            } else {
                string.clone()
            };
            println!("  [0x{:04x}] ({} 文字): \"{}\"", offset, string.len(), display_str);
        }
    }
    
    // 文字列の種類を分析
    let mut compiler_strings = 0;
    let mut path_strings = 0;
    let mut function_strings = 0;
    
    for (_, string) in &all_strings {
        let lower = string.to_lowercase();
        if lower.contains("clang") || lower.contains("gcc") || lower.contains("compiler") {
            compiler_strings += 1;
        } else if string.contains("/") || string.contains("\\") {
            path_strings += 1;
        } else if lower.contains("func") || lower.contains("main") || lower.contains("init") {
            function_strings += 1;
        }
    }
    
    println!("\n--- 文字列分類 ---");
    println!("  コンパイラ関連: {} 個", compiler_strings);
    println!("  パス関連: {} 個", path_strings);
    println!("  関数関連: {} 個", function_strings);
    println!("  その他: {} 個", total_strings - compiler_strings - path_strings - function_strings);
}

fn display_section_hexdump(buffer: &[u8], section: &SectionInfo) {
    println!("セクション: {} (セグメント: {})", section.name, section.seg_name);
    println!("  ファイルオフセット: 0x{:08x}", section.offset);
    println!("  サイズ: {} バイト", section.size);
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    if start_offset >= buffer.len() || section_size == 0 {
        println!("  エラー: セクションデータが無効です");
        return;
    }
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    let max_dump = std::cmp::min(section_data.len(), 512); // 最大512バイト表示
    for (i, chunk) in section_data[..max_dump].chunks(16).enumerate() {
        print!("    {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!(" | ");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' };
            print!("{}", c);
        }
        println!(" |");
    }
    if section_data.len() > max_dump {
        println!("    ... (省略。全体: {} バイト)", section_data.len());
    }
}

fn display_unwind_info_section(buffer: &[u8], section: &SectionInfo) {
    println!("\n=== __unwind_info セクション内容 ===");
    display_section_hexdump(buffer, section);
}

fn display_got_section(buffer: &[u8], section: &SectionInfo) {
    println!("\n=== __got セクション内容 ===");
    display_section_hexdump(buffer, section);
}

fn display_stubs_section(buffer: &[u8], section: &SectionInfo, arch: CpuArchitecture) {
    println!("\n=== __stubs セクション内容 (arch: {}) ===", arch.name());
    println!("※ オフセット解釈は32ビット(u32, 4バイト単位)固定です");
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    if start_offset >= buffer.len() || section_size == 0 {
        println!("エラー: __stubsセクションのデータが無効です");
        return;
    }
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    let max_dump = std::cmp::min(section_data.len(), 512); // 最大512バイト表示
    for (i, chunk) in section_data[..max_dump].chunks(16).enumerate() {
        print!("  {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!(" | ");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' };
            print!("{}", c);
        }
        println!(" |");
    }
    if section_data.len() > max_dump {
        println!("  ... (省略。全体: {} バイト)", section_data.len());
    }
    println!("  (offset: 0x{:x}, size: {}バイト)", section.offset, section.size);

    // --- 追加: 各ワード値をオフセットとして文字列取得 ---
    println!("\n");
    let word_size = 4; // 32ビット固定
    if section_data.len() < word_size {
        println!("  __stubsセクションが短すぎます");
        return;
    }
    // 最初の値＝文字列テーブルの先頭
    let strtab_offset = u32::from_le_bytes(section_data[0..4].try_into().unwrap()) as usize;
    if strtab_offset < buffer.len() {
        let mut end = strtab_offset;
        while end < buffer.len() && buffer[end] != 0 {
            end += 1;
        }
        let s = &buffer[strtab_offset..end];
        if let Ok(s) = std::str::from_utf8(s) {
            println!("  先頭文字列: '{}'", s);
        } else {
            println!("  先頭文字列: (非UTF8)");
        }
    }


    // --- __stubs命令列の簡易解析 ---
    println!("\n[__stubs命令列の簡易解析]");
    match arch {
        CpuArchitecture::X86_64 => {
            let mut addr = section.addr;
            let mut offset = 0usize;
            while offset < section_data.len() {
                if offset + 6 <= section_data.len() && section_data[offset] == 0xff && section_data[offset+1] == 0x25 {
                    let disp = u32::from_le_bytes([
                        section_data[offset+2], section_data[offset+3], section_data[offset+4], section_data[offset+5]
                    ]) as u64;
                    let target = addr + 6 + disp;
                    println!(
                        "  0x{:016x}: ff 25 {:02x} {:02x} {:02x} {:02x}    ; jmp QWORD PTR [rip+0x{:x}] -> [0x{:016x}]",
                        addr,
                        section_data[offset+2], section_data[offset+3], section_data[offset+4], section_data[offset+5],
                        disp, target
                    );
                    offset += 6;
                    addr += 6;
                    continue;
                }
                // その他: バイトを表示
                println!("  0x{:016x}: {:02x}", addr, section_data[offset]);
                offset += 1;
                addr += 1;
            }
        }
        CpuArchitecture::ARM64 => {
            let mut addr = section.addr;
            let mut offset = 0usize;
            // ARM64は4バイト(32bit)命令固定
            while offset + 4 <= section_data.len() {
                // 先に一般的なスタブの4命令(16バイト)をまとめて検出
                if offset + 16 <= section_data.len() {
                    let adrp = u32::from_le_bytes([section_data[offset], section_data[offset+1], section_data[offset+2], section_data[offset+3]]);
                    let add  = u32::from_le_bytes([section_data[offset+4], section_data[offset+5], section_data[offset+6], section_data[offset+7]]);
                    let ldr  = u32::from_le_bytes([section_data[offset+8], section_data[offset+9], section_data[offset+10], section_data[offset+11]]);
                    let br   = u32::from_le_bytes([section_data[offset+12], section_data[offset+13], section_data[offset+14], section_data[offset+15]]);
                    let is_adrp = (adrp & 0x9f00_0000) == 0x9000_0000; // ADRP
                    let is_add  = (add  & 0xffc0_0000) == 0x9100_0000; // ADD (immediate)
                    let is_ldr  = (ldr  & 0xff00_0000) == 0xf900_0000; // LDR (unsigned offset, 64-bit)
                    let is_br   = (br   & 0xffff_fc1f) == 0xd61f_0000; // BR Xn
                    if is_adrp && is_add && is_ldr && is_br {
                        println!(
                            "  0x{:016x}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}    ; ARM64 stub: adrp; add; ldr; br",
                            addr,
                            section_data[offset], section_data[offset+1], section_data[offset+2], section_data[offset+3],
                            section_data[offset+4], section_data[offset+5], section_data[offset+6], section_data[offset+7],
                            section_data[offset+8], section_data[offset+9], section_data[offset+10], section_data[offset+11],
                            section_data[offset+12], section_data[offset+13], section_data[offset+14], section_data[offset+15]
                        );
                        offset += 16;
                        addr += 16;
                        continue;
                    }
                }
                // 単発命令の簡易表示
                let ins = u32::from_le_bytes([section_data[offset], section_data[offset+1], section_data[offset+2], section_data[offset+3]]);
                let mnem = if (ins & 0x9f00_0000) == 0x9000_0000 { "adrp" }
                           else if (ins & 0xffc0_0000) == 0x9100_0000 { "add" }
                           else if (ins & 0xff00_0000) == 0xf900_0000 { "ldr" }
                           else if (ins & 0xffff_fc1f) == 0xd61f_0000 { "br" }
                           else { "(unknown)" };
                println!(
                    "  0x{:016x}: {:02x} {:02x} {:02x} {:02x}    ; {}",
                    addr, section_data[offset], section_data[offset+1], section_data[offset+2], section_data[offset+3], mnem
                );
                offset += 4;
                addr += 4;
            }
        }
        _ => {
            println!("  (このアーキテクチャの逆アセンブルは簡易表示のみ)");
            let mut addr = section.addr;
            for b in section_data.iter() {
                println!("  0x{:016x}: {:02x}", addr, *b);
                addr += 1;
            }
        }
    }
}



fn display_apple_names_section(buffer: &[u8], section: &SectionInfo) {
    println!("\n=== __apple_names セクション内容 ===");
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    if start_offset >= buffer.len() || section_size == 0 {
        println!("エラー: __apple_namesセクションのデータが無効です");
        return;
    }
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    let max_dump = std::cmp::min(section_data.len(), 512); // 最大512バイト表示
    for (i, chunk) in section_data[..max_dump].chunks(16).enumerate() {
        print!("  {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!(" | ");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' };
            print!("{}", c);
        }
        println!(" |");
    }
    if section_data.len() > max_dump {
        println!("  ... (省略。全体: {} バイト)", section_data.len());
    }
}

fn parse_and_display_debug_line_str(buffer: &[u8], section: &SectionInfo) {
    println!("    === __debug_line_str 詳細解析 ===");
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("    エラー: __debug_line_strセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("    文字列テーブルサイズ: {} バイト", section_data.len());
    
    // 文字列を抽出して表示
    let mut offset = 0;
    let mut string_count = 0;
    let max_strings = 20;
    
    println!("\n    --- 文字列一覧 (最初の{}個) ---", max_strings);
    
    while offset < section_data.len() && string_count < max_strings {
        let (string_value, consumed) = extract_null_terminated_string(&section_data[offset..]);
        
        if !string_value.is_empty() {
            println!("    {}: [0x{:04x}] {}", string_count, offset, string_value);
            string_count += 1;
        }
        
        offset += consumed;
        
        // 安全のため、無限ループを防ぐ
        if consumed == 0 {
            break;
        }
    }
    
    if string_count == 0 {
        println!("    (文字列が見つかりませんでした)");
    }
}


// DWARF省略形エントリ構造体
#[derive(Debug, Clone)]
pub struct AbbrevEntry {
    pub code: u64,
    pub tag: u64,
    pub has_children: bool,
    pub attributes: Vec<(u64, u64)>, // (attr_name, attr_form)
}


/// __debug_abbrevセクションからabbrevテーブルをパースし、abbrev_code→AbbrevEntryのマップを返す
fn parse_abbrev_table(buffer: &[u8], section: &SectionInfo, abbrev_offset: u32) -> HashMap<u64, AbbrevEntry> {
    let start_offset = section.offset as usize + abbrev_offset as usize;
    let section_size = section.size as usize;
    let mut abbrev_map = HashMap::new();
    if start_offset >= buffer.len() || section_size == 0 {
        return abbrev_map;
    }
    let actual_end = std::cmp::min(section.offset as usize + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    let mut offset = 0;
    loop {
        let (code, consumed) = read_uleb128(&section_data[offset..]);
        offset += consumed;
        if code == 0 {
            // NULL entry: abbrevテーブル終端
            break;
        }
        let (tag, consumed2) = read_uleb128(&section_data[offset..]);
        offset += consumed2;
        let has_children = match section_data[offset] {
            0 => false,
            1 => true,
            v => {
                // 不正値
                eprintln!("    [abbrev] 警告: has_children値が不正: {}", v);
                false
            }
        };
        offset += 1;
        let mut attributes = Vec::new();
        loop {
            let (attr_name, c1) = read_uleb128(&section_data[offset..]);
            offset += c1;
            let (attr_form, c2) = read_uleb128(&section_data[offset..]);
            offset += c2;
            if attr_name == 0 && attr_form == 0 {
                break;
            }
            attributes.push((attr_name, attr_form));
        }
        abbrev_map.insert(code, AbbrevEntry {
            code,
            tag,
            has_children,
            attributes,
        });
    }
    abbrev_map
}

fn display_die_tree(
    section_data: &[u8],
    offset: &mut usize,
    abbrev_map: &std::collections::HashMap<u64, AbbrevEntry>,
    depth: usize,
    version: u16,
    debug_str_buf: Option<&[u8]>,
    debug_str_off: Option<u32>,
    debug_str_size: Option<u32>,
    address_size: usize,
    macho_header: &mach_header_64,
    text_addr: u64,
) {
    let (abbrev_code, consumed) = read_uleb128(&section_data[*offset..]);
    *offset += consumed;
    display_die_tree_recursive(section_data, abbrev_code, offset, abbrev_map, depth, version, debug_str_buf, debug_str_off, debug_str_size, address_size, macho_header, text_addr);
}

fn display_die_tree_recursive(
    section_data: &[u8],
    abbrev_code: u64,
    offset: &mut usize,
    abbrev_map: &std::collections::HashMap<u64, AbbrevEntry>,
    depth: usize,
    version: u16,
    debug_str_buf: Option<&[u8]>,
    debug_str_off: Option<u32>,
    debug_str_size: Option<u32>,
    address_size: usize,
    macho_header: &mach_header_64,
    text_addr: u64,
) {
    let indent = "  ".repeat(depth);
    let die_start = *offset;

    if abbrev_code == 0 {
        println!("{}<NULL DIE>", indent);
        return;
    }
    let abbrev = match abbrev_map.get(&abbrev_code) {
        Some(a) => a,
        None => {
            println!("{}[未知のabbrev_code: {}]", indent, abbrev_code);
            return;
        }
    };
    
    // タグ名を表示
    let tag_name = get_die_tag_name(abbrev.tag, version);
    println!("{}<{:x}><{}> {}", indent, die_start, abbrev_code, tag_name);
    
    let mut attr_values: Vec<(u64, u64, u8, String, String)> = Vec::new(); // (attr, value, form, attr_name_str, human_value)
    let _attr_count = abbrev.attributes.len();
    let mut offset_tmp = *offset;
    let mut low_pc_opt: Option<u64> = None;
    for (attr_name, attr_form) in &abbrev.attributes {
        let attr_name_str = get_attr_name(*attr_name).to_string();
        let (value, human_value, form_code) = match *attr_form {
            0x08 => {
                let (s, consumed) = extract_null_terminated_string(&section_data[offset_tmp..]);
                offset_tmp += consumed;
                (0, format!("\"{}\"", s), 0x08)
            },
            0x0e => {
                let raw = &section_data[offset_tmp..offset_tmp+4];
                let attr_value = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as u64;
                offset_tmp += 4;
                let value_str = if let (Some(buf), Some(stroff), Some(strsize)) = (debug_str_buf, debug_str_off, debug_str_size) {
                    get_string_from_table(buf, stroff, strsize, attr_value as u32)
                } else {
                    format!("0x{:x}", attr_value)
                };
                (attr_value, format!("(strp: 0x{:x}) \"{}\"", attr_value, value_str), 0x0e)
            },
            0x0b => {
                let value = section_data[offset_tmp] as u64;
                offset_tmp += 1;
                if *attr_name == 0x13 {
                    (value, format!("0x{:x} ({} - {})", value, get_language_name(value), get_language_description(value)), 0x0b)
                } else {
                    (value, format!("0x{:x}", value), 0x0b)
                }
            },
            0x05 => {
                let value = u16::from_le_bytes([
                    section_data[offset_tmp],
                    section_data[offset_tmp+1],
                ]) as u64;
                offset_tmp += 2;
                if *attr_name == 0x12 || *attr_name == 0x13 { // DW_AT_low_pc, DW_AT_high_pc
                    let abs_addr = value + text_addr;
                    (abs_addr, format!("0x{:x} (base: 0x{:x} + offset: 0x{:x})", abs_addr, text_addr, value), 0x05)
                } else if *attr_name == 0x11 { // DW_AT_low_pc
                    (value, format!("0x{:x}", value), 0x05)
                } else {
                    (value, format!("0x{:x}", value), 0x05)
                }
            },
            0x06 | 0x13 => {
                let value = u32::from_le_bytes([
                    section_data[offset_tmp],
                    section_data[offset_tmp+1],
                    section_data[offset_tmp+2],
                    section_data[offset_tmp+3],
                ]) as u64;
                offset_tmp += 4;
                if *attr_name == 0x12 || *attr_name == 0x13 { // DW_AT_low_pc, DW_AT_high_pc
                    let abs_addr = value + text_addr;
                    (abs_addr, format!("0x{:x} (base: 0x{:x} + offset: 0x{:x})", abs_addr, text_addr, value), if *attr_form == 0x06 { 0x06 } else { 0x13 })
                } else if *attr_name == 0x11 { // DW_AT_low_pc
                    (value, format!("0x{:x}", value), if *attr_form == 0x06 { 0x06 } else { 0x13 })
                } else {
                    (value, format!("0x{:x}", value), if *attr_form == 0x06 { 0x06 } else { 0x13 })
                }
            },
            0x07 => {
                if *attr_name == 0x12 || *attr_name == 0x13 {
                    let value = if address_size == 8 {
                        u64::from_le_bytes([
                            section_data[offset_tmp],
                            section_data[offset_tmp+1],
                            section_data[offset_tmp+2],
                            section_data[offset_tmp+3],
                            section_data[offset_tmp+4],
                            section_data[offset_tmp+5],
                            section_data[offset_tmp+6],
                            section_data[offset_tmp+7],
                        ])
                    } else {
                        u32::from_le_bytes([
                            section_data[offset_tmp],
                            section_data[offset_tmp+1],
                            section_data[offset_tmp+2],
                            section_data[offset_tmp+3],
                        ]) as u64
                    };
                    let abs_addr = value + text_addr;
                    offset_tmp += address_size;
                    (abs_addr, format!("0x{:x} (base: 0x{:x} + offset: 0x{:x})", abs_addr, text_addr, value), 0x07)
                } else {
                    let value = u64::from_le_bytes([
                        section_data[offset_tmp],
                        section_data[offset_tmp+1],
                        section_data[offset_tmp+2],
                        section_data[offset_tmp+3],
                        section_data[offset_tmp+4],
                        section_data[offset_tmp+5],
                        section_data[offset_tmp+6],
                        section_data[offset_tmp+7],
                    ]);
                    offset_tmp += 8;
                    (value, format!("0x{:x}", value), 0x07)
                }
            },
            _ => {
                let (attr_value, consumed) = read_uleb128(&section_data[offset_tmp..]);
                offset_tmp += consumed;
                if *attr_name == 0x12 || *attr_name == 0x13 { // DW_AT_low_pc, DW_AT_high_pc
                    let abs_addr = attr_value + text_addr;
                    (abs_addr, format!("0x{:x} (base: 0x{:x} + offset: 0x{:x})", abs_addr, text_addr, attr_value), 0xff)
                } else if *attr_name == 0x11 { // DW_AT_low_pc
                    (attr_value, format!("0x{:x}", attr_value), 0xff)
                } else if *attr_name == 0x14 { // DW_AT_language
                    (attr_value, format!("0x{:x} ({} - {})", attr_value, get_language_name(attr_value), get_language_description(attr_value)), 0xff)
                } else {
                    (attr_value, format!("0x{:x}", attr_value), 0xff)
                }
            },
        };
        if *attr_name == 0x12 { // DW_AT_low_pc
            low_pc_opt = Some(value); // valueは既に仮想ベースアドレスが加算済み
        }
        attr_values.push((*attr_name, value, form_code, attr_name_str, human_value));
    }
    *offset = offset_tmp;
    // 2回目: 出力
    for (attr_name, value, attr_form, attr_name_str, human_value) in &attr_values {
        if *attr_name == 0x13 { // DW_AT_high_pc
            if let Some(low_pc) = low_pc_opt {
                // DW_FORM_addr (0x01, 0x05, 0x06, 0x07, 0x13) の場合は value が絶対アドレス、それ以外は low_pc からのオフセット
                let end_addr = if *attr_form == 0x01 || *attr_form == 0x05 || *attr_form == 0x06 || *attr_form == 0x07 || *attr_form == 0x13 {
                    *value // valueは既に仮想ベースアドレスが加算済み
                } else {
                    low_pc + *value
                };
                println!("{}  {}\t({} → 終了アドレス: 0x{:x})", indent, attr_name_str, human_value, end_addr);
                continue;
            }
        }
        println!("{}  {}\t({})", indent, attr_name_str, human_value);
    }



    if abbrev.has_children {
        loop {
            let (abbrev_code, consumed) = read_uleb128(&section_data[*offset..]);
            if abbrev_code == 0 {
                *offset += consumed; // NULL DIEなので消費バイト数分オフセットを進める
                break; // end of children
            }
            *offset += consumed; // abbrev_codeを読み飛ばす
            display_die_tree_recursive(section_data, abbrev_code, offset, abbrev_map, depth + 1, version, debug_str_buf, debug_str_off, debug_str_size, address_size, macho_header, text_addr);
        }
    }
}




// DWARFバージョンを抽出する関数
fn extract_dwarf_version(buffer: &[u8], section: &SectionInfo) -> Option<u16> {
    let start_offset = section.offset as usize;
    if start_offset + 6 > buffer.len() {
        return None;
    }
    
    // コンパイル単位ヘッダーからバージョンを読み取り
    let _unit_length = u32::from_le_bytes([
        buffer[start_offset],
        buffer[start_offset + 1], 
        buffer[start_offset + 2],
        buffer[start_offset + 3]
    ]);
    
    let version = u16::from_le_bytes([
        buffer[start_offset + 4],
        buffer[start_offset + 5]
    ]);
    
    Some(version)
}

fn parse_line_number_program(program_data: &[u8], _file_names: &[String], line_base: i8, line_range: u8, opcode_base: u8) {
    println!("Address            Line   Column File   ISA Discriminator OpIndex Flags");
    println!("------------------ ------ ------ ------ --- ------------- ------- -------------");
    
    let mut offset = 0;
    let mut address = 0u64;
    let mut file_index = 1u32;
    let mut line = 1u32;
    let mut column = 0u32;
    let mut is_stmt = true;
    let mut basic_block = false;
    let mut end_sequence = false;
    let mut prologue_end = false;
    let mut epilogue_begin = false;
    let mut isa = 0u32;
    let mut discriminator = 0u32;
    let mut op_index = 0u32;
    
    // 行情報を出力するヘルパー関数
    let output_row = |addr: u64, ln: u32, col: u32, file_idx: u32, isa_val: u32, disc: u32, op_idx: u32,
                         stmt: bool, bb: bool, end_seq: bool, prol_end: bool, epil_begin: bool| {
        let mut flags = Vec::new();
        if stmt { flags.push("is_stmt"); }
        if bb { flags.push("basic_block"); }
        if end_seq { flags.push("end_sequence"); }
        if prol_end { flags.push("prologue_end"); }
        if epil_begin { flags.push("epilogue_begin"); }
        
        println!("0x{:016x} {:6} {:6} {:6} {:3} {:13} {:7} {}",
                addr, ln, col, file_idx, isa_val, disc, op_idx, flags.join(" "));
    };
    
    while offset < program_data.len() {
        let opcode = program_data[offset];
        offset += 1;
        
        if opcode == 0 {
            // 拡張オペコード
            if offset >= program_data.len() {
                break;
            }
            let (length, consumed) = read_uleb128(&program_data[offset..]);
            offset += consumed;
            
            if offset >= program_data.len() {
                break;
            }
            let ext_opcode = program_data[offset];
            offset += 1;
            
            match ext_opcode {
                1 => {
                    // DW_LNE_end_sequence
                    end_sequence = true;
                    output_row(address, line, column, file_index, isa, discriminator, op_index,
                              is_stmt, basic_block, end_sequence, prologue_end, epilogue_begin);
                    // 状態をリセット
                    address = 0;
                    file_index = 1;
                    line = 1;
                    column = 0;
                    is_stmt = true;
                    basic_block = false;
                    end_sequence = false;
                    prologue_end = false;
                    epilogue_begin = false;
                    isa = 0;
                    discriminator = 0;
                    op_index = 0;
                },
                2 => {
                    // DW_LNE_set_address
                    if length >= 8 && offset + 8 <= program_data.len() {
                        address = u64::from_le_bytes([
                            program_data[offset], program_data[offset + 1],
                            program_data[offset + 2], program_data[offset + 3],
                            program_data[offset + 4], program_data[offset + 5],
                            program_data[offset + 6], program_data[offset + 7]
                        ]);
                        offset += 8;
                    }
                },
                3 => {
                    // DW_LNE_define_file
                    let (_filename, consumed) = extract_null_terminated_string(&program_data[offset..]);
                    offset += consumed;
                    // ディレクトリインデックス、修正時刻、ファイルサイズをスキップ
                    let (_, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    let (_, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    let (_, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                },
                _ => {
                    if length > 1 {
                        offset += (length - 1) as usize;
                    }
                }
            }
        } else if opcode < opcode_base {
            // 標準オペコード
            match opcode {
                1 => {
                    // DW_LNS_copy
                    output_row(address, line, column, file_index, isa, discriminator, op_index,
                              is_stmt, basic_block, end_sequence, prologue_end, epilogue_begin);
                    basic_block = false;
                    prologue_end = false;
                    epilogue_begin = false;
                },
                2 => {
                    // DW_LNS_advance_pc
                    let (advance, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    address += advance;
                },
                3 => {
                    // DW_LNS_advance_line
                    let (advance, consumed) = read_sleb128(&program_data[offset..]);
                    offset += consumed;
                    // 符号付き演算で行番号を正しく計算
                    let new_line = (line as i64) + advance;
                    line = if new_line < 0 {
                        0  // 負の値になった場合は0にクランプ
                    } else {
                        new_line as u32
                    };
                },
                4 => {
                    // DW_LNS_set_file
                    let (new_file, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    file_index = new_file as u32;
                },
                5 => {
                    // DW_LNS_set_column
                    let (new_column, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    column = new_column as u32;
                },
                6 => {
                    // DW_LNS_negate_stmt
                    is_stmt = !is_stmt;
                },
                7 => {
                    // DW_LNS_set_basic_block
                    basic_block = true;
                },
                8 => {
                    // DW_LNS_const_add_pc
                    let adjusted_opcode = 255 - opcode_base;
                    let addr_advance = (adjusted_opcode / line_range) as u64;
                    address += addr_advance;
                },
                9 => {
                    // DW_LNS_fixed_advance_pc
                    if offset + 2 <= program_data.len() {
                        let advance = u16::from_le_bytes([program_data[offset], program_data[offset + 1]]);
                        offset += 2;
                        address += advance as u64;
                    }
                },
                10 => {
                    // DW_LNS_set_prologue_end
                    prologue_end = true;
                },
                11 => {
                    // DW_LNS_set_epilogue_begin
                    epilogue_begin = true;
                },
                12 => {
                    // DW_LNS_set_isa
                    let (new_isa, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    isa = new_isa as u32;
                },
                _ => {
                    // 未知の標準オペコード - パラメータをスキップ
                }
            }
        } else {
            // 特別オペコード
            let adjusted_opcode = opcode - opcode_base;
            let addr_advance = (adjusted_opcode / line_range) as u64;
            let line_advance = line_base + (adjusted_opcode % line_range) as i8;
            
            address += addr_advance;
            // 符号付き演算で行番号を正しく計算
            let new_line = (line as i64) + (line_advance as i64);
            line = if new_line < 0 {
                0  // 負の値になった場合は0にクランプ
            } else {
                new_line as u32
            };
            
            output_row(address, line, column, file_index, isa, discriminator, op_index,
                      is_stmt, basic_block, end_sequence, prologue_end, epilogue_begin);
            basic_block = false;
            prologue_end = false;
            epilogue_begin = false;
        }
    }
}

fn read_sleb128(data: &[u8]) -> (i64, usize) {
    let mut result = 0i64;
    let mut shift = 0;
    let mut bytes_read = 0;
    let mut byte = 0u8;
    
    loop {
        if bytes_read >= data.len() {
            break;
        }
        
        byte = data[bytes_read];
        bytes_read += 1;
        
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        
        
        if byte & 0x80 == 0 {
            break;
        }
        
        if shift >= 64 || bytes_read >= 10 {
            break; // 安全のため制限
        }
    }
    
    // 符号拡張（データが存在する場合のみ）
    if bytes_read > 0 && shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    
    (result, bytes_read)
}

// gimli::AttributeValue から安全にStringを取得するヘルパ関数（gimli 0.28.x対応）
fn attr_value_to_string<'a, R: gimli::Reader<Offset = usize>>(
    attr: &gimli::AttributeValue<R>,
    debug_str: &gimli::DebugStr<R>,
) -> String {
    match attr {
        gimli::AttributeValue::String(s) => {
            match s.to_slice() {
                Ok(slice) => std::str::from_utf8(&slice).unwrap_or("<invalid utf8>").to_string(),
                Err(_) => "<invalid slice>".to_string(),
            }
        }
        gimli::AttributeValue::DebugStrRef(str_ref) => {
            match debug_str.get_str(*str_ref) {
                Ok(entry) => {
                    match entry.to_slice() {
                        Ok(slice) => std::str::from_utf8(&slice).unwrap_or("<invalid utf8>").to_string(),
                        Err(_) => "<invalid slice>".to_string(),
                    }
                },
                Err(_) => "<invalid debug_str>".to_string(),
            }
        }
        gimli::AttributeValue::DebugLineStrRef(_str_ref) => {
            // DebugLineStrRef対応が必要ならここに追加
            "<DebugLineStrRef未対応>".to_string()
        }
        _ => "<非対応AttributeValue>".to_string(),
    }
}

// __debug_line詳細: アドレス→ファイル名:行番号 テーブル出力（gimli利用）

fn parse_dwarf2_4_file_table(data: &[u8], offset: &mut usize) -> (Vec<String>, Vec<String>) {
    let mut directories = Vec::new();
    let mut file_names = Vec::new();
    
    // インクルードディレクトリテーブル
    let mut dir_count = 0;
    while *offset < data.len() && data[*offset] != 0 && dir_count < 20 {
        let (dir_name, consumed) = extract_null_terminated_string(&data[*offset..]);
        directories.push(dir_name);
        *offset += consumed;
        dir_count += 1;
    }
    
    // ディレクトリテーブル終了のヌルバイトをスキップ
    if *offset < data.len() && data[*offset] == 0 {
        *offset += 1;
    }
    
    // ファイル名テーブル
    let mut file_count = 0;
    while *offset < data.len() && data[*offset] != 0 && file_count < 50 {
        let (file_name, consumed) = extract_null_terminated_string(&data[*offset..]);
        *offset += consumed;
        
        if *offset >= data.len() {
            break;
        }
        
        // ディレクトリインデックス、修正時刻、ファイルサイズを読み取り
        let (_dir_idx, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        let (_mod_time, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        let (_file_size, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        
        file_names.push(file_name);
        file_count += 1;
    }
    
    // ファイル名テーブル終了のヌルバイトをスキップ
    if *offset < data.len() && data[*offset] == 0 {
        *offset += 1;
    }
    
    (directories, file_names)
}

// DWARF 5の__debug_str_offs__DWARFセクションを解析
fn parse_and_display_debug_str_offsets(buffer: &[u8], section: &SectionInfo) {
    println!("\n=== __debug_str_offs__DWARF 詳細解析 ===");
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("エラー: __debug_str_offs__DWARFセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("セクションサイズ: {} バイト", section_data.len());
    
    // DWARF 5の文字列オフセットテーブルを解析
    let mut offset = 0;
    let mut entry_count = 0;
    
    println!("\n--- 文字列オフセットエントリ ---");
    
    while offset + 4 <= section_data.len() && entry_count < 20 {
        let str_offset = u32::from_le_bytes([
            section_data[offset], section_data[offset + 1],
            section_data[offset + 2], section_data[offset + 3]
        ]);
        
        println!("  {}: 0x{:08x}", entry_count, str_offset);
        
        offset += 4;
        entry_count += 1;
    }
    
    if entry_count == 0 {
        println!("  (エントリが見つかりませんでした)");
    } else if entry_count == 20 && offset < section_data.len() {
        println!("  ... (残りのエントリは省略)");
    }
}

// DWARF 5の__debug_addrセクションを解析
fn parse_and_display_debug_addr(buffer: &[u8], section: &SectionInfo) {
    println!("\n=== __debug_addr 詳細解析 ===");
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("エラー: __debug_addrセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("セクションサイズ: {} バイト", section_data.len());
    
    // DWARF 5のアドレステーブルヘッダーを解析
    if section_data.len() < 8 {
        println!("エラー: セクションが小さすぎます");
        return;
    }
    
    let unit_length = u32::from_le_bytes([
        section_data[0], section_data[1], section_data[2], section_data[3]
    ]);
    let version = u16::from_le_bytes([
        section_data[4], section_data[5]
    ]);
    let address_size = section_data[6];
    let segment_selector_size = section_data[7];
    
    println!("ユニット長: {} バイト", unit_length);
    println!("バージョン: {}", version);
    println!("アドレスサイズ: {} バイト", address_size);
    println!("セグメントセレクタサイズ: {} バイト", segment_selector_size);
    
    // アドレスエントリを解析
    let mut offset = 8;
    let mut entry_count = 0;
    
    println!("\n--- アドレスエントリ ---");
    
    while offset + address_size as usize <= section_data.len() && entry_count < 20 {
        let address = if address_size == 8 {
            u64::from_le_bytes([
                section_data[offset], section_data[offset + 1],
                section_data[offset + 2], section_data[offset + 3],
                section_data[offset + 4], section_data[offset + 5],
                section_data[offset + 6], section_data[offset + 7]
            ])
        } else if address_size == 4 {
            u32::from_le_bytes([
                section_data[offset], section_data[offset + 1],
                section_data[offset + 2], section_data[offset + 3]
            ]) as u64
        } else {
            println!("  エラー: サポートされていないアドレスサイズ: {}", address_size);
            break;
        };
        
        println!("  {}: 0x{:016x}", entry_count, address);
        
        offset += address_size as usize;
        entry_count += 1;
    }
    
    if entry_count == 0 {
        println!("  (エントリが見つかりませんでした)");
    } else if entry_count == 20 && offset < section_data.len() {
        println!("  ... (残りのエントリは省略)");
    }
}
// DWARF 5のファイルテーブル解析
fn parse_dwarf5_file_table(data: &[u8], offset: &mut usize) -> (Vec<String>, Vec<String>) {
    let mut directories = Vec::new();
    let mut file_names = Vec::new();
    
    println!("    [DEBUG] DWARF5ファイルテーブル解析開始, offset: {}", *offset);
    
    // DWARF 5では新しいファイルテーブル形式
    if *offset + 1 >= data.len() {
        println!("    [DEBUG] データが不足しています");
        return (directories, file_names);
    }
    
    // ディレクトリエントリフォーマット数
    let directory_entry_format_count = data[*offset];
    *offset += 1;
    println!("    [DEBUG] ディレクトリエントリフォーマット数: {}", directory_entry_format_count);
    
    // ディレクトリエントリフォーマット
    let mut dir_formats = Vec::new();
    for _ in 0..directory_entry_format_count {
        if *offset >= data.len() {
            break;
        }
        let (content_type, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        let (form, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        dir_formats.push((content_type, form));
    }
    
    // ディレクトリ数
    if *offset >= data.len() {
        println!("    [DEBUG] ディレクトリ数読み取り前にデータが不足");
        return (directories, file_names);
    }
    let (directories_count, consumed) = read_uleb128(&data[*offset..]);
    *offset += consumed;
    println!("    [DEBUG] ディレクトリ数: {}", directories_count);
    
    // ディレクトリエントリ
    for i in 0..directories_count {
        let mut dir_name = String::new();
        println!("    [DEBUG] ディレクトリエントリ {} 解析中, offset: {}", i, *offset);
        for (j, (content_type, form)) in dir_formats.iter().enumerate() {
            println!("    [DEBUG]   フォーマット {}: content_type={}, form=0x{:x}", j, content_type, form);
            if *content_type == 1 { // DW_LNCT_path
                if *form == 0x08 { // DW_FORM_string
                    let (name, consumed) = extract_null_terminated_string(&data[*offset..]);
                    println!("    [DEBUG]   DW_FORM_string: '{}'", name);
                    dir_name = name;
                    *offset += consumed;
                } else if *form == 0x0e { // DW_FORM_strp
                    if *offset + 4 <= data.len() {
                        let str_offset = u32::from_le_bytes([
                            data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]
                        ]);
                        *offset += 4;
                        dir_name = format!("strp_offset_0x{:x}", str_offset);
                        println!("    [DEBUG]   DW_FORM_strp: {}", dir_name);
                    }
                } else if *form == 0x1f { // DW_FORM_line_strp
                    if *offset + 4 <= data.len() {
                        let str_offset = u32::from_le_bytes([
                            data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]
                        ]);
                        *offset += 4;
                        dir_name = format!("line_strp_offset_0x{:x}", str_offset);
                        println!("    [DEBUG]   DW_FORM_line_strp: {}", dir_name);
                    }
                } else {
                    // 他のフォームをスキップ
                    let (value, consumed) = read_uleb128(&data[*offset..]);
                    println!("    [DEBUG]   未対応フォーム 0x{:x}: value={}, consumed={}", form, value, consumed);
                    *offset += consumed;
                }
            } else {
                // 他のコンテンツタイプをスキップ
                let (value, consumed) = read_uleb128(&data[*offset..]);
                println!("    [DEBUG]   未対応コンテンツタイプ {}: value={}, consumed={}", content_type, value, consumed);
                *offset += consumed;
            }
        }
        println!("    [DEBUG] ディレクトリ名: '{}'", dir_name);
        if !dir_name.is_empty() {
            directories.push(dir_name);
        }
    }
    
    // ファイル名エントリフォーマット数
    if *offset >= data.len() {
        return (directories, file_names);
    }
    let file_name_entry_format_count = data[*offset];
    *offset += 1;
    
    // ファイル名エントリフォーマット
    let mut file_formats = Vec::new();
    for _ in 0..file_name_entry_format_count {
        if *offset >= data.len() {
            break;
        }
        let (content_type, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        let (form, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        file_formats.push((content_type, form));
    }
    
    // ファイル名数
    if *offset >= data.len() {
        println!("    [DEBUG] ファイル名数読み取り前にデータが不足");
        return (directories, file_names);
    }
    let (file_names_count, consumed) = read_uleb128(&data[*offset..]);
    *offset += consumed;
    println!("    [DEBUG] ファイル名数: {}", file_names_count);
    
    // ファイル名エントリ
    for i in 0..file_names_count {
        let mut file_name = String::new();
        println!("    [DEBUG] ファイル名エントリ {} 解析中, offset: {}", i, *offset);
        for (j, (content_type, form)) in file_formats.iter().enumerate() {
            println!("    [DEBUG]   フォーマット {}: content_type={}, form=0x{:x}", j, content_type, form);
            if *content_type == 1 { // DW_LNCT_path
                if *form == 0x08 { // DW_FORM_string
                    let (name, consumed) = extract_null_terminated_string(&data[*offset..]);
                    println!("    [DEBUG]   DW_FORM_string: '{}'", name);
                    file_name = name;
                    *offset += consumed;
                } else if *form == 0x0e { // DW_FORM_strp
                    if *offset + 4 <= data.len() {
                        let str_offset = u32::from_le_bytes([
                            data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]
                        ]);
                        *offset += 4;
                        file_name = format!("strp_offset_0x{:x}", str_offset);
                        println!("    [DEBUG]   DW_FORM_strp: {}", file_name);
                    }
                } else if *form == 0x1f { // DW_FORM_line_strp
                    if *offset + 4 <= data.len() {
                        let str_offset = u32::from_le_bytes([
                            data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]
                        ]);
                        *offset += 4;
                        file_name = format!("line_strp_offset_0x{:x}", str_offset);
                        println!("    [DEBUG]   DW_FORM_line_strp: {}", file_name);
                    }
                } else {
                    // 他のフォームをスキップ
                    let (value, consumed) = read_uleb128(&data[*offset..]);
                    println!("    [DEBUG]   未対応フォーム 0x{:x}: value={}, consumed={}", form, value, consumed);
                    *offset += consumed;
                }
            } else {
                // 他のコンテンツタイプをスキップ
                let (value, consumed) = read_uleb128(&data[*offset..]);
                println!("    [DEBUG]   未対応コンテンツタイプ {}: value={}, consumed={}", content_type, value, consumed);
                *offset += consumed;
            }
        }
        println!("    [DEBUG] ファイル名: '{}'", file_name);
        if !file_name.is_empty() {
            file_names.push(file_name);
        }
    }
    
    (directories, file_names)
}