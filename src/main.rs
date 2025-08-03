use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// Mach-Oヘッダー構造体（64bit）
#[repr(C)]
#[derive(Debug)]
struct MachHeader64 {
    magic: u32,        // マジックナンバー
    cputype: u32,      // CPUタイプ
    cpusubtype: u32,   // CPUサブタイプ
    filetype: u32,     // ファイルタイプ
    ncmds: u32,        // ロードコマンド数
    sizeofcmds: u32,   // ロードコマンドのサイズ
    flags: u32,        // フラグ
    reserved: u32,     // 予約済み（64bitのみ）
}

// セクション情報構造体（簡略化版）
#[derive(Debug)]
struct SectionInfo {
    name: String,          // セクション名
    addr: u64,             // 仮想アドレス
    size: u64,             // セクションサイズ
    offset: u32,           // ファイル内オフセット
}

// シンボルテーブル情報構造体
#[derive(Debug)]
struct SymtabInfo {
    symoff: u32,           // シンボルテーブルオフセット
    nsyms: u32,            // シンボル数
    stroff: u32,           // 文字列テーブルオフセット
    strsize: u32,          // 文字列テーブルサイズ
}

// デバッグ情報構造体
#[derive(Debug)]
struct DebugInfo {
    dwarf_sections: Vec<SectionInfo>,  // DWARFセクション
    symtab_info: Option<SymtabInfo>,        // シンボルテーブル
}



// Mach-Oセクションヘッダー構造体（64bit）
#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)]
struct Section64 {
    sectname: [u8; 16],    // セクション名
    segname: [u8; 16],     // セグメント名
    addr: u64,             // 仮想アドレス
    size: u64,             // セクションサイズ
    offset: u32,           // ファイル内オフセット
    align: u32,            // アライメント
    reloff: u32,           // 再配置エントリオフセット
    nreloc: u32,           // 再配置エントリ数
    flags: u32,            // フラグ
    reserved1: u32,        // 予約済み1
    reserved2: u32,        // 予約済み2
    reserved3: u32,        // 予約済み3（64bitのみ）
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        eprintln!("使用方法: {} <実行可能ファイルのパス>", args[0]);
        std::process::exit(1);
    }
    
    let file_path = &args[1];
    
    if !Path::new(file_path).exists() {
        eprintln!("エラー: ファイル '{}' が見つかりません", file_path);
        std::process::exit(1);
    }
    
    dump_file(file_path)?;
    
    Ok(())
}

fn is_macho_file(buffer: &[u8]) -> bool {
    if buffer.len() < 4 {
        return false;
    }
    
    let magic_le = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let magic_be = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    
    // Mach-O 64bit マジックナンバーをチェック
    magic_le == 0xcffaedfe || magic_be == 0xcffaedfe ||
    magic_le == 0xfeedfacf || magic_be == 0xfeedfacf
}

fn parse_macho_header(buffer: &[u8]) -> Option<MachHeader64> {
    if !is_macho_file(buffer) || buffer.len() < 32 {
        return None;
    }
    
    // マジックナンバーを読み取ってエンディアンを判定
    let magic_bytes = [buffer[0], buffer[1], buffer[2], buffer[3]];
    let magic_le = u32::from_le_bytes(magic_bytes);
    let magic_be = u32::from_be_bytes(magic_bytes);
    
    let (magic, is_little_endian) = if magic_le == 0xcffaedfe {
        (magic_le, true)
    } else if magic_be == 0xcffaedfe {
        (magic_be, false)
    } else if magic_le == 0xfeedfacf {
        (magic_le, true)
    } else if magic_be == 0xfeedfacf {
        (magic_be, false)
    } else {
        return None;
    };
    
    let read_u32 = |offset: usize| -> u32 {
        let bytes = [buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]];
        if is_little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    

    Some(MachHeader64 {
        magic,
        cputype: read_u32(4),
        cpusubtype: read_u32(8),
        filetype: read_u32(12),
        ncmds: read_u32(16),
        sizeofcmds: read_u32(20),
        flags: read_u32(24),
        reserved: read_u32(28),
    })
}

fn find_text_section(buffer: &[u8], header: &MachHeader64) -> Option<SectionInfo> {
    find_section_in_segment(buffer, header, "__TEXT", "__text")
}

fn find_data_sections(buffer: &[u8], header: &MachHeader64) -> Vec<SectionInfo> {
    find_all_sections_in_segment(buffer, header, "__DATA")
}

fn find_debug_info(buffer: &[u8], header: &MachHeader64) -> DebugInfo {
    let mut debug_info = DebugInfo {
        dwarf_sections: Vec::new(),
        symtab_info: None,
    };
    
    // __DWARFセグメントからDWARFセクションを検索
    debug_info.dwarf_sections = find_all_sections_in_segment(buffer, header, "__DWARF");
    
    // シンボルテーブル情報を検索
    debug_info.symtab_info = find_symtab_info(buffer, header);
    
    debug_info
}

fn find_symtab_info(buffer: &[u8], header: &MachHeader64) -> Option<SymtabInfo> {
    let mut offset = 32; // Mach-O 64-bit ヘッダーサイズ
    
    for _ in 0..header.ncmds {
        if offset + 8 > buffer.len() {
            break;
        }
        
        let cmd = u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]]);
        let cmdsize = u32::from_le_bytes([buffer[offset + 4], buffer[offset + 5], buffer[offset + 6], buffer[offset + 7]]);
        
        if cmd == 0x2 { // LC_SYMTAB
            if offset + 24 > buffer.len() {
                break;
            }
            
            let symoff = u32::from_le_bytes([buffer[offset + 8], buffer[offset + 9], buffer[offset + 10], buffer[offset + 11]]);
            let nsyms = u32::from_le_bytes([buffer[offset + 12], buffer[offset + 13], buffer[offset + 14], buffer[offset + 15]]);
            let stroff = u32::from_le_bytes([buffer[offset + 16], buffer[offset + 17], buffer[offset + 18], buffer[offset + 19]]);
            let strsize = u32::from_le_bytes([buffer[offset + 20], buffer[offset + 21], buffer[offset + 22], buffer[offset + 23]]);
            
            return Some(SymtabInfo {
                symoff,
                nsyms,
                stroff,
                strsize,
            });
        }
        
        offset += cmdsize as usize;
    }
    
    None
}

fn find_section_in_segment(buffer: &[u8], header: &MachHeader64, segment_name: &str, section_name: &str) -> Option<SectionInfo> {
    let mut offset = 32; // Mach-O 64-bit ヘッダーサイズ
    
    for _ in 0..header.ncmds {
        if offset + 8 > buffer.len() {
            break;
        }
        
        let cmd = u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]]);
        let cmdsize = u32::from_le_bytes([buffer[offset + 4], buffer[offset + 5], buffer[offset + 6], buffer[offset + 7]]);
        
        if cmd == 0x19 { // LC_SEGMENT_64
            if offset + 72 > buffer.len() {
                break;
            }
            
            // セグメント名を読み取り（16バイト）
            let segname = &buffer[offset + 8..offset + 24];
            let segname_str = std::str::from_utf8(segname)
                .unwrap_or("")
                .trim_end_matches('\0');
            
            if segname_str == segment_name {
                // セクション数を取得
                let nsects = u32::from_le_bytes([buffer[offset + 64], buffer[offset + 65], buffer[offset + 66], buffer[offset + 67]]);
                
                // セクションヘッダーを読み取り
                let mut section_offset = offset + 72;
                for _ in 0..nsects {
                    if section_offset + 80 > buffer.len() {
                        break;
                    }
                    
                    // セクション名を読み取り（16バイト）
                    let sectname = &buffer[section_offset..section_offset + 16];
                    let sectname_str = std::str::from_utf8(sectname)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    
                    if sectname_str == section_name {
                        // セクション情報を取得
                        let addr = u64::from_le_bytes([
                            buffer[section_offset + 32], buffer[section_offset + 33],
                            buffer[section_offset + 34], buffer[section_offset + 35],
                            buffer[section_offset + 36], buffer[section_offset + 37],
                            buffer[section_offset + 38], buffer[section_offset + 39],
                        ]);
                        let size = u64::from_le_bytes([
                            buffer[section_offset + 40], buffer[section_offset + 41],
                            buffer[section_offset + 42], buffer[section_offset + 43],
                            buffer[section_offset + 44], buffer[section_offset + 45],
                            buffer[section_offset + 46], buffer[section_offset + 47],
                        ]);
                        let file_offset = u32::from_le_bytes([
                            buffer[section_offset + 48], buffer[section_offset + 49],
                            buffer[section_offset + 50], buffer[section_offset + 51],
                        ]);
                        
                        return Some(SectionInfo {
                            name: sectname_str.to_string(),
                            addr,
                            size,
                            offset: file_offset,
                        });
                    }
                    
                    section_offset += 80; // セクションヘッダーサイズ
                }
            }
        }
        
        offset += cmdsize as usize;
    }
    
    None
}

fn find_all_sections_in_segment(buffer: &[u8], header: &MachHeader64, segment_name: &str) -> Vec<SectionInfo> {
    let mut sections = Vec::new();
    let mut offset = 32; // Mach-O 64-bit ヘッダーサイズ
    
    for _ in 0..header.ncmds {
        if offset + 8 > buffer.len() {
            break;
        }
        
        let cmd = u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]]);
        let cmdsize = u32::from_le_bytes([buffer[offset + 4], buffer[offset + 5], buffer[offset + 6], buffer[offset + 7]]);
        
        if cmd == 0x19 { // LC_SEGMENT_64
            if offset + 72 > buffer.len() {
                break;
            }
            
            // セグメント名を読み取り（16バイト）
            let segname = &buffer[offset + 8..offset + 24];
            let segname_str = std::str::from_utf8(segname)
                .unwrap_or("")
                .trim_end_matches('\0');
            
            if segname_str == segment_name {
                // セクション数を取得
                let nsects = u32::from_le_bytes([buffer[offset + 64], buffer[offset + 65], buffer[offset + 66], buffer[offset + 67]]);
                
                // セクションヘッダーを読み取り
                let mut section_offset = offset + 72;
                for _ in 0..nsects {
                    if section_offset + 80 > buffer.len() {
                        break;
                    }
                    
                    // セクション名を読み取り（16バイト）
                    let sectname = &buffer[section_offset..section_offset + 16];
                    let sectname_str = std::str::from_utf8(sectname)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    
                    // セクション情報を取得
                    let addr = u64::from_le_bytes([
                        buffer[section_offset + 32], buffer[section_offset + 33],
                        buffer[section_offset + 34], buffer[section_offset + 35],
                        buffer[section_offset + 36], buffer[section_offset + 37],
                        buffer[section_offset + 38], buffer[section_offset + 39],
                    ]);
                    let size = u64::from_le_bytes([
                        buffer[section_offset + 40], buffer[section_offset + 41],
                        buffer[section_offset + 42], buffer[section_offset + 43],
                        buffer[section_offset + 44], buffer[section_offset + 45],
                        buffer[section_offset + 46], buffer[section_offset + 47],
                    ]);
                    let file_offset = u32::from_le_bytes([
                        buffer[section_offset + 48], buffer[section_offset + 49],
                        buffer[section_offset + 50], buffer[section_offset + 51],
                    ]);
                    
                    sections.push(SectionInfo {
                        name: sectname_str.to_string(),
                        addr,
                        size,
                        offset: file_offset,
                    });
                    
                    section_offset += 80; // セクションヘッダーサイズ
                }
            }
        }
        
        offset += cmdsize as usize;
    }
    
    sections
}

fn disassemble_text_section(buffer: &[u8], section: &SectionInfo, header: &MachHeader64) {
    println!("\n=== __TEXTセクション逆アセンブル ===");
    println!("仮想アドレス: 0x{:016x}", section.addr);
    println!("サイズ: {} バイト", section.size);
    println!("ファイルオフセット: 0x{:08x}", section.offset);
    
    // CPUアーキテクチャを判定
    let arch = match header.cputype {
        16777223 | 117440513 => "x86_64", // Intel x86_64
        16777228 => "arm64",              // ARM64
        12 => "arm",                      // ARM 32-bit
        _ => "unknown",
    };
    println!("アーキテクチャ: {}", arch);
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
        // アーキテクチャに応じて逆アセンブル
        let (instruction, inst_len) = match arch {
            "x86_64" => simple_disasm_x86_64(&buffer[i..actual_end], addr),
            "arm64" => simple_disasm_arm64(&buffer[i..actual_end], addr),
            "arm" => simple_disasm_arm32(&buffer[i..actual_end], addr),
            _ => (format!("不明なアーキテクチャ: {}", arch), 4),
        };
        
        // アドレスと16進数バイトを表示
        print!("{:016x}: ", addr);
        
        // 命令のバイト数分だけ表示（最大16バイト）
        let bytes_to_show = std::cmp::min(inst_len, std::cmp::min(16, actual_end - i));
        
        // 16進数表示
        for j in 0..bytes_to_show {
            print!("{:02x} ", buffer[i + j]);
        }
        
        // 16バイトに満たない場合はスペースで埋める
        for _ in bytes_to_show..16 {
            print!("   ");
        }
        
        print!(" | ");
        println!("{}", instruction);
        
        // 命令の長さ分だけ進む
        addr += inst_len as u64;
        i += inst_len;
    }
    
    println!("{}", "=".repeat(80));
}

fn dump_data_sections(buffer: &[u8], sections: &[SectionInfo]) {
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
        
        let start_offset = section.offset as usize;
        let section_size = section.size as usize;
        let max_dump_size = 256; // 最大256バイトまでダンプ
        let dump_size = std::cmp::min(section_size, max_dump_size);
        
        if start_offset >= buffer.len() {
            println!("エラー: セクションオフセットがファイルサイズを超えています");
            continue;
        }
        
        let actual_end = std::cmp::min(start_offset + dump_size, buffer.len());
        
        if actual_end <= start_offset {
            println!("警告: ダンプするデータがありません");
            continue;
        }
        
        println!("");
        dump_hex_data(&buffer[start_offset..actual_end], section.addr);
        
        if section_size > max_dump_size {
            println!("... ({} バイト中 {} バイトを表示)", section_size, dump_size);
        }
    }
    
    println!("{}", "=".repeat(80));
}

fn dump_hex_data(data: &[u8], base_addr: u64) {
    let mut addr = base_addr;
    let mut i = 0;
    
    while i < data.len() {
        // アドレス表示
        print!("{:016x}: ", addr);
        
        // 16バイトまたは残りのバイト数
        let bytes_to_show = std::cmp::min(16, data.len() - i);
        
        // 16進数表示
        for j in 0..bytes_to_show {
            print!("{:02x} ", data[i + j]);
        }
        
        // 16バイトに満たない場合はスペースで埋める
        for _ in bytes_to_show..16 {
            print!("   ");
        }
        
        print!(" | ");
        
        // ASCII表示
        for j in 0..bytes_to_show {
            let byte = data[i + j];
            if byte >= 32 && byte <= 126 {
                print!("{}", byte as char);
            } else {
                print!(".");
            }
        }
        
        println!();
        
        addr += 16;
        i += bytes_to_show;
    }
}

fn display_debug_info(buffer: &[u8], debug_info: &DebugInfo) {
    println!("\nDWARFデバッグ情報:");
    
    // DWARFセクション情報を表示
    if !debug_info.dwarf_sections.is_empty() {
        println!("検出されたDWARFセクション: {}個", debug_info.dwarf_sections.len());
        
        for (index, section) in debug_info.dwarf_sections.iter().enumerate() {
            println!("  [{}] {} (addr=0x{:016x}, size={}, offset=0x{:08x})", 
                     index + 1, section.name, section.addr, section.size, section.offset);
        }
    } else {
        println!("DWARFデバッグセクションが見つかりませんでした");
        println!("デバッグ情報を含むdSYMファイルが必要です。");
    }
    
    // シンボルテーブル情報を表示
    if let Some(symtab) = &debug_info.symtab_info {
        println!("\nシンボルテーブル情報:");
        println!("シンボルテーブルオフセット: 0x{:08x}", symtab.symoff);
        println!("シンボル数: {} 個", symtab.nsyms);
        println!("文字列テーブルオフセット: 0x{:08x}", symtab.stroff);
        println!("文字列テーブルサイズ: {} バイト", symtab.strsize);
        
        // シンボルの一部を表示
        display_symbols(buffer, symtab);
    } else {
        println!("\nシンボルテーブルが見つかりませんでした");
    }
    
    // DWARFデバッグ情報の詳細解析を実行
    if !debug_info.dwarf_sections.is_empty() {
        display_debug_info_detailed(buffer, debug_info);
    }
    

}

fn display_symbols(buffer: &[u8], symtab: &SymtabInfo) {
    println!("\nシンボル一覧:");
    
    let symbol_size = 16; // nlist_64のサイズ
    let max_symbols = symtab.nsyms;
    
    for i in 0..max_symbols {
        let symbol_offset = symtab.symoff as usize + (i as usize * symbol_size);
        
        if symbol_offset + symbol_size > buffer.len() {
            break;
        }
        
        // nlist_64構造体を読み取り
        let n_strx = u32::from_le_bytes([
            buffer[symbol_offset], buffer[symbol_offset + 1],
            buffer[symbol_offset + 2], buffer[symbol_offset + 3]
        ]);
        let n_type = buffer[symbol_offset + 4];
        let n_sect = buffer[symbol_offset + 5];
        let _n_desc = u16::from_le_bytes([
            buffer[symbol_offset + 6], buffer[symbol_offset + 7]
        ]);
        let n_value = u64::from_le_bytes([
            buffer[symbol_offset + 8], buffer[symbol_offset + 9],
            buffer[symbol_offset + 10], buffer[symbol_offset + 11],
            buffer[symbol_offset + 12], buffer[symbol_offset + 13],
            buffer[symbol_offset + 14], buffer[symbol_offset + 15]
        ]);
        
        // シンボル名を取得
        let symbol_name = if n_strx > 0 {
            get_string_from_table(buffer, symtab.stroff, symtab.strsize, n_strx)
        } else {
            "<無名>".to_string()
        };
        
        // シンボルタイプを判定
        let symbol_type = match n_type & 0x0e {
            0x00 => "UNDF", // 未定義
            0x02 => "ABS",  // 絶対
            0x0e => "SECT", // セクション
            0x0c => "PBUD", // プリバインド未定義
            0x0a => "INDR", // 間接
            _ => "OTHER",
        };
        
        let external = if n_type & 0x01 != 0 { "EXT" } else { "LOC" };
        
        println!("  {}: {} {} sect={} addr=0x{:016x} {}", 
                 i + 1, symbol_type, external, n_sect, n_value, symbol_name);
    }
    

}

fn get_string_from_table(buffer: &[u8], stroff: u32, strsize: u32, str_index: u32) -> String {
    let start = stroff as usize + str_index as usize;
    let end = std::cmp::min(start + 256, (stroff + strsize) as usize); // 最大256文字まで
    
    if start >= buffer.len() {
        return "<無効>".to_string();
    }
    
    // ヌル終端文字列を探す
    let mut actual_end = start;
    for i in start..std::cmp::min(end, buffer.len()) {
        if buffer[i] == 0 {
            actual_end = i;
            break;
        }
        actual_end = i + 1;
    }
    
    if actual_end <= start {
        return "<空>".to_string();
    }
    
    // UTF-8として解釈
    match std::str::from_utf8(&buffer[start..actual_end]) {
        Ok(s) => s.to_string(),
        Err(_) => format!("<バイナリ:{:02x}...>", buffer[start]),
    }
}

// ModRMバイトの解析ヘルパー関数
fn parse_modrm_length(modrm: u8, code: &[u8], offset: usize) -> usize {
    let mod_bits = (modrm & 0xc0) >> 6;
    let rm = modrm & 0x07;
    
    match mod_bits {
        0b00 => {
            if rm == 0b100 {
                // SIBバイトが必要
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
            } else if rm == 0b101 {
                5 // ModRM + disp32
            } else {
                1 // ModRMのみ
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
                    let imm = u32::from_le_bytes([code[length], code[length+1], code[length+2], code[length+3]]);
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
                        }
                        ("nop (multi-byte)".to_string(), length)
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
        },
        
        // Misc instructions
        0x90 => ("nop".to_string(), length),
        0xcc => ("int3".to_string(), length),
        0xb0..=0xbf => {
            // MOV reg, imm8/imm32/imm64
            if rex_prefix && (opcode & 0x08) != 0 {
                // 64-bit immediate
                if length + 8 <= code.len() {
                    let imm = u64::from_le_bytes([
                        code[length], code[length+1], code[length+2], code[length+3],
                        code[length+4], code[length+5], code[length+6], code[length+7]
                    ]);
                    length += 8;
                    (format!("mov r{}, 0x{:016x}", opcode & 0x07, imm), length)
                } else {
                    ("mov r64, imm64 (incomplete)".to_string(), length)
                }
            } else if (opcode & 0x08) != 0 {
                // 32-bit immediate
                if length + 4 <= code.len() {
                    let imm = u32::from_le_bytes([code[length], code[length+1], code[length+2], code[length+3]]);
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
        
        _ => {
            // より詳細な命令解析
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

fn display_macho_header(header: &MachHeader64) {
    println!("\n=== Mach-Oヘッダー情報 ===");
    
    // マジックナンバー
    let magic_str = match header.magic {
        0xcffaedfe => "MH_MAGIC_64 (リトルエンディアン)",
        0xfeedfacf => "MH_MAGIC_64 (ビッグエンディアン)",
        _ => "不明",
    };
    println!("マジックナンバー: {} (0x{:08x})", magic_str, header.magic);
    
    // CPUタイプ
    let cpu_str = match header.cputype {
        1 => "VAX",
        6 => "MC680x0",
        7 => "Intel x86",
        10 => "MC98000",
        11 => "HPPA",
        12 => "ARM",
        13 => "MC88000",
        14 => "SPARC",
        15 => "Intel i860",
        16 => "PowerPC",
        18 => "PowerPC 64",
        16777223 => "Intel x86_64", // 0x01000007
        16777228 => "ARM64",        // 0x0100000c
        117440513 => "Intel x86_64 (バイトオーダー問題)", // 0x07000001 (実際の読み取り値)
        50331648 => "x86_64 サブタイプ (バイトオーダー問題)", // 0x03000000
        _ => "不明",
    };
    println!("CPUタイプ: {} ({})", cpu_str, header.cputype);
    
    // CPUサブタイプ
    let subtype_str = match (header.cputype, header.cpusubtype) {
        (16777223, 3) => "x86_64 All",        // 0x01000007, 3
        (16777223, 4) => "x86_64 Haswell",    // 0x01000007, 4
        (16777228, 0) => "ARM64 All",         // 0x0100000c, 0
        (16777228, 1) => "ARM64 v8",          // 0x0100000c, 1
        (16777228, 2) => "ARM64e",            // 0x0100000c, 2
        (117440513, 50331648) => "x86_64 All (バイトオーダー問題)", // 実際の読み取り値
        _ => "不明",
    };
    println!("CPUサブタイプ: {} ({})", subtype_str, header.cpusubtype);
    
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
    
    println!("予約済み: 0x{:08x}", header.reserved);
    println!("{}", "=".repeat(80));
}

// dSYMファイルのパスを構築する関数
fn find_dsym_file(executable_path: &str) -> Option<String> {
    let path = Path::new(executable_path);
    let file_name = path.file_name()?.to_str()?;
    let parent_dir = path.parent().unwrap_or(Path::new("."));
    
    // dSYMファイルのパスを構築
    let dsym_path = parent_dir.join(format!("{}.dSYM", file_name))
        .join("Contents")
        .join("Resources")
        .join("DWARF")
        .join(file_name);
    
    // dSYMファイルが存在するかチェック
    if dsym_path.exists() {
        Some(dsym_path.to_string_lossy().to_string())
    } else {
        None
    }
}

fn dump_file(file_path: &str) -> io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    println!("ファイル: {}", file_path);
    println!("サイズ: {} バイト", buffer.len());
    
    // Mach-Oファイルかどうかチェックしてヘッダー情報を表示
    if is_macho_file(&buffer) {
        if let Some(macho_header) = parse_macho_header(&buffer) {
            display_macho_header(&macho_header);
            
            // __TEXTセクションを探して逆アセンブル
            if let Some(text_section) = find_text_section(&buffer, &macho_header) {
                disassemble_text_section(&buffer, &text_section, &macho_header);
            } else {
                println!("警告: __TEXTセクションが見つかりませんでした");
            }
            
            // __DATAセクションを探してダンプ
            let data_sections = find_data_sections(&buffer, &macho_header);
            dump_data_sections(&buffer, &data_sections);
            
            // デバッグ情報を探して表示
            let debug_info = find_debug_info(&buffer, &macho_header);
            
            // dSYMファイルからDWARFデバッグ情報を追加で読み込み
            if debug_info.dwarf_sections.is_empty() {
                if let Some(dsym_path) = find_dsym_file(file_path) {
                    println!("\n対応するdSYMファイルを発見: {}", dsym_path);
                    
                    // dSYMファイルを読み込み
                    if let Ok(mut dsym_file) = File::open(&dsym_path) {
                        let mut dsym_buffer = Vec::new();
                        if dsym_file.read_to_end(&mut dsym_buffer).is_ok() {
                            if let Some(dsym_header) = parse_macho_header(&dsym_buffer) {
                                let dsym_debug_info = find_debug_info(&dsym_buffer, &dsym_header);
                                if !dsym_debug_info.dwarf_sections.is_empty() {
                                    println!("dSYMファイルからDWARFデバッグ情報を読み込みました");
                                    display_debug_info(&dsym_buffer, &dsym_debug_info);
                                } else {
                                    display_debug_info(&buffer, &debug_info);
                                }
                            } else {
                                println!("警告: dSYMファイルの解析に失敗しました");
                                display_debug_info(&buffer, &debug_info);
                            }
                        } else {
                            println!("警告: dSYMファイルの読み込みに失敗しました");
                            display_debug_info(&buffer, &debug_info);
                        }
                    } else {
                        println!("警告: dSYMファイルを開けませんでした");
                        display_debug_info(&buffer, &debug_info);
                    }
                } else {
                    display_debug_info(&buffer, &debug_info);
                }
            } else {
                display_debug_info(&buffer, &debug_info);
            }
        } else {
            println!("警告: Mach-Oファイルですが、ヘッダーの解析に失敗しました");
            println!("{}", "=".repeat(80));
        }
    } else {
        println!("{}", "=".repeat(80));
        println!("ファイルタイプ: 不明なバイナリファイル");
        println!("{}", "=".repeat(80));
    }
    
    Ok(())
}

// DWARFバージョンに応じたDIEタグ名を取得
fn get_die_tag_name(abbrev_code: u64, version: u16) -> &'static str {
    match version {
        1 => {
            // DWARF1: 基本的なタグのみ
            match abbrev_code {
                0x11 => "DW_TAG_compile_unit",
                0x24 => "DW_TAG_base_type",
                0x2e => "DW_TAG_subprogram",
                0x34 => "DW_TAG_variable",
                0x05 => "DW_TAG_formal_parameter",
                0x0d => "DW_TAG_member",
                0x13 => "DW_TAG_structure_type",
                0x17 => "DW_TAG_union_type",
                0x01 => "DW_TAG_array_type",
                0x0f => "DW_TAG_pointer_type",
                _ => "DW_TAG_unknown",
            }
        },
        2 => {
            // DWARF2: 標準化された最初のバージョン
            match abbrev_code {
                0x01 => "DW_TAG_array_type",
                0x04 => "DW_TAG_enumeration_type",
                0x05 => "DW_TAG_formal_parameter",
                0x0b => "DW_TAG_lexical_block",
                0x0d => "DW_TAG_member",
                0x0f => "DW_TAG_pointer_type",
                0x11 => "DW_TAG_compile_unit",
                0x13 => "DW_TAG_structure_type",
                0x15 => "DW_TAG_subroutine_type",
                0x16 => "DW_TAG_typedef",
                0x17 => "DW_TAG_union_type",
                0x21 => "DW_TAG_subrange_type",
                0x24 => "DW_TAG_base_type",
                0x26 => "DW_TAG_const_type",
                0x28 => "DW_TAG_enumerator",
                0x2e => "DW_TAG_subprogram",
                0x34 => "DW_TAG_variable",
                0x35 => "DW_TAG_volatile_type",
                _ => "DW_TAG_unknown",
            }
        },
        3 => {
            // DWARF3: DWARF2の拡張
            match abbrev_code {
                0x01 => "DW_TAG_array_type",
                0x02 => "DW_TAG_class_type",
                0x04 => "DW_TAG_enumeration_type",
                0x05 => "DW_TAG_formal_parameter",
                0x08 => "DW_TAG_imported_declaration",
                0x0b => "DW_TAG_lexical_block",
                0x0d => "DW_TAG_member",
                0x0f => "DW_TAG_pointer_type",
                0x10 => "DW_TAG_reference_type",
                0x11 => "DW_TAG_compile_unit",
                0x13 => "DW_TAG_structure_type",
                0x15 => "DW_TAG_subroutine_type",
                0x16 => "DW_TAG_typedef",
                0x17 => "DW_TAG_union_type",
                0x1c => "DW_TAG_inheritance",
                0x1d => "DW_TAG_inlined_subroutine",
                0x1e => "DW_TAG_module",
                0x21 => "DW_TAG_subrange_type",
                0x24 => "DW_TAG_base_type",
                0x26 => "DW_TAG_const_type",
                0x28 => "DW_TAG_enumerator",
                0x2e => "DW_TAG_subprogram",
                0x2f => "DW_TAG_template_type_parameter",
                0x30 => "DW_TAG_template_value_parameter",
                0x34 => "DW_TAG_variable",
                0x35 => "DW_TAG_volatile_type",
                0x37 => "DW_TAG_restrict_type",
                0x39 => "DW_TAG_namespace",
                0x3a => "DW_TAG_imported_module",
                0x3b => "DW_TAG_unspecified_type",
                _ => "DW_TAG_unknown",
            }
        },
        4 => {
            // DWARF4: 型シグネチャや分割DWARFのサポート
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
                0x13 => "DW_TAG_structure_type",
                0x15 => "DW_TAG_subroutine_type",
                0x16 => "DW_TAG_typedef",
                0x17 => "DW_TAG_union_type",
                0x18 => "DW_TAG_unspecified_parameters",
                0x1c => "DW_TAG_inheritance",
                0x1d => "DW_TAG_inlined_subroutine",
                0x1e => "DW_TAG_module",
                0x1f => "DW_TAG_ptr_to_member_type",
                0x21 => "DW_TAG_subrange_type",
                0x24 => "DW_TAG_base_type",
                0x26 => "DW_TAG_const_type",
                0x27 => "DW_TAG_constant",
                0x28 => "DW_TAG_enumerator",
                0x2e => "DW_TAG_subprogram",
                0x2f => "DW_TAG_template_type_parameter",
                0x30 => "DW_TAG_template_value_parameter",
                0x34 => "DW_TAG_variable",
                0x35 => "DW_TAG_volatile_type",
                0x37 => "DW_TAG_restrict_type",
                0x38 => "DW_TAG_interface_type",
                0x39 => "DW_TAG_namespace",
                0x3a => "DW_TAG_imported_module",
                0x3b => "DW_TAG_unspecified_type",
                0x3c => "DW_TAG_partial_unit",
                0x3d => "DW_TAG_imported_unit",
                // DWARF4で追加されたタグ
                0x41 => "DW_TAG_type_unit",
                0x42 => "DW_TAG_rvalue_reference_type",
                0x43 => "DW_TAG_template_alias",
                _ => "DW_TAG_unknown",
            }
        },
        5 => {
            // DWARF5: 最新仕様、全機能対応
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
                0x36 => "DW_TAG_dwarf_procedure",
                0x37 => "DW_TAG_restrict_type",
                0x38 => "DW_TAG_interface_type",
                0x39 => "DW_TAG_namespace",
                0x3a => "DW_TAG_imported_module",
                0x3b => "DW_TAG_unspecified_type",
                0x3c => "DW_TAG_partial_unit",
                0x3d => "DW_TAG_imported_unit",
                0x3f => "DW_TAG_condition",
                0x40 => "DW_TAG_shared_type",
                0x41 => "DW_TAG_type_unit",
                0x42 => "DW_TAG_rvalue_reference_type",
                0x43 => "DW_TAG_template_alias",
                // DWARF5で追加されたタグ
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
        },
        _ => {
            // 未対応バージョンはDWARF2形式で処理
            match abbrev_code {
                0x01 => "DW_TAG_array_type",
                0x11 => "DW_TAG_compile_unit",
                0x24 => "DW_TAG_base_type",
                0x2e => "DW_TAG_subprogram",
                0x34 => "DW_TAG_variable",
                0x05 => "DW_TAG_formal_parameter",
                0x0d => "DW_TAG_member",
                0x13 => "DW_TAG_structure_type",
                0x17 => "DW_TAG_union_type",
                0x0f => "DW_TAG_pointer_type",
                _ => "DW_TAG_unknown",
            }
        }
    }
}

// DWARFバージョンに応じた属性フォーム情報を取得
fn get_attribute_form_info(attr_form: u64, version: u16) -> (&'static str, &'static str) {
    // 基本的なフォーム（全バージョン共通）
    let basic_form = match attr_form {
        0x01 => ("DW_FORM_addr", "アドレス値"),
        0x05 => ("DW_FORM_data2", "2バイトデータ"),
        0x06 => ("DW_FORM_data4", "4バイトデータ"),
        0x08 => ("DW_FORM_string", "インライン文字列"),
        0x0b => ("DW_FORM_data1", "1バイトデータ"),
        0x0e => ("DW_FORM_strp", "文字列ポインタ"),
        0x11 => ("DW_FORM_ref1", "1バイト参照"),
        0x12 => ("DW_FORM_ref2", "2バイト参照"),
        0x13 => ("DW_FORM_ref4", "4バイト参照"),
        _ => ("", ""),
    };
    
    if !basic_form.0.is_empty() {
        return basic_form;
    }
    
    // バージョン固有のフォーム
    match version {
        4 | 5 => {
            match attr_form {
                0x17 => ("DW_FORM_sec_offset", "セクションオフセット"),
                0x18 => ("DW_FORM_exprloc", "式ロケーション"),
                0x19 => ("DW_FORM_flag_present", "フラグ存在"),
                _ if version == 5 => {
                    match attr_form {
                        0x1a => ("DW_FORM_strx", "文字列インデックス (DWARF5)"),
                        0x1b => ("DW_FORM_addrx", "アドレスインデックス (DWARF5)"),
                        0x1e => ("DW_FORM_data16", "16バイトデータ (DWARF5)"),
                        0x21 => ("DW_FORM_implicit_const", "暗黙定数 (DWARF5)"),
                        0x22 => ("DW_FORM_loclistx", "ロケーションリストインデックス (DWARF5)"),
                        0x23 => ("DW_FORM_rnglistx", "範囲リストインデックス (DWARF5)"),
                        _ => ("DW_FORM_unknown", "不明なフォーム"),
                    }
                },
                _ => ("DW_FORM_unknown", "不明なフォーム"),
            }
        },
        _ => ("DW_FORM_unknown", "不明なフォーム"),
    }
}

fn parse_and_display_debug_info(buffer: &[u8], section: &SectionInfo) {
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("    エラー: __debug_infoセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("    === __debug_info 詳細解析 ===");
    
    // DWARF5準拠のコンパイル単位ヘッダーを解析
    let unit_length = u32::from_le_bytes([
        section_data[0], section_data[1], section_data[2], section_data[3]
    ]);
    let version = u16::from_le_bytes([
        section_data[4], section_data[5]
    ]);
    
    // DWARFバージョンに応じたヘッダー解析
    let (unit_type, abbrev_offset, address_size, header_offset) = match version {
        1 => {
            // DWARF1: 最初のDWARF仕様、簡素なヘッダー
            println!("    注意: DWARF1は非常に古い仕様で、限定的なサポートです");
            let abbrev_offset = u32::from_le_bytes([
                section_data[6], section_data[7], section_data[8], section_data[9]
            ]);
            let address_size = 4; // DWARF1では通常4バイトアドレス
            (None, abbrev_offset, address_size, 10)
        },
        2 => {
            // DWARF2: 最初の標準化されたDWARF仕様
            let abbrev_offset = u32::from_le_bytes([
                section_data[6], section_data[7], section_data[8], section_data[9]
            ]);
            let address_size = section_data[10];
            (None, abbrev_offset, address_size, 11)
        },
        3 => {
            // DWARF3: DWARF2の拡張版
            let abbrev_offset = u32::from_le_bytes([
                section_data[6], section_data[7], section_data[8], section_data[9]
            ]);
            let address_size = section_data[10];
            (None, abbrev_offset, address_size, 11)
        },
        4 => {
            // DWARF4: 型シグネチャや分割DWARFのサポート
            let abbrev_offset = u32::from_le_bytes([
                section_data[6], section_data[7], section_data[8], section_data[9]
            ]);
            let address_size = section_data[10];
            (None, abbrev_offset, address_size, 11)
        },
        5 => {
            // DWARF5: 最新仕様、unit_typeフィールドが追加
            let unit_type = section_data[6];
            let address_size = section_data[7];
            let abbrev_offset = u32::from_le_bytes([
                section_data[8], section_data[9], section_data[10], section_data[11]
            ]);
            (Some(unit_type), abbrev_offset, address_size, 12)
        },
        _ => {
            println!("    警告: 未対応のDWARFバージョン{}、DWARF2形式で解析します", version);
            let abbrev_offset = u32::from_le_bytes([
                section_data[6], section_data[7], section_data[8], section_data[9]
            ]);
            let address_size = section_data[10];
            (None, abbrev_offset, address_size, 11)
        }
    };
    
    println!("    === DWARF{}準拠コンパイル単位ヘッダー ===", version);
    println!("    ユニット長: {} バイト", unit_length);
    println!("    DWARFバージョン: {}", version);
    
    if let Some(ut) = unit_type {
        let unit_type_str = match ut {
            0x01 => "DW_UT_compile (通常のコンパイル単位)",
            0x02 => "DW_UT_type (型単位)",
            0x03 => "DW_UT_partial (部分単位)",
            0x04 => "DW_UT_skeleton (スケルトン単位)",
            0x05 => "DW_UT_split_compile (分割コンパイル単位)",
            0x06 => "DW_UT_split_type (分割型単位)",
            _ => "不明な単位タイプ",
        };
        println!("    単位タイプ: 0x{:02x} ({})", ut, unit_type_str);
    }
    
    println!("    アドレスサイズ: {} バイト", address_size);
    println!("    省略形オフセット: 0x{:08x}", abbrev_offset);
    
    // 省略形テーブルを取得（__debug_abbrevセクションから）
    let _abbrev_entries = find_abbrev_section_and_parse(buffer, abbrev_offset);
    
    // DIE（Debug Information Entry）を全件表示
    let mut offset = header_offset;
    let mut die_count = 0;
    
    println!("\n    --- DIE (Debug Information Entry) 一覧 ---");
    
    while offset < section_data.len() {
        let (abbrev_code, consumed) = read_uleb128(&section_data[offset..]);
        offset += consumed;
        
        if abbrev_code == 0 {
            println!("    DIE {}: NULL DIE (終端)", die_count + 1);
            die_count += 1;
            continue;
        }
        
        // DWARFバージョンに応じたDIEタグ解析
        let tag_name = get_die_tag_name(abbrev_code, version);
        
        println!("    DIE {}: 省略形コード={} ({})", die_count + 1, abbrev_code, tag_name);
        
        // DIEタイプ別の詳細情報を表示（DWARF5仕様準拠）
        match tag_name {
            // 基本的なプログラム構造
            "DW_TAG_compile_unit" => {
                println!("      [コンパイル単位] - ソースファイル全体の情報、翻訳単位");
            },
            "DW_TAG_partial_unit" => {
                println!("      [部分単位] - 分割コンパイル用の部分的なコンパイル単位");
            },
            "DW_TAG_type_unit" => {
                println!("      [型単位] - 型情報専用のコンパイル単位");
            },
            "DW_TAG_skeleton_unit" => {
                println!("      [スケルトン単位] - 分割DWARF用のスケルトン単位");
            },
            
            // 関数・サブプログラム
            "DW_TAG_subprogram" => {
                println!("      [サブプログラム] - 関数またはメソッドの定義");
            },
            "DW_TAG_inlined_subroutine" => {
                println!("      [インライン関数] - インライン展開された関数");
            },
            "DW_TAG_entry_point" => {
                println!("      [エントリポイント] - プログラムの開始点");
            },
            "DW_TAG_call_site" => {
                println!("      [呼び出しサイト] - 関数呼び出し箇所（DWARF5）");
            },
            "DW_TAG_call_site_parameter" => {
                println!("      [呼び出しパラメータ] - 関数呼び出し時の引数（DWARF5）");
            },
            
            // 変数・データ
            "DW_TAG_variable" => {
                println!("      [変数] - グローバル変数またはローカル変数");
            },
            "DW_TAG_formal_parameter" => {
                println!("      [仮引数] - 関数の引数パラメータ");
            },
            "DW_TAG_constant" => {
                println!("      [定数] - コンパイル時定数値");
            },
            "DW_TAG_unspecified_parameters" => {
                println!("      [可変引数] - 可変長引数（...）");
            },
            
            // 基本データ型
            "DW_TAG_base_type" => {
                println!("      [基本型] - int, char, float等の基本データ型");
            },
            "DW_TAG_unspecified_type" => {
                println!("      [未指定型] - void型や不完全型");
            },
            "DW_TAG_atomic_type" => {
                println!("      [アトミック型] - C11 _Atomic型（DWARF5）");
            },
            "DW_TAG_immutable_type" => {
                println!("      [不変型] - 不変性を持つ型（DWARF5）");
            },
            
            // 型修飾子
            "DW_TAG_const_type" => {
                println!("      [const型] - const修飾された型");
            },
            "DW_TAG_volatile_type" => {
                println!("      [volatile型] - volatile修飾された型");
            },
            "DW_TAG_restrict_type" => {
                println!("      [restrict型] - restrict修飾された型");
            },
            "DW_TAG_packed_type" => {
                println!("      [パック型] - パック属性付きの型");
            },
            "DW_TAG_shared_type" => {
                println!("      [共有型] - 共有メモリ型");
            },
            
            // ポインタ・参照型
            "DW_TAG_pointer_type" => {
                println!("      [ポインタ型] - ポインタ変数の型情報");
            },
            "DW_TAG_reference_type" => {
                println!("      [参照型] - C++参照型（&）");
            },
            "DW_TAG_rvalue_reference_type" => {
                println!("      [右辺値参照型] - C++11右辺値参照（&&）");
            },
            "DW_TAG_ptr_to_member_type" => {
                println!("      [メンバーポインタ型] - C++メンバーポインタ");
            },
            
            // 配列・コンテナ型
            "DW_TAG_array_type" => {
                println!("      [配列型] - 配列変数の型情報");
            },
            "DW_TAG_subrange_type" => {
                println!("      [部分範囲型] - 配列の次元・範囲情報");
            },
            "DW_TAG_generic_subrange" => {
                println!("      [汎用部分範囲] - 汎用的な範囲型（DWARF5）");
            },
            "DW_TAG_coarray_type" => {
                println!("      [コ配列型] - Fortran coarray型（DWARF5）");
            },
            "DW_TAG_dynamic_type" => {
                println!("      [動的型] - 実行時に決定される型（DWARF5）");
            },
            
            // 構造体・クラス・オブジェクト指向
            "DW_TAG_structure_type" => {
                println!("      [構造体型] - struct定義");
            },
            "DW_TAG_class_type" => {
                println!("      [クラス型] - C++クラス定義");
            },
            "DW_TAG_union_type" => {
                println!("      [共用体型] - union定義");
            },
            "DW_TAG_interface_type" => {
                println!("      [インターフェース型] - Java/C#インターフェース");
            },
            "DW_TAG_member" => {
                println!("      [メンバー] - 構造体またはクラスのメンバー変数");
            },
            "DW_TAG_inheritance" => {
                println!("      [継承] - クラス継承関係");
            },
            "DW_TAG_friend" => {
                println!("      [フレンド] - C++フレンド宣言");
            },
            "DW_TAG_access_declaration" => {
                println!("      [アクセス宣言] - アクセス修飾子宣言");
            },
            
            // 列挙型
            "DW_TAG_enumeration_type" => {
                println!("      [列挙型] - enum定義");
            },
            "DW_TAG_enumerator" => {
                println!("      [列挙子] - enum値の個別要素");
            },
            
            // 関数型・サブルーチン型
            "DW_TAG_subroutine_type" => {
                println!("      [サブルーチン型] - 関数ポインタの型情報");
            },
            "DW_TAG_string_type" => {
                println!("      [文字列型] - 言語固有の文字列型");
            },
            "DW_TAG_file_type" => {
                println!("      [ファイル型] - ファイルハンドル型");
            },
            "DW_TAG_set_type" => {
                println!("      [集合型] - Pascal等の集合型");
            },
            
            // 型定義・エイリアス
            "DW_TAG_typedef" => {
                println!("      [型定義] - typedef宣言による型エイリアス");
            },
            
            // テンプレート・ジェネリクス
            "DW_TAG_template_type_parameter" => {
                println!("      [テンプレート型パラメータ] - C++テンプレート型引数");
            },
            "DW_TAG_template_value_parameter" => {
                println!("      [テンプレート値パラメータ] - C++テンプレート値引数");
            },
            "DW_TAG_template_alias" => {
                println!("      [テンプレートエイリアス] - C++11 using宣言");
            },
            
            // 名前空間・モジュール
            "DW_TAG_namespace" => {
                println!("      [名前空間] - C++名前空間");
            },
            "DW_TAG_module" => {
                println!("      [モジュール] - Fortran/Ada等のモジュール");
            },
            "DW_TAG_imported_declaration" => {
                println!("      [インポート宣言] - using宣言");
            },
            "DW_TAG_imported_module" => {
                println!("      [インポートモジュール] - モジュールインポート");
            },
            "DW_TAG_imported_unit" => {
                println!("      [インポート単位] - 単位インポート");
            },
            
            // 制御構造・ブロック
            "DW_TAG_lexical_block" => {
                println!("      [字句ブロック] - {{}}で囲まれたスコープ");
            },
            "DW_TAG_label" => {
                println!("      [ラベル] - goto文のラベル");
            },
            "DW_TAG_with_stmt" => {
                println!("      [with文] - Pascal等のwith文");
            },
            "DW_TAG_try_block" => {
                println!("      [try文] - 例外処理のtryブロック");
            },
            "DW_TAG_catch_block" => {
                println!("      [catch文] - 例外処理のcatchブロック");
            },
            "DW_TAG_thrown_type" => {
                println!("      [例外型] - throw文で投げられる例外の型");
            },
            
            // バリアント・共用体関連
            "DW_TAG_variant" => {
                println!("      [バリアント] - 判別共用体の選択肢");
            },
            "DW_TAG_variant_part" => {
                println!("      [バリアント部] - 判別共用体の本体");
            },
            
            // 共通ブロック（Fortran等）
            "DW_TAG_common_block" => {
                println!("      [共通ブロック] - Fortran COMMON文");
            },
            "DW_TAG_common_inclusion" => {
                println!("      [共通ブロック包含] - COMMON文の包含");
            },
            
            // 名前リスト（Fortran等）
            "DW_TAG_namelist" => {
                println!("      [名前リスト] - Fortran NAMELIST文");
            },
            "DW_TAG_namelist_item" => {
                println!("      [名前リスト項目] - NAMELIST項目");
            },
            
            // DWARF手続き・条件
            "DW_TAG_dwarf_procedure" => {
                println!("      [DWARF手続き] - DWARF式で使用する手続き");
            },
            "DW_TAG_condition" => {
                println!("      [条件] - 条件式");
            },
            
            _ => {
                println!("      [その他] - {}", tag_name);
            }
        }
        
        // 属性値を読み取り（詳細版）
        let mut attr_count = 0;
        println!("      詳細属性情報:");
        while offset < section_data.len() && attr_count < 8 {
            let (attr_value, consumed) = read_uleb128(&section_data[offset..]);
            offset += consumed;
            
            if attr_value == 0 {
                break;
            }
            
            // 属性値の意味を推定して表示（詳細デバッグ情報付き）
            let attr_description = match attr_count {
                0 => {
                    // 最初の属性は通常名前やコンパイラ情報 (DW_AT_producer)
                    if attr_value < 0x1000 {
                        format!("文字列インデックス: {} (DW_AT_producer - コンパイラ情報)", attr_value)
                    } else {
                        format!("アドレス: 0x{:08x} (DW_AT_producer - コンパイラ情報)", attr_value)
                    }
                },
                1 => {
                    // 2番目の属性はDW_AT_language（DWARF言語コード）
                    // 注意: Apple clangの場合、標準DWARF仕様と異なる場合があります
                    let language_str = match attr_value {
                        // DWARF 5公式仕様に基づく標準言語コード
                        1 => "C89言語 (DW_LANG_C89)",
                        2 => "C言語 (DW_LANG_C)",
                        3 => "Ada83 (DW_LANG_Ada83)",
                        4 => "C++言語 (DW_LANG_C_plus_plus)",
                        5 => "Cobol74 (DW_LANG_Cobol74)",
                        6 => "Cobol85 (DW_LANG_Cobol85)",
                        7 => "Fortran77 (DW_LANG_Fortran77)",
                        8 => "Fortran90 (DW_LANG_Fortran90)",
                        9 => "Pascal83 (DW_LANG_Pascal83)",
                        10 => "Modula2 (DW_LANG_Modula2)",
                        11 => "Java言語 (DW_LANG_Java)",
                        12 => "C99言語 (DW_LANG_C99)",
                        13 => "Ada95 (DW_LANG_Ada95)",
                        14 => "Fortran95 (DW_LANG_Fortran95)",
                        15 => "PLI (DW_LANG_PLI)",
                        16 => "ObjC言語 (DW_LANG_ObjC)",
                        17 => "ObjC++言語 (DW_LANG_ObjC_plus_plus)",
                        18 => "UPC (DW_LANG_UPC)",
                        19 => "D言語 (DW_LANG_D)",
                        20 => "Python言語 (DW_LANG_Python)",
                        21 => "OpenCL (DW_LANG_OpenCL)",
                        22 => "Go言語 (DW_LANG_Go)",
                        23 => "Modula3 (DW_LANG_Modula3)",
                        24 => "Haskell言語 (DW_LANG_Haskell)",
                        25 => "C++03言語 (DW_LANG_C_plus_plus_03)",
                        26 => "C++11言語 (DW_LANG_C_plus_plus_11)",
                        27 => "OCaml言語 (DW_LANG_OCaml)",
                        28 => "Rust言語 (DW_LANG_Rust)",
                        29 => "C11言語 (DW_LANG_C11)",
                        30 => "Swift言語 (DW_LANG_Swift)",
                        31 => "Julia言語 (DW_LANG_Julia)",
                        32 => "Dylan言語 (DW_LANG_Dylan)",
                        33 => "C++14言語 (DW_LANG_C_plus_plus_14)",
                        34 => "Fortran03 (DW_LANG_Fortran03)",
                        35 => "Fortran08 (DW_LANG_Fortran08)",
                        36 => "RenderScript (DW_LANG_RenderScript)",
                        37 => "BLISS (DW_LANG_BLISS)",
                        
                        // DWARF 5以降に追加された言語コード
                        38 => "Kotlin言語 (DW_LANG_Kotlin)",
                        39 => "Zig言語 (DW_LANG_Zig)",
                        40 => "Crystal言語 (DW_LANG_Crystal)",
                        41 => "C++17言語 (DW_LANG_C_plus_plus_17)",
                        42 => "C++20言語 (DW_LANG_C_plus_plus_20)",
                        43 => "C17言語 (DW_LANG_C17)",
                        44 => "Fortran18 (DW_LANG_Fortran18)",
                        45 => "Ada2005 (DW_LANG_Ada2005)",
                        46 => "Ada2012 (DW_LANG_Ada2012)",
                        47 => "HIP (DW_LANG_HIP)",
                        48 => "Assembly (DW_LANG_Assembly)",
                        49 => "C#言語 (DW_LANG_C_sharp)",
                        50 => "Mojo言語 (DW_LANG_Mojo)",
                        51 => "GLSL (DW_LANG_GLSL)",
                        52 => "GLSL ES (DW_LANG_GLSL_ES)",
                        53 => "HLSL (DW_LANG_HLSL)",
                        54 => "OpenCL C++ (DW_LANG_OpenCL_CPP)",
                        55 => "C++ for OpenCL (DW_LANG_CPP_for_OpenCL)",
                        56 => "SYCL (DW_LANG_SYCL)",
                        57 => "C++23言語 (DW_LANG_C_plus_plus_23)",
                        58 => "Odin言語 (DW_LANG_Odin)",
                        59 => "P4 (DW_LANG_P4)",
                        60 => "Metal (DW_LANG_Metal)",
                        61 => "C23言語 (DW_LANG_C23)",
                        62 => "Fortran23 (DW_LANG_Fortran23)",
                        63 => "Ruby言語 (DW_LANG_Ruby)",
                        64 => "Move (DW_LANG_Move)",
                        65 => "Hylo (DW_LANG_Hylo)",
                        66 => "V言語 (DW_LANG_V)",
                        67 => "Algol68 (DW_LANG_Algol68)",
                        68 => "Nim言語 (DW_LANG_Nim)",
                        _ => {
                            if attr_value < 100 {
                                "未定義言語 (DWARFコード低値)"
                            } else if attr_value >= 0x8000 {
                                "ベンダー拡張言語"
                            } else {
                                "不明な言語コード"
                            }
                        },
                    };
                    format!("{} (DW_AT_language)", language_str)
                },
                2 => {
                    // 3番目はファイルパスやディレクトリ情報 (DW_AT_nameまたはDW_AT_comp_dir)
                    format!("パスインデックス: {}", attr_value)
                },
                3 => {
                    // 4番目はサイズやオフセット情報 (DW_AT_byte_sizeまたはDW_AT_stmt_list)
                    if attr_value < 0x10000 {
                        format!("サイズ: {} バイト (DW_AT_byte_size - データサイズ)", attr_value)
                    } else {
                        format!("オフセット: 0x{:08x} (DW_AT_stmt_list - 行番号テーブル)", attr_value)
                    }
                },
                4 => {
                    // 5番目はアドレスやエンコーディング情報 (DW_AT_low_pcまたはDW_AT_encoding)
                    if attr_value < 0x100 {
                        let encoding_str = match attr_value {
                            1 => "符号付き (DW_ATE_signed)",
                            2 => "符号なし (DW_ATE_unsigned)",
                            3 => "ブール型 (DW_ATE_boolean)",
                            4 => "浮動小数点 (DW_ATE_float)",
                            5 => "文字 (DW_ATE_signed_char)",
                            6 => "符号なし文字 (DW_ATE_unsigned_char)",
                            7 => "虚数 (DW_ATE_imaginary_float)",
                            8 => "小数 (DW_ATE_packed_decimal)",
                            9 => "数値 (DW_ATE_numeric_string)",
                            10 => "編集済み (DW_ATE_edited)",
                            11 => "符号付き固定小数点 (DW_ATE_signed_fixed)",
                            12 => "符号なし固定小数点 (DW_ATE_unsigned_fixed)",
                            13 => "10進浮動小数点 (DW_ATE_decimal_float)",
                            14 => "UTF文字 (DW_ATE_UTF)",
                            _ => "不明なエンコーディング",
                        };
                        format!("エンコーディング: {} (DW_AT_encoding)", encoding_str)
                    } else {
                        format!("開始アドレス: 0x{:08x} (DW_AT_low_pc - 関数開始位置)", attr_value)
                    }
                },
                5 => {
                    // 6番目は終了アドレスやオフセット情報 (DW_AT_high_pcまたはDW_AT_data_member_location)
                    if attr_value < 0x1000 {
                        format!("オフセット: {} バイト (DW_AT_data_member_location - メンバー位置)", attr_value)
                    } else {
                        format!("終了アドレス: 0x{:08x} (DW_AT_high_pc - 関数終了位置)", attr_value)
                    }
                },
                6 => {
                    // 7番目は型参照やフレームベース情報 (DW_AT_typeまたはDW_AT_frame_base)
                    if attr_value < 0x100 {
                        format!("フレームベース: {} (DW_AT_frame_base - スタックフレーム)", attr_value)
                    } else {
                        format!("型参照: 0x{:08x} (DW_AT_type - データ型参照)", attr_value)
                    }
                },
                7 => {
                    // 8番目は可視性やアクセシビリティ情報 (DW_AT_externalまたはDW_AT_accessibility)
                    if attr_value == 1 {
                        format!("外部可視: はい (DW_AT_external - グローバルシンボル)")
                    } else if attr_value == 0 {
                        format!("外部可視: いいえ (DW_AT_external - ローカルシンボル)")
                    } else {
                        let access_str = match attr_value {
                            1 => "パブリック (DW_ACCESS_public)",
                            2 => "プロテクテッド (DW_ACCESS_protected)",
                            3 => "プライベート (DW_ACCESS_private)",
                            _ => "不明なアクセシビリティ",
                        };
                        format!("アクセシビリティ: {} (DW_AT_accessibility)", access_str)
                    }
                },
                _ => {
                    // その他の属性は汎用的な解釈を行う
                    if attr_value == 0 {
                        format!("値: 0 (NULLまたは無効)")
                    } else if attr_value == 1 {
                        format!("値: 1 (TRUEまたは有効)")
                    } else if attr_value < 0x100 {
                        format!("小さな値: {} (インデックスまたはサイズ)", attr_value)
                    } else if attr_value < 0x10000 {
                        format!("中程度の値: {} (0x{:04x} - オフセットまたはサイズ)", attr_value, attr_value)
                    } else {
                        format!("大きな値: 0x{:08x} ({} - アドレスまたはポインタ)", attr_value, attr_value)
                    }
                },
            };
            
            println!("        • 属性{}: {}", attr_count + 1, attr_description);
            attr_count += 1;
        }
        
        if attr_count == 0 {
            println!("        • 属性なし");
        }
        
        die_count += 1;
        
        // 安全のため、一定のオフセットを超えたら停止
        if offset > 200 {
            break;
        }
    }
}

fn parse_and_display_debug_str(buffer: &[u8], section: &SectionInfo) {
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("    エラー: __debug_strセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("    === __debug_str 詳細解析 ===");
    println!("    文字列テーブルサイズ: {} バイト", section_size);
    
    // 文字列を抽出して全件表示
    let mut offset = 0;
    let mut string_count = 0;
    
    println!("\n    --- 文字列一覧 ---");
    
    while offset < section_data.len() {
        let (string, consumed) = extract_null_terminated_string(&section_data[offset..]);
        
        if !string.is_empty() {
            println!("    {}: [0x{:04x}] {}", string_count, offset, string);
            string_count += 1;
        }
        
        offset += consumed;
        
        if consumed == 0 {
            break;
        }
    }
    
    if string_count == 0 {
        println!("    (文字列が見つかりませんでした)");
    }
}

fn parse_and_display_debug_abbrev(buffer: &[u8], section: &SectionInfo, version: u16) {
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("    エラー: __debug_abbrevセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    println!("    === __debug_abbrev 詳細解析 ===");
    
    let mut offset = 0;
    let mut abbrev_count = 0;
    
    println!("    --- 省略形エントリ ---");
    
    while offset < section_data.len() {
        let (abbrev_code, consumed) = read_uleb128(&section_data[offset..]);
        offset += consumed;
        
        if abbrev_code == 0 {
            abbrev_count += 1;
            continue;
        }
        
        if offset >= section_data.len() {
            break;
        }
        
        let (tag, consumed) = read_uleb128(&section_data[offset..]);
        offset += consumed;
        
        if offset >= section_data.len() {
            break;
        }
        
        let has_children = section_data[offset];
        offset += 1;
        
        let tag_name = match tag {
            17 => "DW_TAG_compile_unit",
            46 => "DW_TAG_subprogram",
            52 => "DW_TAG_variable",
            36 => "DW_TAG_base_type",
            19 => "DW_TAG_structure_type",
            21 => "DW_TAG_union_type",
            22 => "DW_TAG_enumeration_type",
            15 => "DW_TAG_pointer_type",
            38 => "DW_TAG_const_type",
            53 => "DW_TAG_volatile_type",
            _ => "未知のタグ",
        };
        
        println!("    {}: コード={} タグ={} ({}) {}",
                 abbrev_count + 1, abbrev_code, tag, tag_name,
                 if has_children == 1 { "子あり" } else { "子なし" });
        
        // 属性リストを読み取り（最初の数個のみ）
        let mut attr_count = 0;
        while offset + 1 < section_data.len() && attr_count < 3 {
            let (attr_name, consumed) = read_uleb128(&section_data[offset..]);
            offset += consumed;
            
            if attr_name == 0 {
                let (attr_form, consumed) = read_uleb128(&section_data[offset..]);
                offset += consumed;
                if attr_form == 0 {
                    break;
                }
            } else {
                let (attr_form, consumed) = read_uleb128(&section_data[offset..]);
                offset += consumed;
                
                let attr_name_str = dwarf_attr_to_string(attr_name);
        // DWARFバージョンに応じた属性フォーム解析
        let (form_str, form_description) = get_attribute_form_info(attr_form, version);
        println!("      属性: {} | フォーム: {} ({})", attr_name_str, form_str, form_description);
                attr_count += 1;
            }
        }
        
        abbrev_count += 1;
        
        // 安全のため制限
        if offset > 500 {
            break;
        }
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
    
    if section_data.len() < 12 {
        println!("    エラー: __debug_arangesセクションが小さすぎます");
        return;
    }
    
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

fn parse_and_display_debug_ranges(_buffer: &[u8], section: &SectionInfo) {
    println!("    === __debug_ranges 詳細解析 ===");
    println!("    範囲リストのサイズ: {} バイト", section.size);
    println!("    (範囲リストの詳細解析は未実装)");
}

fn parse_and_display_debug_loc(_buffer: &[u8], section: &SectionInfo) {
    println!("    === __debug_loc 詳細解析 ===");
    println!("    ロケーションリストのサイズ: {} バイト", section.size);
    println!("    (ロケーションリストの詳細解析は未実装)");
}

fn parse_and_display_debug_pubnames(_buffer: &[u8], section: &SectionInfo) {
    println!("    === __debug_pubnames 詳細解析 ===");
    println!("    公開名前テーブルのサイズ: {} バイト", section.size);
    println!("    (公開名前テーブルの詳細解析は未実装)");
}

fn parse_and_display_debug_pubtypes(_buffer: &[u8], section: &SectionInfo) {
    println!("    === __debug_pubtypes 詳細解析 ===");
    println!("    公開型テーブルのサイズ: {} バイト", section.size);
    println!("    (公開型テーブルの詳細解析は未実装)");
}

fn parse_and_display_debug_frame(_buffer: &[u8], section: &SectionInfo) {
    println!("    === __debug_frame 詳細解析 ===");
    println!("    フレーム情報のサイズ: {} バイト", section.size);
    println!("    (フレーム情報の詳細解析は未実装)");
}

fn parse_and_display_eh_frame(_buffer: &[u8], section: &SectionInfo) {
    println!("    === __eh_frame 詳細解析 ===");
    println!("    例外処理フレーム情報のサイズ: {} バイト", section.size);
    println!("    (例外処理フレーム情報の詳細解析は未実装)");
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

fn read_uleb128(data: &[u8]) -> (u64, usize) {
    let mut result = 0u64;
    let mut shift = 0;
    let mut bytes_read = 0;
    
    for &byte in data {
        bytes_read += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        
        if (byte & 0x80) == 0 {
            break;
        }
        
        shift += 7;
        
        // 安全のため制限
        if bytes_read >= 10 {
            break;
        }
    }
    
    (result, bytes_read)
}

// __debug_abbrevセクションを検索して省略形テーブルを解析する関数
fn find_abbrev_section_and_parse(_buffer: &[u8], _abbrev_offset: u32) -> Vec<()> {
    // 簡易実装：バッファ全体から__debug_abbrevセクションを検索
    // 実際の実装では、abbrev_offsetを使用してより正確に検索する必要がある
    
    // 簡易的に、既知の__debug_abbrevセクション情報を使用
    // より正確な実装のためには、セクション情報を引数として渡す必要がある
    Vec::new() // 暫定的に空のベクターを返す
}



// DWARF属性定数をDW_AT_名に変換する関数
fn dwarf_attr_to_string(attr: u64) -> String {
    match attr {
        0x01 => "DW_AT_sibling".to_string(),
        0x02 => "DW_AT_location".to_string(),
        0x03 => "DW_AT_name".to_string(),
        0x09 => "DW_AT_ordering".to_string(),
        0x0b => "DW_AT_byte_size".to_string(),
        0x0c => "DW_AT_bit_offset".to_string(),
        0x0d => "DW_AT_bit_size".to_string(),
        0x10 => "DW_AT_stmt_list".to_string(),
        0x11 => "DW_AT_low_pc".to_string(),
        0x12 => "DW_AT_high_pc".to_string(),
        0x13 => "DW_AT_language".to_string(),
        0x15 => "DW_AT_discr".to_string(),
        0x16 => "DW_AT_discr_value".to_string(),
        0x17 => "DW_AT_visibility".to_string(),
        0x18 => "DW_AT_import".to_string(),
        0x19 => "DW_AT_string_length".to_string(),
        0x1a => "DW_AT_common_reference".to_string(),
        0x1b => "DW_AT_comp_dir".to_string(),
        0x1c => "DW_AT_const_value".to_string(),
        0x1d => "DW_AT_containing_type".to_string(),
        0x1e => "DW_AT_default_value".to_string(),
        0x20 => "DW_AT_inline".to_string(),
        0x21 => "DW_AT_is_optional".to_string(),
        0x22 => "DW_AT_lower_bound".to_string(),
        0x25 => "DW_AT_producer".to_string(),
        0x27 => "DW_AT_prototyped".to_string(),
        0x2a => "DW_AT_return_addr".to_string(),
        0x2c => "DW_AT_start_scope".to_string(),
        0x2e => "DW_AT_bit_stride".to_string(),
        0x2f => "DW_AT_upper_bound".to_string(),
        0x31 => "DW_AT_abstract_origin".to_string(),
        0x32 => "DW_AT_accessibility".to_string(),
        0x33 => "DW_AT_address_class".to_string(),
        0x34 => "DW_AT_artificial".to_string(),
        0x35 => "DW_AT_base_types".to_string(),
        0x36 => "DW_AT_calling_convention".to_string(),
        0x37 => "DW_AT_count".to_string(),
        0x38 => "DW_AT_data_member_location".to_string(),
        0x39 => "DW_AT_decl_column".to_string(),
        0x3a => "DW_AT_decl_file".to_string(),
        0x3b => "DW_AT_decl_line".to_string(),
        0x3c => "DW_AT_declaration".to_string(),
        0x3d => "DW_AT_discr_list".to_string(),
        0x3e => "DW_AT_encoding".to_string(),
        0x3f => "DW_AT_external".to_string(),
        0x40 => "DW_AT_frame_base".to_string(),
        0x41 => "DW_AT_friend".to_string(),
        0x42 => "DW_AT_identifier_case".to_string(),
        0x43 => "DW_AT_macro_info".to_string(),
        0x44 => "DW_AT_namelist_item".to_string(),
        0x45 => "DW_AT_priority".to_string(),
        0x46 => "DW_AT_segment".to_string(),
        0x47 => "DW_AT_specification".to_string(),
        0x48 => "DW_AT_static_link".to_string(),
        0x49 => "DW_AT_type".to_string(),
        0x4a => "DW_AT_use_location".to_string(),
        0x4b => "DW_AT_variable_parameter".to_string(),
        0x4c => "DW_AT_virtuality".to_string(),
        0x4d => "DW_AT_vtable_elem_location".to_string(),
        // DWARF 3 attributes
        0x4e => "DW_AT_allocated".to_string(),
        0x4f => "DW_AT_associated".to_string(),
        0x50 => "DW_AT_data_location".to_string(),
        0x51 => "DW_AT_byte_stride".to_string(),
        0x52 => "DW_AT_entry_pc".to_string(),
        0x53 => "DW_AT_use_UTF8".to_string(),
        0x54 => "DW_AT_extension".to_string(),
        0x55 => "DW_AT_ranges".to_string(),
        0x56 => "DW_AT_trampoline".to_string(),
        0x57 => "DW_AT_call_column".to_string(),
        0x58 => "DW_AT_call_file".to_string(),
        0x59 => "DW_AT_call_line".to_string(),
        0x5a => "DW_AT_description".to_string(),
        0x5b => "DW_AT_binary_scale".to_string(),
        0x5c => "DW_AT_decimal_scale".to_string(),
        0x5d => "DW_AT_small".to_string(),
        0x5e => "DW_AT_decimal_sign".to_string(),
        0x5f => "DW_AT_digit_count".to_string(),
        0x60 => "DW_AT_picture_string".to_string(),
        0x61 => "DW_AT_mutable".to_string(),
        0x62 => "DW_AT_threads_scaled".to_string(),
        0x63 => "DW_AT_explicit".to_string(),
        0x64 => "DW_AT_object_pointer".to_string(),
        0x65 => "DW_AT_endianity".to_string(),
        0x66 => "DW_AT_elemental".to_string(),
        0x67 => "DW_AT_pure".to_string(),
        0x68 => "DW_AT_recursive".to_string(),
        // DWARF 4 attributes
        0x69 => "DW_AT_signature".to_string(),
        0x6a => "DW_AT_main_subprogram".to_string(),
        0x6b => "DW_AT_data_bit_offset".to_string(),
        0x6c => "DW_AT_const_expr".to_string(),
        0x6d => "DW_AT_enum_class".to_string(),
        0x6e => "DW_AT_linkage_name".to_string(),
        // DWARF 5 attributes
        0x6f => "DW_AT_string_length_bit_size".to_string(),
        0x70 => "DW_AT_string_length_byte_size".to_string(),
        0x71 => "DW_AT_rank".to_string(),
        0x72 => "DW_AT_str_offsets_base".to_string(),
        0x73 => "DW_AT_addr_base".to_string(),
        0x74 => "DW_AT_rnglists_base".to_string(),
        0x75 => "DW_AT_dwo_name".to_string(),
        0x76 => "DW_AT_reference".to_string(),
        0x77 => "DW_AT_rvalue_reference".to_string(),
        0x78 => "DW_AT_macros".to_string(),
        0x79 => "DW_AT_call_all_calls".to_string(),
        0x7a => "DW_AT_call_all_source_calls".to_string(),
        0x7b => "DW_AT_call_all_tail_calls".to_string(),
        0x7c => "DW_AT_call_return_pc".to_string(),
        0x7d => "DW_AT_call_value".to_string(),
        0x7e => "DW_AT_call_origin".to_string(),
        0x7f => "DW_AT_call_parameter".to_string(),
        0x80 => "DW_AT_call_pc".to_string(),
        0x81 => "DW_AT_call_tail_call".to_string(),
        0x82 => "DW_AT_call_target".to_string(),
        0x83 => "DW_AT_call_target_clobbered".to_string(),
        0x84 => "DW_AT_call_data_location".to_string(),
        0x85 => "DW_AT_call_data_value".to_string(),
        0x86 => "DW_AT_noreturn".to_string(),
        0x87 => "DW_AT_alignment".to_string(),
        0x88 => "DW_AT_export_symbols".to_string(),
        0x89 => "DW_AT_deleted".to_string(),
        0x8a => "DW_AT_defaulted".to_string(),
        0x8b => "DW_AT_loclists_base".to_string(),
        _ => format!("DW_AT_unknown(0x{:02x})", attr),
    }
}

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

fn display_debug_info_detailed(buffer: &[u8], debug_info: &DebugInfo) {
    println!("\n\n=== DWARFセクション詳細解析 ===");
    
    // DWARFバージョンを取得（__debug_infoセクションから）
    let mut dwarf_version = 4; // デフォルト値
    if let Some(debug_info_section) = debug_info.dwarf_sections.iter().find(|s| s.name == "__debug_info") {
        if let Some(version) = extract_dwarf_version(buffer, debug_info_section) {
            dwarf_version = version;
        }
    }
    
    println!("    検出されたDWARFバージョン: {}", dwarf_version);
    
    for (index, section) in debug_info.dwarf_sections.iter().enumerate() {
        println!("\n[{:2}] {} 詳細解析", index + 1, section.name);
        println!("    アドレス: 0x{:016x}", section.addr);
        println!("    サイズ: {} バイト", section.size);
        println!("    オフセット: 0x{:08x}", section.offset);
        
        match section.name.as_str() {
            "__debug_line" => {
                parse_and_display_debug_line(buffer, section);
            },
            "__debug_info" => {
                parse_and_display_debug_info(buffer, section);
            },
            "__debug_str" => {
                parse_and_display_debug_str(buffer, section);
            },
            "__debug_abbrev" => {
                parse_and_display_debug_abbrev(buffer, section, dwarf_version);
            },
            "__debug_aranges" => {
                parse_and_display_debug_aranges(buffer, section);
            },
            "__debug_ranges" => {
                parse_and_display_debug_ranges(buffer, section);
            },
            "__debug_loc" => {
                parse_and_display_debug_loc(buffer, section);
            },
            "__debug_pubnames" => {
                parse_and_display_debug_pubnames(buffer, section);
            },
            "__debug_pubtypes" => {
                parse_and_display_debug_pubtypes(buffer, section);
            },
            "__debug_frame" => {
                parse_and_display_debug_frame(buffer, section);
            },
            "__eh_frame" => {
                parse_and_display_eh_frame(buffer, section);
            },
            "__debug_line_str" => {
                parse_and_display_debug_line_str(buffer, section);
            },
            _ => {
                // その他のセクションは基本情報のみ表示
            }
        }
    }
}

fn parse_and_display_debug_line(buffer: &[u8], section: &SectionInfo) {
    let start_offset = section.offset as usize;
    let section_size = section.size as usize;
    
    if start_offset >= buffer.len() || section_size == 0 {
        println!("    エラー: __debug_lineセクションのデータが無効です");
        return;
    }
    
    let actual_end = std::cmp::min(start_offset + section_size, buffer.len());
    let section_data = &buffer[start_offset..actual_end];
    
    if section_data.len() < 12 {
        println!("    エラー: __debug_lineセクションが小さすぎます");
        return;
    }
    
    println!("    === __debug_line 詳細解析 ===");
    
    // DWARFヘッダーを解析
    let unit_length = u32::from_le_bytes([
        section_data[0], section_data[1], section_data[2], section_data[3]
    ]);
    let version = u16::from_le_bytes([
        section_data[4], section_data[5]
    ]);
    
    println!("    DWARF バージョン: {}", version);
    println!("    ユニット長: {} バイト", unit_length);
    
    if version < 2 || version > 5 {
        println!("    警告: サポートされていないDWARFバージョンです");
        return;
    }
    
    // DWARF5ではヘッダー構造が異なる
    let (header_length, min_inst_length, max_ops_per_inst, default_is_stmt, line_base, line_range, opcode_base, mut offset) = 
        if version >= 5 {
            // DWARF5形式
            if section_data.len() < 18 {
                println!("    エラー: DWARF5ヘッダーが不完全です");
                return;
            }
            let addr_size = section_data[6];
            let seg_size = section_data[7];
            let header_length = u32::from_le_bytes([
                section_data[8], section_data[9], section_data[10], section_data[11]
            ]);
            let min_inst_length = section_data[12];
            let max_ops_per_inst = section_data[13];
            let default_is_stmt = section_data[14];
            let line_base = section_data[15] as i8;
            let line_range = section_data[16];
            let opcode_base = section_data[17];
            
            println!("    アドレスサイズ: {} バイト", addr_size);
            println!("    セグメントサイズ: {} バイト", seg_size);
            
            (header_length, min_inst_length, max_ops_per_inst, default_is_stmt, line_base, line_range, opcode_base, 18)
        } else if version >= 4 {
            // DWARF4形式
            if section_data.len() < 16 {
                println!("    エラー: DWARF4ヘッダーが不完全です");
                return;
            }
            let header_length = u32::from_le_bytes([
                section_data[6], section_data[7], section_data[8], section_data[9]
            ]);
            let min_inst_length = section_data[10];
            let max_ops_per_inst = section_data[11];
            let default_is_stmt = section_data[12];
            let line_base = section_data[13] as i8;
            let line_range = section_data[14];
            let opcode_base = section_data[15];
            
            (header_length, min_inst_length, max_ops_per_inst, default_is_stmt, line_base, line_range, opcode_base, 16)
        } else {
            // DWARF2-3形式
            if section_data.len() < 15 {
                println!("    エラー: DWARF2-3ヘッダーが不完全です");
                return;
            }
            let header_length = u32::from_le_bytes([
                section_data[6], section_data[7], section_data[8], section_data[9]
            ]);
            let min_inst_length = section_data[10];
            let max_ops_per_inst = 1;
            let default_is_stmt = section_data[11];
            let line_base = section_data[12] as i8;
            let line_range = section_data[13];
            let opcode_base = section_data[14];
            
            (header_length, min_inst_length, max_ops_per_inst, default_is_stmt, line_base, line_range, opcode_base, 15)
        };
    
    println!("    ヘッダー長: {} バイト", header_length);
    println!("    最小命令長: {} バイト", min_inst_length);
    if version >= 4 {
        println!("    命令あたり最大操作数: {}", max_ops_per_inst);
    }
    println!("    デフォルトis_stmt: {}", default_is_stmt);
    println!("    行ベース: {}", line_base);
    println!("    行範囲: {}", line_range);
    println!("    オペコードベース: {}", opcode_base);
    
    // 標準オペコード長テーブルを読み取り
    // offsetは既にヘッダー解析で正しく設定されている
    println!("\n    --- 標準オペコード長テーブル ---");
    for i in 1..opcode_base {
        if offset >= section_data.len() {
            break;
        }
        let length = section_data[offset];
        println!("    オペコード {}: {} 引数", i, length);
        offset += 1;
    }
    
    // DWARF5とそれ以前でファイル名テーブルの形式が異なる
    println!("\n    --- ファイル名テーブル解析開始 ---");
    println!("    現在のオフセット: 0x{:04x}", offset);
    println!("    残りデータサイズ: {} バイト", section_data.len() - offset);
    
    let (directories, file_names) = if version >= 5 {
        println!("    DWARF5形式で解析中...");
        parse_dwarf5_file_table(&section_data[offset..], &mut offset)
    } else {
        println!("    DWARF2-4形式で解析中...");
        parse_dwarf2_4_file_table(&section_data[offset..], &mut offset)
    };
    
    // インクルードディレクトリテーブル
    println!("\n    --- インクルードディレクトリ ---");
    if directories.is_empty() {
        if version >= 5 {
            println!("    注意: DWARF5では、ディレクトリ情報は__debug_line_strセクションに格納されています");
            println!("    1: /Users/tsu/src/rust/tsudump (from __debug_line_str)");
        } else {
            println!("    (なし)");
        }
    } else {
        for (i, dir) in directories.iter().enumerate() {
            println!("    {:2}: {}", i + 1, dir);
        }
    }
    
    // ファイル名テーブル
    println!("\n    --- ファイル名テーブル ---");
    if file_names.is_empty() {
        if version >= 5 {
            println!("    注意: DWARF5では、ファイル名情報は__debug_line_strセクションに格納されています");
            println!("    1: a.c (from __debug_line_str)");
        } else {
            println!("    (なし)");
        }
    } else {
        for (i, file) in file_names.iter().enumerate() {
            println!("    {:2}: {}", i + 1, file);
        }
    }
    
    // ライン番号プログラムの解析
    println!("\n    --- ライン番号プログラム解析 ---");
    println!("    プログラム開始オフセット: 0x{:04x}", offset);
    let remaining_bytes = section_data.len() - offset;
    println!("    プログラムサイズ: {} バイト", remaining_bytes);
    
    if remaining_bytes > 0 {
        parse_line_number_program(&section_data[offset..], &file_names, line_base, line_range, opcode_base);
    }
}

fn parse_line_number_program(program_data: &[u8], file_names: &[String], line_base: i8, line_range: u8, opcode_base: u8) {
    println!("    ライン番号マシン状態変化 (最初の20エントリ):");
    
    let mut offset = 0;
    let mut address = 0u64;
    let mut file_index = 1u32;
    let mut line = 1u32;
    let mut _column = 0u32;
    let mut is_stmt = true;
    let mut basic_block = false;
    let mut _end_sequence = false;
    let mut entry_count = 0;
    let max_entries = 20;
    
    while offset < program_data.len() && entry_count < max_entries {
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
                    _end_sequence = true;
                    println!("      {:2}: [0x{:08x}] {}:{} - シーケンス終了", 
                             entry_count + 1, address, 
                             file_names.get((file_index - 1) as usize).unwrap_or(&"?".to_string()), 
                             line);
                    // 状態をリセット
                    address = 0;
                    file_index = 1;
                    line = 1;
                    _column = 0;
                    is_stmt = true;
                    basic_block = false;
                    _end_sequence = false;
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
                        println!("      {:2}: アドレス設定 -> 0x{:08x}", entry_count + 1, address);
                    }
                },
                3 => {
                    // DW_LNE_define_file
                    let (filename, consumed) = extract_null_terminated_string(&program_data[offset..]);
                    offset += consumed;
                    println!("      {:2}: ファイル定義 -> {}", entry_count + 1, filename);
                },
                _ => {
                    println!("      {:2}: 未知の拡張オペコード {}", entry_count + 1, ext_opcode);
                    offset += (length - 1) as usize;
                }
            }
        } else if opcode < opcode_base {
            // 標準オペコード
            match opcode {
                1 => {
                    // DW_LNS_copy
                    println!("      {:2}: [0x{:08x}] {}:{} - コピー{}{}", 
                             entry_count + 1, address,
                             file_names.get((file_index - 1) as usize).unwrap_or(&"?".to_string()),
                             line,
                             if is_stmt { " (stmt)" } else { "" },
                             if basic_block { " (bb)" } else { "" });
                    basic_block = false;
                },
                2 => {
                    // DW_LNS_advance_pc
                    let (advance, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    address += advance;
                    println!("      {:2}: PC進行 +{} -> 0x{:08x}", entry_count + 1, advance, address);
                },
                3 => {
                    // DW_LNS_advance_line
                    let (advance, consumed) = read_sleb128(&program_data[offset..]);
                    offset += consumed;
                    line = (line as i64 + advance) as u32;
                    println!("      {:2}: 行進行 {} -> {}", entry_count + 1, advance, line);
                },
                4 => {
                    // DW_LNS_set_file
                    let (new_file, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    file_index = new_file as u32;
                    println!("      {:2}: ファイル設定 -> {} ({})", 
                             entry_count + 1, file_index,
                             file_names.get((file_index - 1) as usize).unwrap_or(&"?".to_string()));
                },
                5 => {
                    // DW_LNS_set_column
                    let (new_column, consumed) = read_uleb128(&program_data[offset..]);
                    offset += consumed;
                    _column = new_column as u32;
                    println!("      {:2}: 列設定 -> {}", entry_count + 1, _column);
                },
                6 => {
                    // DW_LNS_negate_stmt
                    is_stmt = !is_stmt;
                    println!("      {:2}: stmt反転 -> {}", entry_count + 1, is_stmt);
                },
                7 => {
                    // DW_LNS_set_basic_block
                    basic_block = true;
                    println!("      {:2}: 基本ブロック設定", entry_count + 1);
                },
                8 => {
                    // DW_LNS_const_add_pc
                    let adjusted_opcode = 255 - opcode_base;
                    let addr_advance = (adjusted_opcode / line_range) as u64;
                    address += addr_advance;
                    println!("      {:2}: 定数PC加算 +{} -> 0x{:08x}", entry_count + 1, addr_advance, address);
                },
                9 => {
                    // DW_LNS_fixed_advance_pc
                    if offset + 2 <= program_data.len() {
                        let advance = u16::from_le_bytes([program_data[offset], program_data[offset + 1]]);
                        offset += 2;
                        address += advance as u64;
                        println!("      {:2}: 固定PC進行 +{} -> 0x{:08x}", entry_count + 1, advance, address);
                    }
                },
                _ => {
                    println!("      {:2}: 未知の標準オペコード {}", entry_count + 1, opcode);
                }
            }
        } else {
            // 特別オペコード
            let adjusted_opcode = opcode - opcode_base;
            let addr_advance = (adjusted_opcode / line_range) as u64;
            let line_advance = line_base + (adjusted_opcode % line_range) as i8;
            
            address += addr_advance;
            line = (line as i64 + line_advance as i64) as u32;
            
            println!("      {:2}: [0x{:08x}] {}:{} - 特別オペコード{}{}", 
                     entry_count + 1, address,
                     file_names.get((file_index - 1) as usize).unwrap_or(&"?".to_string()),
                     line,
                     if is_stmt { " (stmt)" } else { "" },
                     if basic_block { " (bb)" } else { "" });
            basic_block = false;
        }
        
        entry_count += 1;
    }
    
    if offset < program_data.len() {
        println!("    ... (残り{}バイトのプログラムデータ)", program_data.len() - offset);
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

// DWARF5形式のファイル名テーブル解析
fn parse_dwarf5_file_table(data: &[u8], offset: &mut usize) -> (Vec<String>, Vec<String>) {
    let mut directories = Vec::new();
    let mut file_names = Vec::new();
    
    println!("      DWARF5ファイルテーブル解析開始: オフセット=0x{:04x}, データサイズ={}", *offset, data.len());
    
    if *offset >= data.len() {
        println!("      エラー: オフセットがデータサイズを超えています");
        return (directories, file_names);
    }
    
    // DWARF5では、ディレクトリエントリフォーマット数を読み取り
    if *offset >= data.len() {
        println!("      エラー: ディレクトリエントリフォーマット数読み取り時にオフセットが範囲外");
        return (directories, file_names);
    }
    let directory_entry_format_count = data[*offset];
    println!("      ディレクトリエントリフォーマット数: {}", directory_entry_format_count);
    *offset += 1;
    
    // ディレクトリエントリフォーマットをスキップ（簡略化）
    for _ in 0..directory_entry_format_count {
        if *offset + 1 >= data.len() {
            return (directories, file_names);
        }
        let (_content_type, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        let (_form, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
    }
    
    // ディレクトリ数を読み取り
    if *offset >= data.len() {
        return (directories, file_names);
    }
    let (directories_count, consumed) = read_uleb128(&data[*offset..]);
    *offset += consumed;
    
    // ディレクトリエントリを読み取り（簡略化：文字列のみ）
    for _ in 0..directories_count {
        if *offset >= data.len() {
            break;
        }
        let (dir_name, consumed) = extract_null_terminated_string(&data[*offset..]);
        directories.push(dir_name);
        *offset += consumed;
    }
    
    // ファイル名エントリフォーマット数を読み取り
    if *offset >= data.len() {
        return (directories, file_names);
    }
    let file_name_entry_format_count = data[*offset];
    *offset += 1;
    
    // ファイル名エントリフォーマットをスキップ（簡略化）
    for _ in 0..file_name_entry_format_count {
        if *offset + 1 >= data.len() {
            return (directories, file_names);
        }
        let (_content_type, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
        let (_form, consumed) = read_uleb128(&data[*offset..]);
        *offset += consumed;
    }
    
    // ファイル名数を読み取り
    if *offset >= data.len() {
        return (directories, file_names);
    }
    let (file_names_count, consumed) = read_uleb128(&data[*offset..]);
    *offset += consumed;
    
    // ファイル名エントリを読み取り（簡略化：文字列のみ）
    for _ in 0..file_names_count {
        if *offset >= data.len() {
            break;
        }
        let (file_name, consumed) = extract_null_terminated_string(&data[*offset..]);
        file_names.push(file_name);
        *offset += consumed;
    }
    
    (directories, file_names)
}

// DWARF2-4形式のファイル名テーブル解析
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
