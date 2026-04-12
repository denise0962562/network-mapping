use std::collections::HashSet;
use std::path::Path;
use std::fs;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use deadpool_postgres::Pool;
use ipnet::IpAdd;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::net::IpAddr;
use serde::{Serialize, Deserialize};
use std::str::FromStr;


fn get_st<'a>(
    record: &'a HashMap<String, String>,
    key: &str
) -> Option<&'a str> {
    record.get(key).map(String::as_str)
}

#[derive(Serialize, Deserialize)]
struct RecordData {
    org_name: Option<String>,                                                          // 组织名称
    organisation: Option<String>,                                                      // 组织唯一标识符
    org_type: Option<String>,                                                          // 组织类型
    org_descr: Option<String>,                                                         // 组织描述信息
    as_name: Option<String>,                                                           // 
    as_number: Option<i32>,
    ip: Option<IpAddr>,
    country: Option<String>,                                                           // 国家
    address: Option<String>,
    last_modified: Option<String>,                                                     // 最后修改时间
    admin_c: Option<HashSet<String>>,                                                  // 管理联系人
    tech_c: Option<HashSet<String>>,                                                   // 技术联系人
    mnt_by: Option<String>,                                                            // 主要维护者
    status: Option<String>,
    notify: Option<String>,
    created: Option<String>,
    changed: Option<String>,
    remarks: Option<String>,
    source: Option<String>
}



/// 对应数据开头键为 organisation
struct OrgData<'a> {
    org_name: Option<&'a str>,                                                          // 组织名称
    organisation: Option<&'a str>,                                                      // 组织唯一标识符
    org_type: Option<&'a str>,                                                          // 组织类型
    org_descr: Option<&'a str>,                                                         // 组织描述信息
    created: Option<&'a str>,
    last_modified: Option<&'a str>,
    address: Option<&'a str>,
    phone: Option<&'a str>,
    email: Option<&'a str>,
    changed: Option<&'a str>,
    abuse_c: Option<&'a str>,
    country: Option<&'a str>,
    source: Option<&'a str>,

}

impl<'a> OrgData<'a> {
    fn new(
        record: &'a HashMap<String, String>
    ) -> Self {
        Self { 
            org_name: get_st(record, "org-name"), 
            organisation: get_st(record, "organisation"),
            org_type: get_st(record, "org-type"), 
            org_descr: get_st(record, "descr"), 
            created: get_st(record, "created"), 
            last_modified: get_st(record, "last-modified"), 
            address: get_st(record, "address"), 
            phone: get_st(record, "phone"),
            email: get_st(record, "e-mail"), 
            abuse_c: get_st(record, "abuse-c"), 
            country: get_st(record, "country"), 
            source: get_st(record, "source"),
            changed: get_st(record, "changed")
        }
    }
}

/// 对应的数据开头应为 route/route6
struct RouteData<'a> {
    ip: Option<String>,
    descr: Option<&'a str>,
    country: Option<&'a str>,
    origin: Option<&'a str>,                                                             // 声明该 IP/CIDR 的 ASN
    mnt_by: Option<&'a str>,
    remarks: Option<&'a str>,
    notify: Option<&'a str>,
    source: Option<&'a str>,
    created: Option<&'a str>,
    last_modified: Option<&'a str>,

}

impl<'a> RouteData<'a> {
    fn new(
        record: &'a HashMap<String, String>
    ) -> Result<Self, Box<dyn std::error::Error>> {

        let tmp_ip = if let Some(ip) = record.get("route") {
            // println!("{}", ip);
            Some(parse_to_ipv4net(ip)?.to_string().trim().to_string())
        }
        else if let Some(ip) = record.get("route6") {
            Some(ip.trim().to_string())
        }
        else {
            None
        };

        Ok(Self { 
            ip: tmp_ip, 
            descr: record.get("descr").map(|t| t.as_str()), 
            country: get_st(record, "country"), 
            origin: get_st(record, "origin"), 
            mnt_by: get_st(record, "mnt-by"), 
            remarks: get_st(record, "remarks"), 
            notify: get_st(record, "notify"),
            source: get_st(record, "source"), 
            created: get_st(record, "created"),
            last_modified: get_st(record, "last-modified") 
        })
    }
}


/// 对应开头键为 inetnum/inet6num
/// 
/// 需要应对
struct InetNum<'a> {
    ip: Option<String>,
    netname: Option<&'a str>,
    descr: Option<&'a str>,
    country: Option<&'a str>,
    admin_c: Option<&'a str>,
    tech_c: Option<&'a str>,
    notify: Option<&'a str>,
    status: Option<&'a str>,
    mnt_by: Option<&'a str>,
    mnt_irt: Option<&'a str>,
    remarks: Option<&'a str>,
    last_modified: Option<&'a str>,
    source: Option<&'a str>
}

impl<'a> InetNum<'a> {
    fn new(
        record: &'a HashMap<String, String>
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tmp_ip = if let Some(ip) = record.get("inetnum") {
            // println!("{}", ip);
            Some(parse_to_ipv4net(ip)?.to_string().trim().to_string())
        }
        else if let Some(ip) = record.get("inet6num") {
            Some(ip.trim().to_string())
        }
        else {
            None
        };

        Ok(Self { 
            ip: tmp_ip, 
            netname: get_st(record, "netname"), 
            descr: get_st(record, "descr"), 
            country: get_st(record, "country"), 
            admin_c: get_st(record, "admin-c"), 
            tech_c: get_st(record, "tech-c"), 
            notify: get_st(record, "notify"), 
            status: get_st(record, "status"), 
            mnt_by: get_st(record, "mnt-by"), 
            mnt_irt: get_st(record, "mnt-irt"), 
            remarks: get_st(record, "remarks"), 
            last_modified: get_st(record, "last-modified"), 
            source: get_st(record, "source") 
        })
    }
}


/// 每个 record 是 HashMap<key, Vec<value>>
fn parse_rir_records(reader: &mut BufReader<File>) -> Result<Option<HashMap<String, String>>, Box<dyn std::error::Error>>
{
    let mut current_record: HashMap<String, String> = HashMap::new();
    let mut last_key: Option<String> = None;  // ← 追踪当前 key
    let mut buf = Vec::new();

    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        
        // ← 关键：n == 0 表示文件结束
        if n == 0 {
            // 返回最后一个 record（如果非空）
            return Ok(if current_record.is_empty() {
                None
            } else {
                Some(current_record)
            });
        }

        // 去掉行尾 \r\n 或 \n
        if buf.ends_with(&[b'\n']) {
            buf.pop();
            if buf.ends_with(&[b'\r']) {
                buf.pop();
            }
        }

        let line = String::from_utf8_lossy(&buf).into_owned();
        let trimmed_line = line.trim_start();

        // 空行或注释：结束当前 record
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            if !current_record.is_empty() {
                return Ok(Some(current_record));  // ← 返回当前 record，下次调用继续读
            }
            last_key = None;
            continue;
        }

        // 续行处理
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(ref key) = last_key {
                let content = line.trim_start();
                current_record.get_mut(key).unwrap().push('\n');
                current_record.get_mut(key).unwrap().push_str(content);
            }
            continue;
        }

        // 跳过非法行
        if !line.chars().next().map_or(false, |c| c.is_ascii_alphabetic()) {
            continue;
        }

        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            if !key.is_empty() {
                let value = line[colon_pos + 1..].trim_start().to_string();
                last_key = Some(key.clone());
                current_record
                    .entry(key)
                    .and_modify(|v| {
                        v.push('\n');
                        v.push_str(&value);
                    })
                    .or_insert(value);
            }
        }
    }
}



pub async fn w_records(
    pool: &Pool,
    path: impl AsRef<Path>
) -> Result<(), Box<dyn std::error::Error>> {
    let mut c = pool.get().await?;

    let stat_organisation = c.prepare_cached(
        "INSERT INTO org (org_name, org_key, org_type, descr, country, address, phone, email, admin_c, last_modified, source) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::timestamptz, $11);"
    ).await?;

    let stat_route = c.prepare_cached(
        "INSERT INTO asn (ip, asnumber, descr, mnt_by, created, last_modified, remarks, source) VALUES ($1::text::inet, $2, $3, $4, $5, $6::text::timestamptz, $7, $8);"
    ).await?;

    // 13 个参数
    let stat_inetnum = c.prepare_cached(
        "INSERT INTO isp (ip, netname, descr, country, admin_c, tech_c, notify, status, mnt_by, mnt_irt, remarks, last_modified, source) VALUES ($1::text::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::text::timestamptz, $13);"
    ).await?;

    println!("打开文件");
    let file = File::open(path)?;
    let mut buf = BufReader::new(file);


    loop {
        if let Some(tmp) = parse_rir_records(&mut buf)? {
            if tmp.contains_key("organisation") {
                let transaction = c.transaction().await?;

                let org_data = OrgData::new(&tmp);

                let _re = transaction.execute(
                    &stat_organisation, 
                    &[
                        &org_data.org_name,
                        &org_data.organisation,
                        &org_data.org_type,
                        &org_data.org_descr,
                        &org_data.country,
                        &org_data.address,
                        &org_data.phone,
                        &org_data.email,
                        &org_data.abuse_c,
                        &org_data.last_modified,
                        &org_data.source
                    ]
                ).await?;

                transaction.commit().await?;
            }
            else if tmp.contains_key("route") || tmp.contains_key("route6") {
                let transaction = c.transaction().await?;

                match RouteData::new(&tmp) {
                    Ok(route_data) => {
                        // if let Some(ip) = &route_data.ip {
                        //     for i in ip.bytes() {
                        //         print!("{i}")
                        //     }
                        //     println!("route {}", ip);
                        // }
                        
                        transaction.execute(
                            &stat_route,
                            &[
                                &route_data.ip,
                                &route_data.origin,
                                &route_data.descr,
                                &route_data.mnt_by,
                                &route_data.created,
                                &route_data.last_modified,
                                &route_data.remarks,
                                &route_data.source
                            ] 
                        ).await?;
                    },
                    Err(e) => {
                        println!("字段错误 {}", e.to_string());
                        continue;
                    }
                }

                transaction.commit().await?;
            }
            else if tmp.contains_key("inetnum") || tmp.contains_key("inet6num") {
                let transaction = c.transaction().await?;

                match InetNum::new(&tmp) {
                    Ok(inet_data) => {
                        // if let Some(ip) = &inet_data.ip {
                        //     for i in ip.bytes() {
                        //         print!("{i}")
                        //     }
                        //     println!("inet: {}", ip);
                        // }
                        
                        transaction.execute(
                            &stat_inetnum,
                            &[
                                &inet_data.ip,
                                &inet_data.netname,
                                &inet_data.descr,
                                &inet_data.country,
                                &inet_data.admin_c,
                                &inet_data.tech_c,
                                &inet_data.notify,
                                &inet_data.status,
                                &inet_data.mnt_by,
                                &inet_data.mnt_irt,
                                &inet_data.remarks,
                                &inet_data.last_modified,
                                &inet_data.source
                            ]
                        ).await?;
                    },
                    Err(e) => {
                        println!("字段错误 {}", e.to_string());
                        continue;
                    }
                }

                transaction.commit().await?;
            }
            else {
                continue;
            }
        }
        else {
            // 返回 NONE 意味没有数据了
            println!("一个文件处理完毕");
            break;
        }

    }

    Ok(())
}

pub async fn read_all(
    pool: &Pool,
    p_set: HashSet<String>
) {
    println!("开始读取文件路径");
    if p_set.is_empty() {
        println!("文件目录为空");
    }
    for i in p_set {
        println!("开始处理 {}", &i);
        match w_records(pool, i).await {
            Ok(_) => {
                println!("文件: 处理完毕");
            },
            Err(e) => {
                println!("{}", e.to_string())
            }
        }
    }
}


// pub async fn read_all(
//     pool: &Pool,
//     p_set: HashSet<String>
// ) {
//     println!("开始读取文件路径");
    
//     let futures: Vec<_> = p_set.into_iter().map(|i| {
//         let pool = pool.clone();
//         async move {
//             println!("开始处理 {}", &i);
//             match w_records(&pool, i).await {
//                 Ok(_) => println!("文件:处理完毕"),
//                 Err(e) => println!("{}", e.to_string())
//             }
//         }
//     }).collect();
    
//     futures::future::join_all(futures).await;
// }

/// 该函数用于根据一个输入路径获取该路径下所有文件路径
pub fn get_all_filename(path: impl AsRef<Path>) -> Result<HashSet<String>, Box<dyn std::error::Error>> {

    let entry = fs::read_dir(path)?;
    
    // let file_set = entry.filter_map(|e| e.ok()).map(|i| file_set.insert(i.path().to_string_lossy().to_string()));

    let file_set: HashSet<String> = entry.filter_map(|e| e.ok()).map(|t| t.path().to_string_lossy().to_string()).collect();

    Ok(file_set)
}


// async fn read_line()

/// 该函数用于通过一个 ip 范围生成相应的cidr，只支持 ipv4
// pub fn parse_to_ipv4net(input: &str) -> Result<Ipv4Net, Box<dyn std::error::Error>> {
//     let s = input.trim();

//     // 含 '-' → 区间格式；否则视为 CIDR
//     if s.contains('-') {
//         Ok(parse_range(s)?)
//     } else {
//         Ok(Ipv4Net::from_str(s)?)
//     }
// }

// /// 解析 `"start - end"` 或 `"start-end"` 格式并转换为 CIDR。
// fn parse_range(s: &str) -> Result<Ipv4Net, Box<dyn std::error::Error>> {
//     // 优先按 " - "（带空格）分割，再按第一个 '-' 分割
//     println!("{}", s);
//     let (start_str, end_str) = if let Some(pos) = s.find(" - ") {
//         (&s[..pos], &s[pos + 3..])
//     } else {

//         if let Some(p) = s.find('-') {
//             (&s[..p], &s[p + 1..])
//         }
//         else {
//             return Err("没有在字段中找到 '-' 字符".into())
//         }

//         // let pos = s.find('-');                                        // 不管了直接 unwarp
//         // (&s[..pos], &s[pos + 1..])
//     };

//     let start_str = start_str.trim();
//     let end_str   = end_str.trim();

//     let start = Ipv4Addr::from_str(start_str)?;
//     let end   = Ipv4Addr::from_str(end_str)?;

//     Ok(range_to_cidr(start, end)?)
// }

// /// 将 `[start, end]` 转换为单个 CIDR 块。
// ///
// /// 算法：对两端地址做 XOR，前导零数即为公共前缀长度，
// /// 再验证构造出的网络地址和广播地址与输入完全一致。
// fn range_to_cidr(start: Ipv4Addr, end: Ipv4Addr) -> Result<Ipv4Net, Box<dyn std::error::Error>> {
//     let start_u32 = u32::from(start);
//     let end_u32   = u32::from(end);

//     if start_u32 > end_u32 {
//         return Err("起始地址 {start} 大于终止地址 {end}".into());
//     }

//     // 单地址 → /32
//     if start_u32 == end_u32 {
//         return Ok(Ipv4Net::new(start, 32)?);
//     }

//     // XOR → 公共前缀位数
//     let prefix_len = (start_u32 ^ end_u32).leading_zeros() as u8;
//     let network    = Ipv4Net::new(start, prefix_len)?;

//     if network.network() != start {
//         let e_m = format!("起始地址 {start} 不是 /{prefix_len} 的网络地址（应为 {}）",network.network());
//         return Err(e_m.into())
//     }
//     if network.broadcast() != end {
//         let e_m = format!("终止地址 {end} 不是 /{prefix_len} 的广播地址（应为 {}）",network.broadcast());
//         return Err(e_m.into())
//     }

//     Ok(network)
// }


pub fn parse_to_ipv4net(input: &str) -> Result<Ipv4Net, Box<dyn std::error::Error>> {
    let s = input.trim();

    // 检查输入长度限制，防止过长的输入造成潜在问题
    if s.len() > 43 {  // IP地址和CIDR格式通常不会超过这个长度 (xxx.xxx.xxx.xxx/xx)
        return Err("输入字符串过长".into());
    }

    // 含 '-' → 区间格式；否则视为 CIDR
    if s.contains('-') {
        Ok(parse_range(s)?)
    } else {
        // 尝试解析CIDR格式，如果失败则尝试自动补全IP地址
        match Ipv4Net::from_str(s) {
            Ok(net) => {
                // 额外验证：确保CIDR不是过于宽泛的范围（如0.0.0.0/0）
                if net.prefix_len() == 0 && net.addr() == Ipv4Addr::new(0, 0, 0, 0) {
                    return Err("不允许使用0.0.0.0/0这样的全局通配符".into());
                }
                Ok(net)
            },
            Err(_) => {
                // 如果CIDR格式解析失败，尝试自动补全IP地址
                let corrected_input = auto_complete_ip(s)?;
                Ok(Ipv4Net::from_str(&corrected_input)?)
            }
        }
    }
}

/// 自动补全不完整的IP地址，如 "24.152.12/22" -> "24.152.12.0/22"
fn auto_complete_ip(input: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(pos) = input.find('/') {
        let ip_part = &input[..pos];
        let cidr_part = &input[pos..]; // includes '/'
        
        let completed_ip = complete_ip_address(ip_part)?;
        Ok(format!("{}{}", completed_ip, cidr_part))
    } else {
        // 没有CIDR部分，只补全IP地址
        complete_ip_address(input)
    }
}

/// 补全IP地址部分，例如 "24.152.12" -> "24.152.12.0"
fn complete_ip_address(ip_str: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = ip_str.split('.').collect();
    
    if parts.len() > 4 {
        return Err("IP地址段数过多".into());
    }
    
    if parts.iter().any(|part| part.is_empty()) {
        return Err("IP地址格式无效，包含空段".into());
    }
    
    // 验证现有部分是否都是有效的数字
    for part in &parts {
        if part.starts_with('0') && part.len() > 1 {
            // 拒绝前导零（除了单独的"0"）
            return Err("IP地址段不应有前导零".into());
        }
        
        part.parse::<u8>()
            .map_err(|_| format!("IP地址段 '{}' 不是有效的数字", part))?;
    }
    
    // 构建完整的IP地址，缺失的部分用0填充
    let mut completed_parts = Vec::new();
    for i in 0..4 {
        if i < parts.len() {
            completed_parts.push(parts[i].to_string());
        } else {
            completed_parts.push("0".to_string());
        }
    }
    
    Ok(completed_parts.join("."))
}

/// 解析 `"start - end"` 或 `"start-end"` 格式并转换为 CIDR。
fn parse_range(s: &str) -> Result<Ipv4Net, Box<dyn std::error::Error>> {
    // 检查输入格式，防止恶意构造的字符串
    if s.matches('-').count() > 1 {
        return Err("区间格式中包含多个'-'字符，格式无效".into());
    }

    // 优先按 " - "（带空格）分割，再按第一个 '-' 分割
    let (start_str, end_str) = if let Some(pos) = s.find(" - ") {
        (&s[..pos], &s[pos + 3..])
    } else {
        if let Some(p) = s.find('-') {
            (&s[..p], &s[p + 1..])
        } else {
            return Err("没有在字段中找到 '-' 字符".into());
        }
    };

    let start_str = start_str.trim();
    let end_str = end_str.trim();

    // 验证IP地址字符串的格式，防止无效输入
    if start_str.is_empty() || end_str.is_empty() {
        return Err("区间格式中的起始或结束地址为空".into());
    }

    // 自动补全IP地址
    let start_completerd = complete_ip_address(start_str)?;
    let end_completed = complete_ip_address(end_str)?;

    let start = Ipv4Addr::from_str(&start_completerd)?;
    let end = Ipv4Addr::from_str(&end_completed)?;

    // 验证区间范围的合理性：起始地址不能大于结束地址
    if u32::from(start) > u32::from(end) {
        return Err("起始IP地址不能大于结束IP地址".into());
    }

    // 额外的安全检查：防止过于宽泛的范围（例如跨越整个IP空间）
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    
    // 检查范围大小，防止过大范围的IP段
    if end_u32 < start_u32 {  // 溢出保护
        return Err("IP地址范围无效，可能发生整数溢出".into());
    }
    
    let range_size = end_u32 - start_u32;
    if range_size > 1 << 24 {  // 限制在最多2^24个地址（约1600万个）以内
        return Err("IP地址范围过大，超出安全限制".into());
    }

    Ok(range_to_cidr(start, end)?)
}

/// 将IP地址范围转换为一个或多个CIDR块
fn range_to_cidr(start: Ipv4Addr, end: Ipv4Addr) -> Result<Ipv4Net, Box<dyn std::error::Error>> {
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);

    // 找到能覆盖整个范围的最小CIDR块
    let mut current = start_u32;
    let mut networks = Vec::new();

    while current <= end_u32 {
        // 计算从current开始的最大可能的CIDR块
        let mut prefix_len = 32;
        let mut block_size = 1u32;

        loop {
            // 计算当前块的结束地址
            let block_end = current + block_size - 1;
            
            // 检查块是否超出范围或与目标范围不兼容
            if block_end > end_u32 {
                break;
            }

            // 检查当前块是否在当前地址的CIDR边界上
            if current & (block_size - 1) != 0 {
                break;
            }

            // 更新到更大的块
            prefix_len -= 1;
            block_size <<= 1;

            if prefix_len == 0 {
                break;
            }
        }

        // 创建CIDR块
        let network_addr = Ipv4Addr::from(current);
        let network = Ipv4Net::new(network_addr, prefix_len)?;
        networks.push(network);

        // 移动到下一个未覆盖的地址
        current += 1u32 << (32 - prefix_len);
    }

    // 返回第一个网络块作为代表（如果只需要单个CIDR块的话）
    if let Some(first_network) = networks.first() {
        Ok(*first_network)
    } else {
        // 这种情况理论上不应该发生
        Err("无法创建有效的CIDR块".into())
    }
}

