<p align="center">
  <img src="assets/NCS_Icon_Shield.png" width="130" alt="NCS Security Shield"><br>
  <b>VIETNAM NATIONAL CYBER SECURITY TECHNOLOGY JSC</b><br>
  <h1>HardeningNCS</h1>
  <p><b>Bộ công cụ kiểm toán & thiết lập an toàn thông tin chuyên biệt cho Windows Legacy</b></p>
  <p>
    <img src="https://img.shields.io/badge/Platform-Windows%207%20%7C%202008%20R2%20%7C%202012%20R2-blue" alt="Platform">
    <img src="https://img.shields.io/badge/Engine-PowerShell%202.0%2B%20%7C%20VBScript-green" alt="Engine">
    <img src="https://img.shields.io/badge/Benchmark-CIS%20v3.3.1-orange" alt="CIS Benchmark">
    <img src="https://img.shields.io/badge/License-MIT-purple" alt="License">
    <img src="https://img.shields.io/badge/Security-4--Layer%20Atomic%20Backup-red" alt="Backup Security">
  </p>
</p>

---

## 📖 Giới Thiệu Tổng Quan

**HardeningNCS** là bộ giải pháp an toàn thông tin mã nguồn mở do **NCS (Công ty Cổ phần Công nghệ An ninh mạng Quốc gia Việt Nam)** phát triển. Công cụ tập trung giải quyết bài toán kiểm toán (Audit), đánh giá tuân thủ (Compliance Assessment) và thiết lập cấu hình an toàn (Hardening / Remediation) chuẩn hóa theo **CIS Benchmark** trên các hệ điều hành Windows thế hệ cũ (Legacy Windows):
- **Windows 7 SP1** (Máy trạm Client)
- **Windows Server 2008 R2** (Máy chủ Server)
- **Windows Server 2012 / 2012 R2** (Máy chủ Server)

### 💡 Tại sao cần HardeningNCS?
Các công cụ hardening hiện đại (như *HardeningKitty*) yêu cầu **PowerShell 5.1**, **.NET 4.5+**, hoặc các module chỉ có từ Windows 10/Server 2016 trở lên. Khi chạy trên các máy chủ Windows EOL đời cũ:
1. Thiếu các cmdlet hiện đại (`Get-ItemPropertyValue`, `Get-CimInstance`, `Get-LocalUser`) gây **crash ngay khi khởi động**.
2. Một số máy chủ cũ bị khóa cứng PowerShell Execution Policy (`Restricted`) hoặc không được cài thêm WMF 5.1.
3. Chế độ can thiệp tự động (Remediation) thiếu cơ chế sao lưu độc quyền và không thể xóa các Registry Key mới tạo khi cần Rollback.

**HardeningNCS** được thiết kế từ gốc để vượt qua toàn bộ các rào cản trên bằng kiến trúc **Dual-Engine** song song.

---

## 🏛️ Kiến Trúc Kỹ Thuật (Dual-Engine)

```
                       ┌────────────────────────────────────────┐
                       │   Finding List (CSV 11 cột / 21 cột)   │
                       └───────────────────┬────────────────────┘
                                           │
                    ┌──────────────────────┴──────────────────────┐
                    ▼                                             ▼
       ┌─────────────────────────┐                   ┌─────────────────────────┐
       │   PowerShell 2.0        │                   │   VBScript Engine       │
       │   (Primary Engine)      │                   │   (Zero-Dependency)     │
       ├─────────────────────────┤                   ├─────────────────────────┤
       │ • .NET 2.0/3.5 BCL      │                   │ • Chạy qua cscript.exe  │
       │ • 0 cú pháp PS 3.0+     │                   │ • RFC 4180 CSV Parser   │
       │ • SecEdit / AuditPol /  │                   │ • WScript.Shell + WMI   │
       │   WMI Win32_UserAccount │                   │ • Không cần PowerShell  │
       └────────────┬────────────┘                   └────────────┬────────────┘
                    │                                             │
                    └──────────────────────┬──────────────────────┘
                                           ▼
                       ┌────────────────────────────────────────┐
                       │     Báo Cáo Kiểm Toán (outputs/*.csv)  │
                       │     Passed / Failed / Skipped          │
                       └───────────────────┬────────────────────┘
                                           │
                                           ▼
                       ┌────────────────────────────────────────┐
                       │   Remediate-LegacyWin.ps1              │
                       │   • 4-Layer Atomic Backup              │
                       │   • Per-Session Directory Isolation    │
                       │   • Selective Fix (Failed only)        │
                       └───────────────────┬────────────────────┘
                                           │ (Khi cần hoàn tác)
                                           ▼
                       ┌────────────────────────────────────────┐
                       │   Rollback-LegacyWin.ps1               │
                       │   1-Click Rollback (Khôi phục 100%)    │
                       └────────────────────────────────────────┘
```

1. **PowerShell 2.0 Engine (`src/Audit-LegacyWin.ps1`)**:
   - Tương thích 100% với PowerShell 2.0 mặc định của Windows 7 SP1 và Windows Server 2008 R2.
   - Tuyệt đối không dùng syntax PS 3.0+ (không `[pscustomobject]`, `[ordered]`, `$PSScriptRoot`, `Get-CimInstance`).
   - Xử lý mượt mà các file checklist CIS 21 cột gốc (324+ rules).
2. **VBScript Engine (`src/Audit-LegacyWin.vbs`)**:
   - Zero-dependency: Chạy trực tiếp qua `cscript.exe //nologo` có sẵn trên mọi bản Windows từ Windows 2000 đến nay.
   - Tích hợp bộ parser **RFC 4180 State Machine** xử lý an toàn dấu phẩy trong ngoặc kép.
   - Tự động lập bảng ánh xạ cột động (**Dynamic Header-to-Index Mapping**), không phụ thuộc vào thứ tự cột.

---

## 📁 Cấu Trúc Thư Mục Dự Án

```text
HardeningNCS/
├── assets/                                                # Bộ nhận diện thương hiệu NCS
│   ├── NCS_Icon_Shield.png                                # Biểu tượng khiên bảo mật NCS
│   ├── NCS_Icon_Shield.svg                                # Vector khiên bảo mật NCS
│   ├── NCS_Icon_Shield.ico                                # Icon định dạng Windows ICO
│   ├── NCS_Logo_Trang.svg                                 # Logo NCS phiên bản nền tối
│   ├── NCS_Logo_Den.svg                                   # Logo NCS phiên bản nền sáng
│   └── ascii-art.txt                                      # Banner ASCII Art NCS từ SVG
├── lists/                                                 # Danh mục kiểm toán CIS Benchmark dạng CSV
│   ├── CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv# Baseline 21 cột gốc (324 rules)
│   ├── finding_list_cis_server2008r2_machine.csv          # Baseline 11 cột cốt lõi cho Server 2008 R2
│   ├── finding_list_cis_win7_sp1_machine.csv              # Baseline 11 cột cốt lõi cho Windows 7 SP1
│   └── finding_list_cis_server2012r2_machine.csv          # Baseline 11 cột cốt lõi cho Server 2012 R2
├── src/                                                   # Mã nguồn các Engine thực thi
│   ├── Audit-LegacyWin.ps1                                # Engine Audit PowerShell 2.0 thuần
│   ├── Audit-LegacyWin.vbs                                # Engine Audit VBScript Zero-Dependency
│   ├── Remediate-LegacyWin.ps1                            # Engine Fix có kiểm soát & 4-Layer Backup
│   ├── Rollback-LegacyWin.ps1                             # Engine Hoàn tác 1-Click phục hồi 100%
│   └── common/                                            # Thư viện hàm phụ trợ (PS2 compatible)
│       ├── Compare-Value.ps1                              # Bộ so sánh toán tử (=, !=, >=, <=, <=!0, regex)
│       ├── Parse-SecEdit.ps1                              # Xuất & phân tích cấu hình secedit INF
│       └── Parse-AuditPol.ps1                             # Thu thập & phân tích Advanced Audit Policy
├── tests/                                                 # Hệ thống kiểm thử tự động hóa (8 suites)
│   ├── Test-PS2Compat.ps1                                 # Static AST Linter: cấm cú pháp PS 3.0+
│   ├── Test-Audit-Smoke.ps1                               # Smoke test kiểm chứng schema báo cáo
│   ├── Test-Rollback.ps1                                  # Integration Test: E2E Fix -> Rollback
│   ├── test_common_helpers.ps1                            # 68 unit tests kiểm định bộ so sánh & parser
│   ├── test_csv_schema.ps1                                # Kiểm định tính toàn vẹn của các file CSV
│   ├── test_audit_engine.ps1                              # 36 tests kiểm định dispatch engine
│   ├── test_remediate_rollback.ps1                        # 44 tests kiểm định an toàn backup & lockfile
│   └── test_vbs_audit.ps1                                 # 17 tests kiểm thử VBScript Engine
├── outputs/                                               # Thư mục lưu báo cáo audit và backup session
└── tools/
    └── accesschk.exe.url                                  # Shortcut Sysinternals AccessChk chính thức
```

---

## 🚀 Hướng Dẫn Cài Đặt & Triển Khai

### 1. Tải về máy quản trị
```bash
git clone https://github.com/Agents-Coding-Space/HardeningNCS.git
cd HardeningNCS
```

### 2. Triển khai lên máy đích (Windows 7 / Server 2008 R2 / 2012 R2)
* **Môi trường kết nối mạng (SSH / SCP):**
  ```bash
  scp -r src lists outputs tests vagrant@<IP_TARGET>:C:/HardeningNCS/
  ```
* **Môi trường cô lập (Air-Gapped / Offline):**
  Copy toàn bộ thư mục `HardeningNCS` vào USB và dán vào thư mục bất kỳ trên máy đích (ví dụ: `C:\HardeningNCS`).

> **Yêu cầu quyền hạn:** Mở **Command Prompt** hoặc **PowerShell** với quyền **Run as Administrator** để có đủ đặc quyền kiểm toán bảo mật (`SeSecurityPrivilege`) cho `secedit.exe` và `auditpol.exe`.

---

## 💻 Hướng Dẫn Sử Dụng Chi Tiết

### BƯỚC 1: Khảo Sát & Kiểm Toán (Audit)

#### Cách 1 — Chạy bằng PowerShell 2.0 (Khuyến nghị)
Sử dụng file baseline 21 cột gốc chuẩn của CIS Benchmark:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\src\Audit-LegacyWin.ps1 `
  -FindingList .\lists\CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv `
  -OutputDir .\outputs
```
*(Hoặc dùng file rút gọn cho từng hệ điều hành: `.\lists\finding_list_cis_server2008r2_machine.csv`)*.

#### Cách 2 — Chạy bằng VBScript (Zero-Dependency)
Dành cho máy bị chặn PowerShell hoặc cấm script `.ps1`:
```cmd
cscript.exe //nologo .\src\Audit-LegacyWin.vbs .\lists\CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv .\outputs
```

> **Kết quả đầu ra:** File báo cáo được lưu tại `outputs\audit_report_<timestamp>.csv` chứa 13 cột chi tiết:
> `ID, Category, Name, Method, MethodArgument, RegistryPath, RegistryItem, DefaultValue, RecommendedValue, Operator, Severity, CurrentValue, Status`.

---

### BƯỚC 2: Mô Phỏng Thiết Lập (Simulation / What-If)
**Nguyên tắc vàng:** Luôn chạy chế độ mô phỏng trước để biết trước công cụ sẽ thay đổi những gì, **cam kết 100% không chạm vào hệ thống**:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\src\Remediate-LegacyWin.ps1 `
  -AuditReport .\outputs\audit_report_20261009_011408.csv `
  -FindingList .\lists\CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv `
  -WhatIf
```

---

### BƯỚC 3: Khắc Phục Chọn Lọc (Selective Remediation)
Khi đã sẵn sàng, chạy lệnh sửa thật. Công cụ sẽ:
1. **Chỉ tác động lên các mục có `Status = Failed`**.
2. **Kích hoạt cơ chế Sao lưu 4 lớp (4-Layer Atomic Backup)** trước khi ghi bất kỳ giá trị nào.
3. Tạo thư mục phiên cô lập `outputs\backup_session_yyyyMMdd_HHmmss_<PID>_<RND>` được khóa bằng **Win32 Exclusive Lockfile**.
4. Áp dụng giá trị an toàn chuẩn hóa.
5. Nếu có bất kỳ lỗi sao lưu nào $\rightarrow$ **Dừng ngay lập tức (Abort Gate)** và tự động dọn sạch rác, không thay đổi hệ thống.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\src\Remediate-LegacyWin.ps1 `
  -AuditReport .\outputs\audit_report_20261009_011408.csv `
  -FindingList .\lists\CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv
```

---

### BƯỚC 4: Phục Hồi 1-Click Khi Có Sự Cố (Rollback)
Nếu phần mềm nghiệp vụ trên máy chủ cũ phát sinh lỗi sau khi hardening, sử dụng đường dẫn file `backup_manifest.txt` được in ở cuối Bước 3 để hoàn tác:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\src\Rollback-LegacyWin.ps1 `
  -ManifestFile .\outputs\backup_session_20261009_011952_1856_6325\backup_manifest.txt
```

**Cơ chế hoàn tác thông minh của HardeningNCS:**
- Khôi phục các giá trị Registry cũ qua file `.reg`.
- **Tự động xóa sạch các Registry Key và Value mới tạo** qua file `registry_undo_delete.reg`.
- Nạp lại Local Security Policy cũ bằng `secedit.exe /configure`.
- Nạp lại Audit Policy cũ bằng `auditpol.exe /restore`.
- Khôi phục trạng thái khởi động của các dịch vụ Windows Services.
- **Cam kết đưa hệ thống về đúng 100% hiện trạng ban đầu**.

---

## 📊 Quy Chuẩn Hợp Đồng Dữ Liệu (CSV Contract)

Bộ công cụ hỗ trợ song song 2 định dạng schema:

### 1. Schema 21 Cột Gốc (CIS Benchmark / HardeningKitty)
Được giữ **nguyên vẹn 100%** không thay đổi cấu trúc:
```text
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,RegistryPathIntune,RegistryPathDCP,RegistryItemIntune,ClassName,Namespace,Property,DefaultValue,DefaultValueIntune,RecommendedValue,RecommendedValueIntune,Operator,OperatorIntune,Severity,Filter
```

### 2. Schema 11 Cột Thu Gọn (Machine Specific)
Dành cho danh mục rút gọn theo máy trạm/máy chủ:
```text
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity
```

### 3. Bảng Phương Thức Kiểm Toán (Method Adapters)

| Method | Mô tả kiểm toán | Nguồn thu thập dữ liệu | Khả năng Remediate |
| :--- | :--- | :--- | :---: |
| `Registry` | Đọc khóa Registry hệ thống | Registry Provider / WMI StdRegProv | ✅ Có hỗ trợ |
| `service` | Kiểm tra chế độ khởi động Service | WMI `Win32_Service` (`StartMode`) | ✅ Có hỗ trợ |
| `secedit` | Chính sách bảo mật cục bộ | `secedit.exe /export` (`SECURITYPOLICY`) | ✅ Có hỗ trợ |
| `accountpolicy`| Chính sách mật khẩu & lockout | `secedit` / fallback `net accounts` | ✅ Có hỗ trợ |
| `auditpol` | Nhật ký nâng cao Advanced Audit | `auditpol.exe /get /category:* /r` | ✅ Có hỗ trợ |
| `localaccount` | Trạng thái tài khoản SID 500/501 | WMI `Win32_UserAccount` (`Disabled`, `Name`) | ⚠️ Audit only |
| `accesschk` | Phân quyền User Rights Assignment | `secedit [Privilege Rights]` (Dịch SID) | ⚠️ Audit only (Guardrail) |
| `command` | Kiểm tra phần mềm bảo mật (EMET)| Registry Uninstall Key (An toàn) | ⚠️ Audit only |

---

## 🧪 Hệ Thống Kiểm Định Tự Động (QA & Testing)

Dự án tích hợp sẵn **8 bộ test suite** tự động hóa kiểm định tính an toàn và tương thích:

```powershell
# 1. Kiểm tra 100% cú pháp thuần PowerShell 2.0 (Cấm PS 3.0+):
powershell -ExecutionPolicy Bypass -File .\tests\Test-PS2Compat.ps1

# 2. Kiểm thử 68 unit tests cho toán tử và parser:
powershell -ExecutionPolicy Bypass -File .\tests\test_common_helpers.ps1

# 3. Kiểm định schema CSV 11 cột và 21 cột gốc:
powershell -ExecutionPolicy Bypass -File .\tests\test_csv_schema.ps1

# 4. Kiểm thử 36 kịch bản dispatch của Audit Engine:
powershell -ExecutionPolicy Bypass -File .\tests\test_audit_engine.ps1

# 5. Kiểm thử 17 kịch bản cho VBScript Engine:
powershell -ExecutionPolicy Bypass -File .\tests\test_vbs_audit.ps1

# 6. Kiểm thử 44 kịch bản an toàn Backup 4 lớp, Lockfile và Rollback:
powershell -ExecutionPolicy Bypass -File .\tests\test_remediate_rollback.ps1

# 7. Smoke test kiểm toán toàn diện:
powershell -ExecutionPolicy Bypass -File .\tests\Test-Audit-Smoke.ps1

# 8. Integration test E2E thực tế trên Registry:
powershell -ExecutionPolicy Bypass -File .\tests\Test-Rollback.ps1
```

---

## 🛡️ Ràng Buộc An Toàn (Safety Guardrails)

- **Anti-Hang Protection**: Không sử dụng vòng lặp vô hạn; các lệnh gọi `secedit.exe` và `auditpol.exe` đều có cờ im lặng `/quiet` và bắt ngoại lệ chặt chẽ.
- **Chống False-Pass cho `accesschk`**: Khi không đủ quyền thu thập `[Privilege Rights]`, công cụ đánh dấu rõ `Skipped`, tuyệt đối không so sánh rỗng bằng rỗng để báo `Passed` sai sự thật.
- **Cô Lập Thư Mục Phiên**: Toàn bộ backup được lưu trong `backup_session_*` riêng biệt và khóa bằng `FileMode.CreateNew` ở cấp OS Kernel, ngăn ngừa việc hai phiên chạy đồng thời xóa nhầm file của nhau.
- **Chống Path Traversal**: Tên thư mục sao lưu được kiểm tra nghiêm ngặt, chặn các ký tự `\`, `/`, `:`, `..` để không ghi đè ra ngoài thư mục `outputs/`.

---

## 📄 Bản Quyền & Giấy Phép (License)

Dự án được phát hành theo giấy phép **[MIT License](LICENSE)**.

**Phát triển bởi:**  
🏢 **Công ty Cổ phần Công nghệ An ninh mạng Quốc gia Việt Nam (NCS)**  
🌐 Website: [https://ncsgroup.vn](https://ncsgroup.vn)  
📦 GitHub: [https://github.com/Agents-Coding-Space/HardeningNCS](https://github.com/Agents-Coding-Space/HardeningNCS)
