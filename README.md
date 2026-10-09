# HardeningLegacyWin (Dual-Engine: PS2 + VBScript)

Bộ công cụ đánh giá kiểm toán và thiết lập an toàn thông tin (Hardening & Security Assessment) chuyên biệt cho các hệ điều hành Windows phiên bản cũ (Legacy Windows Systems):
- **Windows 7 SP1** (Client)
- **Windows Server 2008 R2** (Server)
- **Windows Server 2012 R2** (Server)

---

## 1. Kiến Trúc Dual-Engine

Các hệ thống legacy thường bị giới hạn về môi trường runtime (.NET Framework 2.0/3.5, PowerShell 2.0 mặc định, thiếu các cmdlet hiện đại của WMF 5.1). Bộ công cụ áp dụng kiến trúc **Dual-Engine song song**:

1. **PowerShell 2.0 Engine (`src/`) - Primary**:
   - Tương thích 100% với môi trường mặc định của Windows 7 SP1 / Windows Server 2008 R2 / 2012 R2.
   - Tuyệt đối không phụ thuộc vào PowerShell 3.0+ (không dùng `[pscustomobject]`, `[ordered]`, `Get-CimInstance`, `Get-ItemPropertyValue`, `$PSScriptRoot`).
   - Sử dụng .NET 2.0/3.5 BCL, WMI qua `Get-WmiObject`, ADSI và native CLI tools (`secedit.exe`, `auditpol.exe`, `net.exe`).

2. **VBScript Engine - Fallback**:
   - Sử dụng WSH (Windows Script Host) và WMI/WshShell làm kênh dự phòng khi môi trường bị khóa PowerShell Execution Policy hoặc AppLocker chặn `powershell.exe`.

---

## 2. Cấu Trúc Thư Mục Dự Án

```
HardeningNCS/
├── lists/                  # Danh mục luật CIS Benchmark dạng CSV chuẩn
│   ├── finding_list_cis_win7_sp1_machine.csv
│   ├── finding_list_cis_server2008r2_machine.csv
│   └── finding_list_cis_server2012r2_machine.csv
├── src/                    # Mã nguồn Engine
│   ├── common/             # Thư viện hàm dùng chung (PS 2.0 compatible)
│   │   ├── Compare-Value.ps1   # Đánh giá toán tử so sánh (=, !=, >=, <=, contains, =|0)
│   │   ├── Parse-SecEdit.ps1   # Xuất và phân tích cú pháp cấu hình secedit INF
│   │   └── Parse-AuditPol.ps1  # Thu thập và phân tích Advanced Audit Policy (auditpol /r)
│   └── ...
├── tools/                  # Liên kết và tiện ích bổ trợ (AccessChk, Sysinternals)
│   └── accesschk.exe.url
├── outputs/                # Báo cáo đánh giá, backup registry và cấu hình xuất ra
│   └── .gitkeep
└── tests/                  # Bộ kiểm thử đơn vị và thẩm định schema
```

---

## 3. Quy Chuẩn Schema CSV (11 Cột)

Tất cả baseline CSV trong thư mục `lists/` tuân thủ nghiêm ngặt 11 cột:

| STT | Cột | Kiểu | Mô tả |
|:---:|:---|:---|:---|
| 1 | `ID` | String | Mã định danh duy nhất của rule (vd: `CIS-WIN7-1.1.1`) |
| 2 | `Category` | String | Phân nhóm: `Account Policies`, `Security Options`, `Audit Policy`, `System Services`, `Administrative Templates` |
| 3 | `Name` | String | Tên mô tả thiết lập kiểm toán |
| 4 | `Method` | Enum | Cơ chế kiểm tra: `Registry`, `secedit`, `accountpolicy`, `auditpol`, `localaccount`, `service` |
| 5 | `MethodArgument` | String | Tham số cho Method (vd: tên service, tên subcategory audit, tên account, mục secedit) |
| 6 | `RegistryPath` | String | Đường dẫn Registry (dành cho Method `Registry`) |
| 7 | `RegistryItem` | String | Tên Registry Value cần đọc |
| 8 | `DefaultValue` | String | Giá trị mặc định của hệ điều hành xuất xưởng |
| 9 | `RecommendedValue`| String | Giá trị khuyến nghị an toàn theo chuẩn CIS Benchmark |
| 10| `Operator` | Enum | Toán tử so sánh: `=`, `!=`, `>=`, `<=`, `contains`, `=|0` |
| 11| `Severity` | Enum | Mức độ nghiêm trọng: `High`, `Medium`, `Low` |

### Quy ước Method
- `Registry`: Đọc trực tiếp từ Registry hive (`HKLM:\...`).
- `secedit`: Đọc thông qua phân tích cấu hình `secedit /export /areas SECURITYPOLICY`.
- `accountpolicy`: Kiểm tra chính sách tài khoản qua `net accounts` / secedit System Access.
- `auditpol`: Kiểm tra chính sách ghi log nâng cao qua `auditpol.exe /get /category:* /r`.
- `localaccount`: Kiểm tra trạng thái tài khoản cục bộ (Administrator, Guest).
- `service`: Kiểm tra chế độ khởi động dịch vụ hệ thống (`Disabled`, `Manual`, `Auto`).

### Quy ước Operator
- `=`: Giá trị hiện tại khớp chính xác với giá trị khuyến nghị.
- `!=`: Giá trị hiện tại phải khác giá trị khuyến nghị (vd: Rename Administrator).
- `>=`: Giá trị hiện tại lớn hơn hoặc bằng giá trị khuyến nghị (so sánh số nguyên).
- `<=`: Giá trị hiện tại nhỏ hơn hoặc bằng giá trị khuyến nghị (so sánh số nguyên).
- `contains`: Giá trị hiện tại chứa chuỗi khuyến nghị.
- `=|0`: Giá trị hiện tại khớp khuyến nghị HOẶC bằng 0 (chế độ vô hiệu hóa/không giới hạn theo quy ước CIS).

---

## 4. Ràng Buộc Kỹ Thuật (PowerShell 2.0 Compliance)

Để bảo đảm tương thích tuyệt đối trên Windows 7 SP1 và Windows Server 2008 R2:
- Không dùng `$PSScriptRoot`: Sử dụng `Split-Path $MyInvocation.MyCommand.Path -Parent`.
- Không dùng cú pháp Type Accelerator mới: Không dùng `[ordered]`, không dùng `[pscustomobject]`. Thay vào đó dùng `New-Object PSObject -Property @{...}` hoặc `System.Collections.Hashtable`.
- Không gọi cmdlet PS 3.0+: Không dùng `Get-ItemPropertyValue`, `Get-CimInstance`, `Get-FileHash`, `Get-LocalUser`, `Get-NetFirewallRule`.
- Đảm bảo mã hóa an toàn khi đọc file cấu hình secedit (Unicode / UTF-16 LE).
