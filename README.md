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

## 3. Quy Chuẩn Schema CSV & Hợp Đồng Dữ Liệu

Bộ công cụ hỗ trợ **song song cả 2 định dạng schema** (file gốc 21 cột của CIS Benchmark / HardeningKitty và file thu gọn 11 cột cho từng dòng máy legacy):

### 3.1. Schema Hợp Đồng Gốc 21 Cột (CIS / HardeningKitty)

Áp dụng cho các baseline gốc chuẩn quốc tế, tiêu biểu là `lists/CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv` (được bảo toàn **nguyên vẹn 100%**, tuyệt đối không cắt bớt cột, không chuyển đổi hay chỉnh sửa dữ liệu gốc):

`ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,RegistryPathIntune,RegistryPathDCP,RegistryItemIntune,ClassName,Namespace,Property,DefaultValue,DefaultValueIntune,RecommendedValue,RecommendedValueIntune,Operator,OperatorIntune,Severity,Filter`

| STT | Cột | Kiểu | Mô tả |
|:---:|:---|:---|:---|
| 1 | `ID` | String | Mã định danh CIS rule (vd: `1.1.1`, `2.3.7.1`) |
| 2 | `Category` | String | Phân nhóm kiểm toán (vd: `Account Policies`, `Security Options`) |
| 3 | `Name` | String | Tên mô tả thiết lập kiểm toán |
| 4 | `Method` | Enum | Cơ chế kiểm tra: `Registry`, `accountpolicy`, `auditpol`, `secedit`, `localaccount`, `service`, `accesschk` |
| 5 | `MethodArgument` | String | Tham số cho Method (vd: tên service, tên audit subcategory, tên account) |
| 6 | `RegistryPath` | String | Đường dẫn Registry (hỗ trợ cả `HKLM:\...`, `HKCU:\...`, `HKLM\...`, `HKCU\...`) |
| 7 | `RegistryItem` | String | Tên Registry Value cần đọc |
| 8 | `RegistryPathIntune` | String | Đường dẫn Registry trên thiết bị quản lý qua Intune |
| 9 | `RegistryPathDCP` | String | Đường dẫn Registry trên thiết bị Domain Controller Policy |
| 10| `RegistryItemIntune` | String | Tên Registry Item quản lý qua Intune |
| 11| `ClassName` | String | Tên lớp WMI (dành cho cơ chế WMI query) |
| 12| `Namespace` | String | WMI Namespace (vd: `root\cimv2`, `root\rsop\computer`) |
| 13| `Property` | String | Thuộc tính WMI cần truy vấn |
| 14| `DefaultValue` | String | Giá trị mặc định của hệ điều hành xuất xưởng |
| 15| `DefaultValueIntune` | String | Giá trị mặc định theo mẫu Intune |
| 16| `RecommendedValue` | String | Giá trị khuyến nghị an toàn theo CIS Benchmark (hỗ trợ biểu thức regex) |
| 17| `RecommendedValueIntune`| String | Giá trị khuyến nghị Intune |
| 18| `Operator` | Enum | Toán tử so sánh: `=`, `!=`, `>=`, `<=`, `<=!0`, `contains`, `=|0` |
| 19| `OperatorIntune` | Enum | Toán tử so sánh dành cho Intune |
| 20| `Severity` | Enum | Mức độ nghiêm trọng: `High`, `Medium`, `Low` |
| 21| `Filter` | String | Bộ lọc áp dụng rule (vd: `L1`, `L1 - MS`, `L2`) |

### 3.2. Schema Thu Gọn 11 Cột (Machine Baseline)

Áp dụng cho các file danh mục rút gọn theo đối tượng máy mục tiêu (`finding_list_cis_*.csv`):

`ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity`

| STT | Cột | Kiểu | Mô tả |
|:---:|:---|:---|:---|
| 1 | `ID` | String | Mã định danh duy nhất của rule (vd: `CIS-WIN7-1.1.1`) |
| 2 | `Category` | String | Phân nhóm: `Account Policies`, `Security Options`, `Audit Policy`, `System Services`, `Administrative Templates` |
| 3 | `Name` | String | Tên mô tả thiết lập kiểm toán |
| 4 | `Method` | Enum | Cơ chế kiểm tra: `Registry`, `secedit`, `accountpolicy`, `auditpol`, `localaccount`, `service` |
| 5 | `MethodArgument` | String | Tham số cho Method (vd: tên service, tên subcategory audit, tên account, mục secedit) |
| 6 | `RegistryPath` | String | Đường dẫn Registry (`HKLM\...`, `HKCU\...`, `HKLM:\...`) |
| 7 | `RegistryItem` | String | Tên Registry Value cần đọc |
| 8 | `DefaultValue` | String | Giá trị mặc định của hệ điều hành xuất xưởng |
| 9 | `RecommendedValue`| String | Giá trị khuyến nghị an toàn theo chuẩn CIS Benchmark |
| 10| `Operator` | Enum | Toán tử so sánh (mặc định `=` nếu để trống) |
| 11| `Severity` | Enum | Mức độ nghiêm trọng: `High`, `Medium`, `Low` |

### 3.3. Khả Năng Tương Thích Động Của Dual-Engine (PS2 & VBScript)

Cả hai bộ kiểm toán **PowerShell 2.0 (`Audit-LegacyWin.ps1`)** và **VBScript (`Audit-LegacyWin.vbs`)** đều hỗ trợ tự động nhận diện và xử lý linh hoạt:
- **Xử lý BOM UTF-8**: Tự động loại bỏ ký tự UTF-8 BOM (`EF BB BF` / `U+FEFF`), trích xuất an toàn thuộc tính ID kể cả khi trường bị gán tên `"`ufeffID"`.
- **Dynamic Header-to-Index Mapping**: Trong VBScript, engine đọc dòng header và xây dựng bảng ánh xạ cột động theo tên trường (không phụ thuộc vào số lượng cột hay thứ tự cột). Nhờ đó chạy mượt mà trên cả file 11 cột lẫn 21 cột.
- **Strict Path Guard**: Kiểm tra chặt chẽ `RegistryPath` rỗng/null trước khi gọi kiểm tra registry, tránh lỗi binding tham số.

### 3.4. Quy ước Operator Mở Rộng
- `=`: Giá trị hiện tại khớp chính xác với giá trị khuyến nghị (số hoặc chuỗi). Khi so sánh chuỗi thông thường không khớp mà `RecommendedValue` chứa ký tự regex đặc biệt (như `[`, `\s`, `[rR]2`, `(..|..)`, `.*`), engine tự động kích hoạt đối soát biểu thức chính quy (**Regex matching** qua `-match` trong PowerShell hoặc `VBScript.RegExp` trong VBScript). Mặc định gán `=` nếu cột Operator để trống hoặc null.
- `!=`: Giá trị hiện tại phải khác giá trị khuyến nghị (vd: Rename Administrator).
- `>=`: Giá trị hiện tại lớn hơn hoặc bằng giá trị khuyến nghị (so sánh số nguyên).
- `<=`: Giá trị hiện tại nhỏ hơn hoặc bằng giá trị khuyến nghị (so sánh số nguyên).
- `<=!0`: Giá trị hiện tại nhỏ hơn hoặc bằng giá trị khuyến nghị **VÀ phải khác 0** (khác '0'). Phù hợp cho các chính sách thời hạn mật khẩu (Maximum Password Age) trong CIS.
- `contains`: Giá trị hiện tại chứa chuỗi khuyến nghị (hoặc danh sách mảng chứa phần tử).
- `=|0`: Giá trị hiện tại khớp khuyến nghị HOẶC bằng 0 (chế độ vô hiệu hóa/không giới hạn theo quy ước CIS).

### 3.5. Cơ Chế Xử Lý Phương Thức Kiểm Toán (Method Adapters)

Cả PowerShell 2.0 Engine và VBScript Engine đều hỗ trợ toàn diện 8 phương thức kiểm toán chuẩn CIS:
1. **`Registry`**: Đọc trực tiếp cấu hình qua Registry Provider / WMI StdRegProv (hỗ trợ cả DWORD, String, MultiString, ExpandString).
2. **`service`**: Kiểm tra trạng thái khởi động của Windows Services qua WMI `Win32_Service` (`StartMode`).
3. **`secedit`**: Phân tích chính sách bảo mật cục bộ được xuất tự động từ `secedit.exe` (vùng `SECURITYPOLICY` và `USER_RIGHTS`).
4. **`accountpolicy`**: Bảng ánh xạ 2 chiều các tham số tài khoản chuẩn CIS (`ENFORCE_PASSWORD_HISTORY`, `MAXIMUM_PASSWORD_AGE`, `MINIMUM_PASSWORD_AGE`, `MINIMUM_PASSWORD_LENGTH`, `COMPLEXITY_REQUIREMENTS`, `REVERSIBLE_ENCRYPTION`, `LOCKOUT_DURATION`, `LOCKOUT_THRESHOLD`, `LOCKOUT_RESET`, `FORCE_LOGOFF`) sang các mục secedit INF tương ứng, có cơ chế fallback sang lệnh native `net accounts` khi thiếu quyền elevated.
5. **`auditpol`**: Phân tích Advanced Audit Policy qua `auditpol.exe /get /category:* /r` (hỗ trợ cả Subcategory Name và Subcategory GUID).
6. **`localaccount`**: Nhận diện tài khoản người dùng cục bộ qua SID suffix (`500` cho Administrator, `501` cho Guest) hoặc Username thông qua WMI `Win32_UserAccount`, kiểm tra chính xác cả thuộc tính trạng thái (Disabled/Enabled) và cấu hình đổi tên tài khoản.
7. **`accesschk`**: Đánh giá phân quyền người dùng (Privilege Rights / User Rights Assignment) qua `secedit [Privilege Rights]`. Nếu quyền không được cấu hình, giá trị hiện tại được xác định là `""` (No One). Khi giá trị khuyến nghị rỗng `""` và current rỗng `""` -> kết luận `Passed`. Hỗ trợ chuyển đổi SID chuẩn (`*S-1-5-...`) sang tên tài khoản NTAccount (`BUILTIN\Administrators;...`).
8. **`command`**: Đối với rule kiểm tra phần mềm EMET (ID `18.9.25.1`), kiểm tra an toàn qua Registry `HKLM:\SOFTWARE\Microsoft\EMET` và khóa Uninstall, tuyệt đối không chạy chuỗi lệnh shell tùy ý.
9. **Unknown Method Safety Guardrail**: Mọi method chưa được nhận diện được đánh dấu `Skipped` kèm cảnh báo, tuyệt đối không bao giờ báo nhầm `Passed`.

---

## 4. Remediation Engine & Cơ Chế Guardrails Bảo Vệ

Công cụ khắc phục (`Remediate-LegacyWin.ps1`) tuân thủ nghiêm ngặt các nguyên tắc an toàn công nghiệp:
- **Hỗ Trợ Đọc Báo Cáo 21 Cột**: Tự động phân tích báo cáo kiểm toán sinh ra từ cả file 11 cột và file 21 cột gốc của CIS Benchmark.
- **Whitelist Phương Thức Cho Phép Khắc Phục**: Chỉ thực hiện remediate các method đã có cơ chế sao lưu và phục hồi hoàn chỉnh (`Registry`, `service`, `accountpolicy`, `auditpol`, `secedit`).
- **Remediation Guardrail**: Đối với các method chưa có cơ chế rollback an toàn tự động (như `accesschk`, `command`, `localaccount`), engine ghi nhận cảnh báo rõ ràng và đánh dấu bỏ qua (`Skipped`), tuyệt đối không ghi đè mù quáng gây mất ổn định hệ thống.
- **Cơ Chế 4-Layer Backup**: 100% bắt buộc sao lưu 4 lớp trước khi chỉnh sửa (Registry Export `.reg`, SecEdit Policy INF, AuditPol CSV, State Snapshot CSV).
- **Per-Session Directory Isolation & Atomic Lockfile**: Mỗi phiên remediate sở hữu một thư mục sao lưu độc lập với định dạng chống va chạm `backup_session_yyyyMMdd_HHmmss_<PID>_<RND>`, được bảo vệ bởi Win32 CreateNew Exclusive Lockfile.

---

## 5. Ràng Buộc Kỹ Thuật (PowerShell 2.0 Compliance)

Để bảo đảm tương thích tuyệt đối trên Windows 7 SP1 và Windows Server 2008 R2:
- Không dùng `$PSScriptRoot`: Sử dụng `Split-Path $MyInvocation.MyCommand.Path -Parent`.
- Không dùng cú pháp Type Accelerator mới: Không dùng `[ordered]`, không dùng `[pscustomobject]`. Thay vào đó dùng `New-Object PSObject -Property @{...}` hoặc `System.Collections.Hashtable`.
- Không gọi cmdlet PS 3.0+: Không dùng `Get-ItemPropertyValue`, `Get-CimInstance`, `Get-FileHash`, `Get-LocalUser`, `Get-NetFirewallRule`.
- Đảm bảo mã hóa an toàn khi đọc file cấu hình secedit (Unicode / UTF-16 LE).
