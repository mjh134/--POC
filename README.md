# POC Collection

> 漏洞检测/利用脚本集（Python）

## 📋 漏洞清单 (共 55 个)

| # | 漏洞名称 | 类型 | CVE | 有EXP |
|---|---------|------|-----|-------|
| 1 | [AVideo 文件包含漏洞](./exploits/avideo_file_inclusion.py) | 文件包含 | CVE-2026-33513 | ✅ |
| 2 | [PaperCut NG/MF 权限绕过漏洞](./exploits/papercut_auth_bypass.py) | 权限绕过 | CVE-2023-27351 | ✅ |
| 3 | [PowerJob SSRF漏洞](./exploits/powerjob_ssrf.py) | SSRF | CVE-2025-14518 | ✅ |
| 4 | [WordPress 用户枚举权限绕过](./exploits/wordpress_permission_bypass.py) | 权限绕过 | CVE-2025-4302 | ✅ |
| 5 | [信呼OA SQL注入盲注](./exploits/xinhu_oa_sqli_blind.py) | SQL注入 | CVE-2025-63742 | ❌ |
| 6 | [三汇SMG网关信息泄露](./exploits/sanhui_smg_info_disclosure.py) | 信息泄露 | - | ✅ |
| 7 | [AJ-Report积木报表代码执行](./exploits/aj_report_code_execution.py) | 代码执行 | CVE-2024-7314 | ✅ |
| 8 | [Drupal核心SQL注入](./exploits/drupal_sqli.py) | SQL注入 | CVE-2026-9082 | ✅ |
| 9 | [索贝未授权访问](./exploits/sobey_unauthorized_access.py) | 未授权访问 | - | ✅ |
| 10 | [天地伟业Easy7 SQL注入](./exploits/tiandy_easy7_sqli.py) | SQL注入 | - | ❌ |
| 11 | [WP Ajax Load More信息泄露](./exploits/wordpress_ajax_load_more_info_disclosure.py) | 信息泄露 | CVE-2025-59582 | ✅ |
| 12 | [WP Easy Appointments信息泄露](./exploits/wordpress_easy_appointments_info_disclosure.py) | 信息泄露 | CVE-2026-2262 | ✅ |
| 13 | [WP FlipperCode SQL注入](./exploits/wordpress_flippercode_sqli.py) | SQL注入→RCE | CVE-2026-6433 | ✅ |
| 14 | [WP WebStack文件上传](./exploits/wordpress_webstack_file_upload.py) | 文件上传 | CVE-2026-1555 | ✅ |
| 15 | [XWiki目录遍历](./exploits/xwiki_directory_traversal.py) | 目录遍历 | CVE-2026-23734 | ✅ |
| 16 | [Gitea容器注册表未授权访问](./exploits/gitea_container_registry_unauthorized_access.py) | 未授权访问 | CVE-2026-27771 | ✅ |
| 17 | [用友时空KSOA SQL盲注](./exploits/yonyou_ksoa_sqli_blind.py) | SQL盲注 | - | ❌ |
| 18 | [天锐绿盾审批系统未授权访问](./exploits/trwfe_ws_identity_unauthorized_access.py) | 未授权访问 | - | ✅ |
| 19 | [changedetection.io 目录遍历](./exploits/changedetection_directory_traversal.py) | 目录遍历 | CVE-2026-25527 | ✅ |
| 20 | [FUXA Socket.IO SSRF](./exploits/fuxa_socket_io_ssrf.py) | SSRF | CVE-2026-47719 | ✅ |
| 21 | [Jupyter EG 权限绕过→RCE](./exploits/jupyter_enterprise_gateway_permission_bypass.py) | 权限绕过 | CVE-2026-44180 | ✅ |
| 22 | [Windmill/Nextcloud Flow 目录遍历](./exploits/windmill_nextcloud_flow_directory_traversal.py) | 目录遍历 | CVE-2026-29059 | ✅ |
| 23 | [Open WebUI RAG信息泄露](./exploits/open_webui_retrieval_info_disclosure.py) | 信息泄露 | CVE-2026-45397 | ✅ |
| 24 | [WP Maps Pro 未授权访问→创建管理员](./exploits/wp_maps_pro_unauthorized_access.py) | 未授权访问 | CVE-2026-8732 | ✅ |
| 25 | [Hippoo Mobile App权限绕过](./exploits/hippoo_permission_bypass.py) | 权限绕过 | CVE-2026-10580 | ✅ |
| 26 | [管家婆物联通默认口令](./exploits/gjp_wlt_default_password.py) | 默认口令 | - | ✅ |
| 27 | [全息AI网络运维平台命令执行](./exploits/quanxi_ai_command_execution.py) | 命令执行 | - | ✅ |
| 28 | [SafeCert命令执行](./exploits/safecert_upload_rce.py) | 命令执行 | - | ✅ |
| 29 | [Dgraph 图数据库信息泄露](./exploits/dgraph_debug_vars_info_disclosure.py) | 信息泄露 | CVE-2026-41492 | ✅ |
| 30 | [WP MapPress Maps未授权访问](./exploits/wordpress_mappress_maps_unauthorized_access.py) | 未授权访问 | CVE-2026-8839 | ✅ |
| 31 | [Piwigo浏览历史未授权访问](./exploits/piwigo_ws_unauthorized_access.py) | 未授权访问 | CVE-2026-27833 | ✅ |
| 32 | [OpenBullet2权限绕过](./exploits/openbullet2_permission_bypass.py) | 权限绕过 | CVE-2026-25555 | ✅ |
| 33 | [Nezha Dashboard目录遍历](./exploits/nezha_dashboard_directory_traversal.py) | 目录遍历 | CVE-2026-53519 | ✅ |
| 34 | [Nezha服务信息泄露](./exploits/nezha_api_service_info_disclosure.py) | 信息泄露 | CVE-2026-49397 | ✅ |
| 35 | [motionEye播放目录遍历](./exploits/motioneye_movie_directory_traversal.py) | 目录遍历 | CVE-2026-55488 | ✅ |
| 36 | [motionEye预览目录遍历](./exploits/motioneye_picture_directory_traversal.py) | 目录遍历 | CVE-2026-31978 | ✅ |
| 37 | [用友GRP-U8 A++ V8 SQL注入](./exploits/yonyou_grp_u8_sqli.py) | SQL注入 | - | ✅ |
| 38 | [广联达XXE注入](./exploits/glodon_xxe.py) | XXE | - | ✅ |
| 39 | [LightPicture权限绕过](./exploits/lightpicture_permission_bypass.py) | 权限绕过 | - | ✅ |
| 40 | [9Router未授权访问](./exploits/nine_router_unauthorized_access.py) | 未授权访问 | - | ✅ |
| 41 | [用友A++信息泄露](./exploits/yonyou_aplus_info_disclosure.py) | 信息泄露 | - | ✅ |
| 42 | [Argo CD配置信息泄露](./exploits/argocd_settings_info_disclosure.py) | 信息泄露 | CVE-2024-37152 | ✅ |
| 43 | [KubePi未授权访问](./exploits/kubepi_unauthorized_access.py) | 未授权访问 | CVE-2023-22478 | ✅ |
| 44 | [phpBB权限绕过](./exploits/phpbb_permission_bypass.py) | 权限绕过 | CVE-2026-48611 | ✅ |
| 45 | [喰星云餐饮系统权限绕过](./exploits/acewill_user_add_bypass.py) | 权限绕过 | - | ✅ |
| 46 | [K8s Dashboard权限绕过](./exploits/kubernetes_dashboard_auth_bypass.py) | 权限绕过 | CVE-2018-18264 | ✅ |
| 47 | [天问物业ERP SQL注入](./exploits/tianwen_property_sqli.py) | SQL注入 | - | ✅ |
| 48 | [KSOA insert_cardclass SQL注入](./exploits/yonyou_ksoa_cardcase_insert_cardclass_sqli.py) | SQL注入 | - | ⚡ |
| 49 | [KSOA search_list SQL注入](./exploits/yonyou_ksoa_cardcase_search_list_sqli.py) | SQL注入 | - | ⚡ |
| 50 | [KSOA resubject SQL注入](./exploits/yonyou_ksoa_km_resubject_sqli.py) | SQL注入 | - | ⚡ |
| 51 | [KSOA chatconfirm SQL注入](./exploits/yonyou_ksoa_luntan_chatconfirm_sqli.py) | SQL注入 | - | ⚡ |
| 52 | [KSOA joinvoting SQL注入](./exploits/yonyou_ksoa_vote_joinvoting_sqli.py) | SQL注入 | - | ⚡ |
| 53 | [KSOA joinvoting2 SQL注入](./exploits/yonyou_ksoa_vote_joinvoting2_sqli.py) | SQL注入 | - | ⚡ |
| 54 | [KSOA lookResult SQL注入](./exploits/yonyou_ksoa_vote_result_lookresult_sqli.py) | SQL注入 | - | ⚡ |
| 55 | [U8cloud saleorder.sendaudit SQL注入](./exploits/yonyou_u8cloud_so_saleorder_sendaudit_sqli.py) | SQL注入 | - | ⚡ |

## 🚀 快速使用

```bash
# 安装依赖
pip install -r requirements.txt

# 使用统一入口检测
python run_poc.py check http://target.com:8080 --poc avideo_file_inclusion

# 使用统一入口利用
python run_poc.py exploit http://target.com:8080 --poc avideo_file_inclusion --params '{"filePath":"../etc/passwd"}'

# 直接运行单个POC
python exploits/avideo_file_inclusion.py check http://target.com:8080

# 批量检测
python run_poc.py batch targets.txt --poc all

# 列出所有POC
python run_poc.py list
```

## 📁 目录结构

```
├── README.md                  # 本文件
├── requirements.txt           # Python依赖
├── run_poc.py                 # 统一入口脚本
├── poc_base.py                # POC 基类框架
├── exploits/                  # POC 脚本目录 (Python)
```

完整的 POC 列表见上方的漏洞清单。

## 📖 每个 POC 包含的信息

每个 POC 文件都是**独立可执行**的 Python 脚本，包含：

1. **漏洞文档** — 产品名称、漏洞类型、入口点、漏洞原理、危害等级
2. **检测逻辑** — `check()` 方法，返回是否存在漏洞
3. **利用逻辑** — `exploit()` 方法（如有），执行漏洞利用
4. **命令行入口** — 可直接运行

## ⚙️ 使用方法

### 检测单个目标

```bash
python exploits/<poc_name>.py check <target>
python exploits/powerjob_ssrf.py check http://192.168.1.100:7700
```

### 利用漏洞

```bash
python exploits/<poc_name>.py exploit <target> [--params JSON]
python exploits/avideo_file_inclusion.py exploit http://192.168.1.100:8080 --params '{"filePath":"../etc/passwd"}'
python exploits/papercut_auth_bypass.py exploit http://192.168.1.100:9191 --params '{"username":"hacker","passwd":"Hacker@123"}'
```

### 批量检测

```bash
python run_poc.py batch targets.txt --poc powerjob_ssrf
```

## 🔒 免责声明

本工具仅供安全研究和授权测试使用，使用者需遵守相关法律法规。请勿用于非法用途。
