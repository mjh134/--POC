#!/usr/bin/env python3
"""
POC Collection — 统一入口脚本
=============================
支持单个检测/利用、批量检测、信息查看

用法:
    python run_poc.py check http://target:8080 --poc avideo_file_inclusion
    python run_poc.py exploit http://target:8080 --poc papercut_auth_bypass --params '{"username":"admin","passwd":"Admin@123"}'
    python run_poc.py batch targets.txt --poc all
    python run_poc.py list
    python run_poc.py info avideo_file_inclusion
"""

import sys
import os
import json
import argparse
from typing import Dict, Type

# Ensure exploits package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from poc_base import BasePOC


# POC 注册表 — 所有POC在此登记
POC_REGISTRY: Dict[str, Type[BasePOC]] = {}


def register_pocs():
    """动态注册所有可用的 POC"""
    try:
        from exploits.avideo_file_inclusion import AVideoFileInclusion
        POC_REGISTRY["avideo_file_inclusion"] = AVideoFileInclusion
    except ImportError as e:
        print(f"[!] 加载 AVideo POC 失败: {e}")

    try:
        from exploits.papercut_auth_bypass import PaperCutAuthBypass
        POC_REGISTRY["papercut_auth_bypass"] = PaperCutAuthBypass
    except ImportError as e:
        print(f"[!] 加载 PaperCut POC 失败: {e}")

    try:
        from exploits.powerjob_ssrf import PowerJobSSRF
        POC_REGISTRY["powerjob_ssrf"] = PowerJobSSRF
    except ImportError as e:
        print(f"[!] 加载 PowerJob POC 失败: {e}")

    try:
        from exploits.wordpress_permission_bypass import WordPressPermissionBypass
        POC_REGISTRY["wordpress_permission_bypass"] = WordPressPermissionBypass
    except ImportError as e:
        print(f"[!] 加载 WordPress POC 失败: {e}")

    try:
        from exploits.xinhu_oa_sqli_blind import XinhuOASQLIBlind
        POC_REGISTRY["xinhu_oa_sqli_blind"] = XinhuOASQLIBlind
    except ImportError as e:
        print(f"[!] 加载 信呼OA POC 失败: {e}")

    # ====== Batch 2: 10 new POCs ======
    try:
        from exploits.sanhui_smg_info_disclosure import SanhuiSMGInfoDisclosure
        POC_REGISTRY["sanhui_smg_info_disclosure"] = SanhuiSMGInfoDisclosure
    except ImportError as e:
        print(f"[!] 加载 三汇SMG POC 失败: {e}")

    try:
        from exploits.aj_report_code_execution import AJReportCodeExecution
        POC_REGISTRY["aj_report_code_execution"] = AJReportCodeExecution
    except ImportError as e:
        print(f"[!] 加载 AJ-Report POC 失败: {e}")

    try:
        from exploits.drupal_sqli import DrupalSQLInjection
        POC_REGISTRY["drupal_sqli"] = DrupalSQLInjection
    except ImportError as e:
        print(f"[!] 加载 Drupal POC 失败: {e}")

    try:
        from exploits.sobey_unauthorized_access import SobeyUnauthorizedAccess
        POC_REGISTRY["sobey_unauthorized_access"] = SobeyUnauthorizedAccess
    except ImportError as e:
        print(f"[!] 加载 索贝 POC 失败: {e}")

    try:
        from exploits.tiandy_easy7_sqli import TiandyEasy7SQLI
        POC_REGISTRY["tiandy_easy7_sqli"] = TiandyEasy7SQLI
    except ImportError as e:
        print(f"[!] 加载 天地伟业 POC 失败: {e}")

    try:
        from exploits.wordpress_ajax_load_more_info_disclosure import WordPressAjaxLoadMoreInfoDisclosure
        POC_REGISTRY["wordpress_ajax_load_more_info_disclosure"] = WordPressAjaxLoadMoreInfoDisclosure
    except ImportError as e:
        print(f"[!] 加载 WP Ajax Load More POC 失败: {e}")

    try:
        from exploits.wordpress_easy_appointments_info_disclosure import WordPressEasyAppointmentsInfoDisclosure
        POC_REGISTRY["wordpress_easy_appointments_info_disclosure"] = WordPressEasyAppointmentsInfoDisclosure
    except ImportError as e:
        print(f"[!] 加载 WP Easy Appointments POC 失败: {e}")

    try:
        from exploits.wordpress_flippercode_sqli import WordPressFlipperCodeSQLI
        POC_REGISTRY["wordpress_flippercode_sqli"] = WordPressFlipperCodeSQLI
    except ImportError as e:
        print(f"[!] 加载 WP FlipperCode POC 失败: {e}")

    try:
        from exploits.wordpress_webstack_file_upload import WordPressWebStackFileUpload
        POC_REGISTRY["wordpress_webstack_file_upload"] = WordPressWebStackFileUpload
    except ImportError as e:
        print(f"[!] 加载 WP WebStack POC 失败: {e}")

    try:
        from exploits.xwiki_directory_traversal import XWikiDirectoryTraversal
        POC_REGISTRY["xwiki_directory_traversal"] = XWikiDirectoryTraversal
    except ImportError as e:
        print(f"[!] 加载 XWiki POC 失败: {e}")

    # ====== Batch 3: 9 new POCs ======
    try:
        from exploits.gitea_container_registry_unauthorized_access import GiteaContainerRegistryUnauthorizedAccess
        POC_REGISTRY["gitea_container_registry_unauthorized_access"] = GiteaContainerRegistryUnauthorizedAccess
    except ImportError as e:
        print(f"[!] 加载 Gitea POC 失败: {e}")

    try:
        from exploits.yonyou_ksoa_sqli_blind import YonyouKSOASQLIBlind
        POC_REGISTRY["yonyou_ksoa_sqli_blind"] = YonyouKSOASQLIBlind
    except ImportError as e:
        print(f"[!] 加载 用友KSOA POC 失败: {e}")

    try:
        from exploits.trwfe_ws_identity_unauthorized_access import TrwfeWsIdentityUnauthorizedAccess
        POC_REGISTRY["trwfe_ws_identity_unauthorized_access"] = TrwfeWsIdentityUnauthorizedAccess
    except ImportError as e:
        print(f"[!] 加载 天锐绿盾 POC 失败: {e}")

    try:
        from exploits.changedetection_directory_traversal import ChangedetectionDirectoryTraversal
        POC_REGISTRY["changedetection_directory_traversal"] = ChangedetectionDirectoryTraversal
    except ImportError as e:
        print(f"[!] 加载 changedetection POC 失败: {e}")

    try:
        from exploits.fuxa_socket_io_ssrf import FUXASocketIoSSRF
        POC_REGISTRY["fuxa_socket_io_ssrf"] = FUXASocketIoSSRF
    except ImportError as e:
        print(f"[!] 加载 FUXA POC 失败: {e}")

    try:
        from exploits.jupyter_enterprise_gateway_permission_bypass import JupyterEnterpriseGatewayPermissionBypass
        POC_REGISTRY["jupyter_enterprise_gateway_permission_bypass"] = JupyterEnterpriseGatewayPermissionBypass
    except ImportError as e:
        print(f"[!] 加载 Jupyter EG POC 失败: {e}")

    try:
        from exploits.windmill_nextcloud_flow_directory_traversal import WindmillNextcloudFlowDirectoryTraversal
        POC_REGISTRY["windmill_nextcloud_flow_directory_traversal"] = WindmillNextcloudFlowDirectoryTraversal
    except ImportError as e:
        print(f"[!] 加载 Windmill POC 失败: {e}")

    try:
        from exploits.open_webui_retrieval_info_disclosure import OpenWebUIRetrievalInfoDisclosure
        POC_REGISTRY["open_webui_retrieval_info_disclosure"] = OpenWebUIRetrievalInfoDisclosure
    except ImportError as e:
        print(f"[!] 加载 Open WebUI POC 失败: {e}")

    try:
        from exploits.wp_maps_pro_unauthorized_access import WPMapsProUnauthorizedAccess
        POC_REGISTRY["wp_maps_pro_unauthorized_access"] = WPMapsProUnauthorizedAccess
    except ImportError as e:
        print(f"[!] 加载 WP Maps Pro POC 失败: {e}")

    # ====== Batch 4: 10 new POCs ======
    try:
        from exploits.hippoo_permission_bypass import HippooPermissionBypass
        POC_REGISTRY["hippoo_permission_bypass"] = HippooPermissionBypass
    except ImportError as e:
        print(f"[!] 加载 Hippoo POC 失败: {e}")

    try:
        from exploits.gjp_wlt_default_password import GJpWltDefaultPassword
        POC_REGISTRY["gjp_wlt_default_password"] = GJpWltDefaultPassword
    except ImportError as e:
        print(f"[!] 加载 管家婆 POC 失败: {e}")

    try:
        from exploits.quanxi_ai_command_execution import QuanxiAICommandExecution
        POC_REGISTRY["quanxi_ai_command_execution"] = QuanxiAICommandExecution
    except ImportError as e:
        print(f"[!] 加载 全息AI POC 失败: {e}")

    try:
        from exploits.safecert_upload_rce import SafeCertUploadRCE
        POC_REGISTRY["safecert_upload_rce"] = SafeCertUploadRCE
    except ImportError as e:
        print(f"[!] 加载 SafeCert POC 失败: {e}")

    try:
        from exploits.dgraph_debug_vars_info_disclosure import DgraphDebugVarsInfoDisclosure
        POC_REGISTRY["dgraph_debug_vars_info_disclosure"] = DgraphDebugVarsInfoDisclosure
    except ImportError as e:
        print(f"[!] 加载 Dgraph POC 失败: {e}")

    try:
        from exploits.wordpress_mappress_maps_unauthorized_access import WordPressMapPressMapsUnauthorizedAccess
        POC_REGISTRY["wordpress_mappress_maps_unauthorized_access"] = WordPressMapPressMapsUnauthorizedAccess
    except ImportError as e:
        print(f"[!] 加载 MapPress POC 失败: {e}")

    try:
        from exploits.piwigo_ws_unauthorized_access import PiwigoWsUnauthorizedAccess
        POC_REGISTRY["piwigo_ws_unauthorized_access"] = PiwigoWsUnauthorizedAccess
    except ImportError as e:
        print(f"[!] 加载 Piwigo POC 失败: {e}")

    try:
        from exploits.openbullet2_permission_bypass import OpenBullet2PermissionBypass
        POC_REGISTRY["openbullet2_permission_bypass"] = OpenBullet2PermissionBypass
    except ImportError as e:
        print(f"[!] 加载 OpenBullet2 POC 失败: {e}")

    try:
        from exploits.nezha_dashboard_directory_traversal import NezhaDashboardDirectoryTraversal
        POC_REGISTRY["nezha_dashboard_directory_traversal"] = NezhaDashboardDirectoryTraversal
    except ImportError as e:
        print(f"[!] 加载 Nezha Dashboard POC 失败: {e}")

    try:
        from exploits.nezha_api_service_info_disclosure import NezhaApiServiceInfoDisclosure
        POC_REGISTRY["nezha_api_service_info_disclosure"] = NezhaApiServiceInfoDisclosure
    except ImportError as e:
        print(f"[!] 加载 Nezha API POC 失败: {e}")

    # ====== Batch 5: 13 new POCs ======
    try:
        from exploits.motioneye_movie_directory_traversal import MotionEyeMovieDirectoryTraversal
        POC_REGISTRY["motioneye_movie_directory_traversal"] = MotionEyeMovieDirectoryTraversal
    except ImportError as e:
        print(f"[!] 加载 motionEye Movie POC 失败: {e}")

    try:
        from exploits.motioneye_picture_directory_traversal import MotionEyePictureDirectoryTraversal
        POC_REGISTRY["motioneye_picture_directory_traversal"] = MotionEyePictureDirectoryTraversal
    except ImportError as e:
        print(f"[!] 加载 motionEye Picture POC 失败: {e}")

    try:
        from exploits.yonyou_grp_u8_sqli import YonyouGRPU8SQLI
        POC_REGISTRY["yonyou_grp_u8_sqli"] = YonyouGRPU8SQLI
    except ImportError as e:
        print(f"[!] 加载 用友GRP-U8 POC 失败: {e}")

    try:
        from exploits.glodon_xxe import GlodonXXE
        POC_REGISTRY["glodon_xxe"] = GlodonXXE
    except ImportError as e:
        print(f"[!] 加载 广联达XXE POC 失败: {e}")

    try:
        from exploits.lightpicture_permission_bypass import LightPicturePermissionBypass
        POC_REGISTRY["lightpicture_permission_bypass"] = LightPicturePermissionBypass
    except ImportError as e:
        print(f"[!] 加载 LightPicture POC 失败: {e}")

    try:
        from exploits.nine_router_unauthorized_access import NineRouterUnauthorizedAccess
        POC_REGISTRY["nine_router_unauthorized_access"] = NineRouterUnauthorizedAccess
    except ImportError as e:
        print(f"[!] 加载 9Router POC 失败: {e}")

    try:
        from exploits.yonyou_aplus_info_disclosure import YonyouAPlusInfoDisclosure
        POC_REGISTRY["yonyou_aplus_info_disclosure"] = YonyouAPlusInfoDisclosure
    except ImportError as e:
        print(f"[!] 加载 用友A++ POC 失败: {e}")

    try:
        from exploits.argocd_settings_info_disclosure import ArgoCDSettingsInfoDisclosure
        POC_REGISTRY["argocd_settings_info_disclosure"] = ArgoCDSettingsInfoDisclosure
    except ImportError as e:
        print(f"[!] 加载 ArgoCD POC 失败: {e}")

    try:
        from exploits.kubepi_unauthorized_access import KubePiUnauthorizedAccess
        POC_REGISTRY["kubepi_unauthorized_access"] = KubePiUnauthorizedAccess
    except ImportError as e:
        print(f"[!] 加载 KubePi POC 失败: {e}")

    try:
        from exploits.phpbb_permission_bypass import PhpBBPermissionBypass
        POC_REGISTRY["phpbb_permission_bypass"] = PhpBBPermissionBypass
    except ImportError as e:
        print(f"[!] 加载 phpBB POC 失败: {e}")

    try:
        from exploits.acewill_user_add_bypass import AcewillUserAddBypass
        POC_REGISTRY["acewill_user_add_bypass"] = AcewillUserAddBypass
    except ImportError as e:
        print(f"[!] 加载 喰星云 POC 失败: {e}")

    try:
        from exploits.kubernetes_dashboard_auth_bypass import KubernetesDashboardAuthBypass
        POC_REGISTRY["kubernetes_dashboard_auth_bypass"] = KubernetesDashboardAuthBypass
    except ImportError as e:
        print(f"[!] 加载 K8s Dashboard POC 失败: {e}")

    try:
        from exploits.tianwen_property_sqli import TianwenPropertySQLI
        POC_REGISTRY["tianwen_property_sqli"] = TianwenPropertySQLI
    except ImportError as e:
        print(f"[!] 加载 天问物业 POC 失败: {e}")

    # ====== Batch 6: 16 new POCs (KSOA / U8Cloud / CPAS / FileRead / Upload) ======
    try:
        from exploits.yonyou_ksoa_cardcase_insert_cardclass_sqli import YonyouKSOACardcaseInsertCardclassSQLI
        POC_REGISTRY["yonyou_ksoa_cardcase_insert_cardclass_sqli"] = YonyouKSOACardcaseInsertCardclassSQLI
    except ImportError as e:
        print(f"[!] 加载 KSOA insert_cardclass POC 失败: {e}")

    try:
        from exploits.yonyou_ksoa_cardcase_search_list_sqli import YonyouKSOACardcaseSearchListSQLI
        POC_REGISTRY["yonyou_ksoa_cardcase_search_list_sqli"] = YonyouKSOACardcaseSearchListSQLI
    except ImportError as e:
        print(f"[!] 加载 KSOA search_list POC 失败: {e}")

    try:
        from exploits.yonyou_ksoa_km_resubject_sqli import YonyouKSOAKmResubjectSQLI
        POC_REGISTRY["yonyou_ksoa_km_resubject_sqli"] = YonyouKSOAKmResubjectSQLI
    except ImportError as e:
        print(f"[!] 加载 KSOA resubject POC 失败: {e}")

    try:
        from exploits.yonyou_ksoa_luntan_chatconfirm_sqli import YonyouKSOALuntanChatconfirmSQLI
        POC_REGISTRY["yonyou_ksoa_luntan_chatconfirm_sqli"] = YonyouKSOALuntanChatconfirmSQLI
    except ImportError as e:
        print(f"[!] 加载 KSOA chatconfirm POC 失败: {e}")

    try:
        from exploits.yonyou_ksoa_vote_joinvoting_sqli import YonyouKSOAVoteJoinvotingSQLI
        POC_REGISTRY["yonyou_ksoa_vote_joinvoting_sqli"] = YonyouKSOAVoteJoinvotingSQLI
    except ImportError as e:
        print(f"[!] 加载 KSOA joinvoting POC 失败: {e}")

    try:
        from exploits.yonyou_ksoa_vote_joinvoting2_sqli import YonyouKSOAVoteJoinvoting2SQLI
        POC_REGISTRY["yonyou_ksoa_vote_joinvoting2_sqli"] = YonyouKSOAVoteJoinvoting2SQLI
    except ImportError as e:
        print(f"[!] 加载 KSOA joinvoting2 POC 失败: {e}")

    try:
        from exploits.yonyou_ksoa_vote_result_lookresult_sqli import YonyouKSOAVoteResultLookresultSQLI
        POC_REGISTRY["yonyou_ksoa_vote_result_lookresult_sqli"] = YonyouKSOAVoteResultLookresultSQLI
    except ImportError as e:
        print(f"[!] 加载 KSOA lookresult POC 失败: {e}")

    try:
        from exploits.yonyou_u8cloud_so_saleorder_sendaudit_sqli import YonyouU8cloudSOSaleorderSendauditSQLI
        POC_REGISTRY["yonyou_u8cloud_so_saleorder_sendaudit_sqli"] = YonyouU8cloudSOSaleorderSendauditSQLI
    except ImportError as e:
        print(f"[!] 加载 U8Cloud sendaudit POC 失败: {e}")

    try:
        from exploits.yonyou_u8cloud_rep_add_to_task_action_sqli import YonyouU8CloudRepAddToTaskActionSQLI
        POC_REGISTRY["yonyou_u8cloud_rep_add_to_task_action_sqli"] = YonyouU8CloudRepAddToTaskActionSQLI
    except ImportError as e:
        print(f"[!] 加载 U8Cloud RepAddToTaskAction POC 失败: {e}")

    try:
        from exploits.cpas_find_archive_apply_by_dah_sqli import CPASFindArchiveApplyByDahSQLI
        POC_REGISTRY["cpas_find_archive_apply_by_dah_sqli"] = CPASFindArchiveApplyByDahSQLI
    except ImportError as e:
        print(f"[!] 加载 CPAS POC 失败: {e}")

    try:
        from exploits.yongyou_jimu_report_load_table_data_sqli import YongyouJimuReportLoadTableDataSQLI
        POC_REGISTRY["yongyou_jimu_report_load_table_data_sqli"] = YongyouJimuReportLoadTableDataSQLI
    except ImportError as e:
        print(f"[!] 加载 JimuReport SQLI POC 失败: {e}")

    try:
        from exploits.yonyou_grp_u8cloud_query_field_by_sql_freemarker_rce import YonyouGRPU8CloudFreemarkerRCE
        POC_REGISTRY["yonyou_grp_u8cloud_freemarker_rce"] = YonyouGRPU8CloudFreemarkerRCE
    except ImportError as e:
        print(f"[!] 加载 GRP-U8Cloud Freemarker RCE POC 失败: {e}")

    try:
        from exploits.acrel_ems_appdownload_file_read import AcrelEMSAppdownloadFileRead
        POC_REGISTRY["acrel_ems_appdownload_file_read"] = AcrelEMSAppdownloadFileRead
    except ImportError as e:
        print(f"[!] 加载 安科瑞EMS 文件读取 POC 失败: {e}")

    try:
        from exploits.weaver_ecology10_download_syslog_file_read import WeaverEcology10DownLoadSyslogFileRead
        POC_REGISTRY["weaver_ecology10_download_syslog_file_read"] = WeaverEcology10DownLoadSyslogFileRead
    except ImportError as e:
        print(f"[!] 加载 泛微10 文件读取 POC 失败: {e}")

    try:
        from exploits.yonyou_u8cloud_service_dispatcher_file_upload import YonyouU8CloudServiceDispatcherFileUpload
        POC_REGISTRY["yonyou_u8cloud_service_dispatcher_file_upload"] = YonyouU8CloudServiceDispatcherFileUpload
    except ImportError as e:
        print(f"[!] 加载 U8Cloud 文件上传 POC 失败: {e}")

    try:
        from exploits.balbooa_forms_cve_2026_56291_file_upload import BalbooaFormsCVE202656291FileUpload
        POC_REGISTRY["balbooa_forms_cve_2026_56291_file_upload"] = BalbooaFormsCVE202656291FileUpload
    except ImportError as e:
        print(f"[!] 加载 Balbooa Forms CVE-2026-56291 POC 失败: {e}")


def list_pocs():
    """列出所有可用的 POC"""
    print(f"{'=' * 70}")
    print(f"  POC Collection — 可用漏洞POC清单")
    print(f"{'=' * 70}")
    print(f"  {'名称':<35} {'类型':<15} {'CVE':<18}")
    print(f"  {'-' * 70}")
    for name, cls in sorted(POC_REGISTRY.items()):
        cve = cls.cve if cls.cve else "-"
        print(f"  {name:<35} {cls.vuln_type:<15} {cve:<18}")
    print(f"  {'-' * 70}")
    print(f"  共 {len(POC_REGISTRY)} 个 POC")
    print()


def show_poc_info(poc_name: str):
    """显示指定 POC 的详细信息"""
    if poc_name not in POC_REGISTRY:
        print(f"[-] 未知 POC: {poc_name}")
        print(f"    可用: {', '.join(POC_REGISTRY.keys())}")
        return
    poc_class = POC_REGISTRY[poc_name]
    # 创建一个临时实例仅用于显示信息
    tmp = poc_class(target="target:8080")
    print(tmp.show_info())


def run_check(target: str, poc_name: str, ssl: bool = False,
              timeout: int = 15, verbose: bool = False) -> bool:
    """检测单个目标"""
    if poc_name not in POC_REGISTRY:
        print(f"[-] 未知 POC: {poc_name}")
        return False

    poc_class = POC_REGISTRY[poc_name]
    poc = poc_class(target=target, ssl=ssl, timeout=timeout)

    print(f"[*] 正在检测: {poc.product}")
    print(f"[*] 漏洞: {poc.name}")
    print(f"[*] 目标: {target}")
    if verbose:
        print(f"[*] 超时: {timeout}s, HTTPS: {ssl}")
    print("-" * 50)

    result = poc.check()
    print(result)
    return bool(result)


def run_exploit(target: str, poc_name: str, params: Dict,
                ssl: bool = False, timeout: int = 15) -> bool:
    """利用单个目标"""
    if poc_name not in POC_REGISTRY:
        print(f"[-] 未知 POC: {poc_name}")
        return False

    poc_class = POC_REGISTRY[poc_name]
    poc = poc_class(target=target, ssl=ssl, timeout=timeout)

    if not poc.has_exp:
        print(f"[-] {poc.name} 没有 EXP 功能")
        return False

    print(f"[*] 正在利用: {poc.product}")
    print(f"[*] 漏洞: {poc.name}")
    print(f"[*] 目标: {target}")
    print(f"[*] 参数: {params}")
    print("-" * 50)

    result = poc.exploit(**params)
    print(result)
    return bool(result)


def run_batch(targets_file: str, poc_name: str = "all",
              ssl: bool = False, timeout: int = 15):
    """批量检测"""
    if not os.path.exists(targets_file):
        print(f"[-] 目标文件不存在: {targets_file}")
        return

    with open(targets_file, "r") as f:
        targets = [line.strip() for line in f
                   if line.strip() and not line.strip().startswith("#")]

    if not targets:
        print("[-] 目标文件为空")
        return

    pocs_to_run = list(POC_REGISTRY.keys()) if poc_name == "all" else [poc_name]

    print(f"[*] 批量检测开始: {len(targets)} 个目标, {len(pocs_to_run)} 个 POC")
    print(f"[*] 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    results = {}
    for target in targets:
        results[target] = {}
        for pname in pocs_to_run:
            try:
                result = run_check(target, pname, ssl=ssl, timeout=timeout)
                results[target][pname] = "✅ VULN" if result else "❌ SAFE"
            except Exception as e:
                results[target][pname] = f"❌ ERROR: {e}"

    # 汇总报告
    print()
    print("=" * 70)
    print("  批量检测汇总")
    print("=" * 70)
    vuln_count = 0
    for target, poc_results in results.items():
        for pname, status in poc_results.items():
            if "VULN" in status:
                vuln_count += 1
                print(f"  ✅ [{target}] {pname} — 存在漏洞!")

    if vuln_count == 0:
        print("  所有目标均未发现漏洞")
    print(f"  共检测 {len(targets)} 个目标 × {len(pocs_to_run)} 个 POC = "
          f"{len(targets) * len(pocs_to_run)} 次检测")
    print(f"  发现漏洞: {vuln_count}")


def main():
    parser = argparse.ArgumentParser(
        description="POC Collection — 统一入口",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python run_poc.py check http://192.168.1.100:8080 --poc avideo_file_inclusion\n"
            "  python run_poc.py exploit http://192.168.1.100:9191 --poc papercut_auth_bypass -p '{\"username\":\"admin\",\"passwd\":\"Admin@123\"}'\n"
            "  python run_poc.py batch targets.txt --poc all\n"
            "  python run_poc.py list\n"
            "  python run_poc.py info avideo_file_inclusion\n"
        )
    )

    parser.add_argument("action", choices=["check", "exploit", "batch", "list", "info"],
                        help="执行操作")
    parser.add_argument("target_or_file", nargs="?", default="",
                        help="目标地址 (IP:port) 或目标文件路径 (batch模式)")
    parser.add_argument("--poc", "--name", default="",
                        help="POC 名称 (如 avideo_file_inclusion), 或 'all'")
    parser.add_argument("--params", "-p", default="{}",
                        help='利用参数JSON (如 \'{"filePath":"../etc/passwd"}\')')
    parser.add_argument("--ssl", action="store_true", help="使用 HTTPS")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时秒数")
    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细信息")

    args = parser.parse_args()
    register_pocs()

    if args.action == "list":
        list_pocs()
        return

    if args.action == "info":
        if not args.poc and not args.target_or_file:
            print("[-] 请指定 POC 名称: python run_poc.py info avideo_file_inclusion")
            list_pocs()
            return
        show_poc_info(args.poc or args.target_or_file)
        return

    if args.action == "batch":
        run_batch(
            targets_file=args.target_or_file,
            poc_name=args.poc or "all",
            ssl=args.ssl,
            timeout=args.timeout,
        )
        return

    if not args.target_or_file:
        print("[-] 请指定目标地址")
        parser.print_help()
        return

    if args.action == "check":
        if not args.poc:
            print("[-] 请指定 POC 名称 (--poc)")
            list_pocs()
            return
        run_check(args.target_or_file, args.poc,
                  ssl=args.ssl, timeout=args.timeout,
                  verbose=args.verbose)

    elif args.action == "exploit":
        if not args.poc:
            print("[-] 请指定 POC 名称 (--poc)")
            list_pocs()
            return
        params = json.loads(args.params) if args.params else {}
        run_exploit(args.target_or_file, args.poc, params,
                    ssl=args.ssl, timeout=args.timeout)


if __name__ == "__main__":
    import time
    main()
