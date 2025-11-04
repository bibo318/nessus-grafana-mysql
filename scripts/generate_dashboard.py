from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

DS_UID = "${DS_MYSQL_NESSUS}"
PLUGIN_VERSION = "11.2.0"

HOST_NAME_FILTER = "'$__all' IN (${host:sqlstring}) OR h.hostname IN (${host:sqlstring}) OR h.ip_address IN (${host:sqlstring})"
HOST_IP_FILTER = "'$__all' IN (${ip:sqlstring}) OR h.ip_address IN (${ip:sqlstring})"
HOST_OS_FILTER = "'$__all' IN (${os_filter:sqlstring}) OR h.operating_system IN (${os_filter:sqlstring})"
CATEGORY_HOSTS = """'${phan_loai}' = 'tatca'\n    OR EXISTS (\n      SELECT 1\n      FROM findings f_loc\n      JOIN plugins p_loc ON p_loc.plugin_id = f_loc.plugin_id\n      WHERE f_loc.scan_id = h.scan_id\n        AND f_loc.history_id = h.history_id\n        AND (f_loc.hostname <=> h.hostname)\n        AND (\n          ('${phan_loai}' = 'web' AND (p_loc.plugin_family LIKE '%Web%' OR p_loc.plugin_family LIKE '%CGI%' OR p_loc.plugin_family LIKE '%HTTP%' OR p_loc.plugin_family LIKE '%WWW%'))\n          OR ('${phan_loai}' = 'os' AND (p_loc.plugin_family LIKE '%Windows%' OR p_loc.plugin_family LIKE '%Unix%' OR p_loc.plugin_family LIKE '%Linux%' OR p_loc.plugin_family LIKE '%Operating System%' OR p_loc.plugin_family LIKE '%OS%'))\n        )\n    )"""

PLUGINS_CATEGORY = """'${phan_loai}' = 'tatca'\n    OR ( '${phan_loai}' = 'web' AND (p.plugin_family LIKE '%Web%' OR p.plugin_family LIKE '%CGI%' OR p.plugin_family LIKE '%HTTP%' OR p.plugin_family LIKE '%WWW%') )\n    OR ( '${phan_loai}' = 'os' AND (p.plugin_family LIKE '%Windows%' OR p.plugin_family LIKE '%Unix%' OR p.plugin_family LIKE '%Linux%' OR p.plugin_family LIKE '%Operating System%' OR p.plugin_family LIKE '%OS%') )"""

FINDINGS_HOST_FILTER = "EXISTS (SELECT 1 FROM filtered_hosts fh WHERE fh.scan_id = f.scan_id AND fh.history_id = f.history_id AND (f.hostname IS NULL OR f.hostname = fh.hostname))"
HOST_FINDINGS_FILTER = "EXISTS (SELECT 1 FROM filtered_hosts fh WHERE fh.scan_id = hf.scan_id AND fh.history_id = hf.history_id AND (hf.host_id = fh.host_id OR (hf.hostname IS NOT NULL AND hf.hostname = fh.hostname)))"

HOSTS_CTE = """WITH filtered_hosts AS (\n    SELECT *\n    FROM hosts h\n    WHERE h.scan_id = ${scan:raw}\n      AND h.history_id = ${history:raw}\n      AND ({HOST_NAME_FILTER})\n      AND ({HOST_IP_FILTER})\n      AND ({HOST_OS_FILTER})\n      AND (\n        {CATEGORY_HOSTS}\n      )\n)\n""".replace('{HOST_NAME_FILTER}', HOST_NAME_FILTER).replace('{HOST_IP_FILTER}', HOST_IP_FILTER).replace('{HOST_OS_FILTER}', HOST_OS_FILTER).replace('{CATEGORY_HOSTS}', CATEGORY_HOSTS)


def hosts_query(body: str) -> str:
    return HOSTS_CTE + body


def host_findings_query(body: str) -> str:
    return (HOSTS_CTE + body).replace('{host_findings_filter}', HOST_FINDINGS_FILTER).replace('{plugins_category}', PLUGINS_CATEGORY)


def findings_query(body: str) -> str:
    return (HOSTS_CTE + body).replace('{findings_host_filter}', FINDINGS_HOST_FILTER).replace('{plugins_category}', PLUGINS_CATEGORY)


def datasource() -> Dict[str, str]:
    return {"type": "mysql", "uid": DS_UID}


def stat_panel(panel_id: int, title: str, description: str, sql: str, grid: Dict[str, int],
               color_steps: List[Dict[str, Any]] | None = None, unit: str | None = None,
               mappings: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        "mappings": mappings or [],
        "thresholds": {
            "mode": "absolute",
            "steps": color_steps or [{"color": "#2ECC71", "value": None}]
        }
    }
    if mappings:
        defaults["mappings"] = mappings
    panel = {
        "datasource": datasource(),
        "description": description,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "gridPos": grid,
        "id": panel_id,
        "options": {
            "colorMode": "value",
            "graphMode": "none",
            "justifyMode": "auto",
            "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "textMode": "value",
            "wideLayout": True
        },
        "pluginVersion": PLUGIN_VERSION,
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": sql,
                "refId": "A"
            }
        ],
        "title": title,
        "type": "stat"
    }
    if unit:
        panel["options"]["unit"] = unit
    return panel

def row_panel(panel_id: int, title: str, y: int) -> Dict[str, Any]:
    return {
        "collapsed": False,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
        "id": panel_id,
        "panels": [],
        "title": title,
        "type": "row"
    }


def stat_status_panel() -> Dict[str, Any]:
    mappings = [
        {
            "options": {
                "completed": {"color": "#2ECC71", "index": 0, "text": "Hoàn thành"},
                "running": {"color": "#F39C12", "index": 1, "text": "Đang chạy"},
                "stopped": {"color": "#E74C3C", "index": 2, "text": "Đã dừng"},
                "canceled": {"color": "#E74C3C", "index": 3, "text": "Đã huỷ"}
            },
            "type": "value"
        }
    ]
    return stat_panel(
        panel_id=1,
        title="Trạng thái quét",
        description="Trạng thái của lịch quét đã chọn, hiển thị theo ngôn ngữ tiếng Việt.",
        sql="SELECT LOWER(status) AS value FROM processed_history WHERE scan_id = ${scan:raw} AND history_id = ${history:raw} LIMIT 1;",
        grid={"h": 4, "w": 4, "x": 0, "y": 1},
        color_steps=[{"color": "#2ECC71", "value": None}],
        mappings=mappings
    )


def build_summary_panels() -> List[Dict[str, Any]]:
    panels: List[Dict[str, Any]] = [stat_status_panel()]

    panels.append(stat_panel(
        panel_id=2,
        title="Bắt đầu quét",
        description="Thời điểm Nessus bắt đầu chạy lịch quét này.",
        sql="SELECT FROM_UNIXTIME(scan_start) AS value FROM processed_history WHERE scan_id = ${scan:raw} AND history_id = ${history:raw} LIMIT 1;",
        grid={"h": 4, "w": 4, "x": 4, "y": 1},
        color_steps=[{"color": "#3498DB", "value": None}],
        unit="dateTimeAsIso"
    ))

    panels.append(stat_panel(
        panel_id=3,
        title="Kết thúc quét",
        description="Thời điểm Nessus kết thúc lịch quét này.",
        sql="SELECT FROM_UNIXTIME(scan_end) AS value FROM processed_history WHERE scan_id = ${scan:raw} AND history_id = ${history:raw} LIMIT 1;",
        grid={"h": 4, "w": 4, "x": 8, "y": 1},
        color_steps=[{"color": "#9B59B6", "value": None}],
        unit="dateTimeAsIso"
    ))

    panels.append(stat_panel(
        panel_id=4,
        title="Thời lượng quét (phút)",
        description="Thời lượng thực thi tính theo phút (scan_end - scan_start).",
        sql="SELECT ROUND((scan_end - scan_start) / 60, 1) AS value FROM processed_history WHERE scan_id = ${scan:raw} AND history_id = ${history:raw} LIMIT 1;",
        grid={"h": 4, "w": 4, "x": 12, "y": 1},
        color_steps=[
            {"color": "#2ECC71", "value": None},
            {"color": "#F39C12", "value": 60},
            {"color": "#E74C3C", "value": 180}
        ],
        unit="m"
    ))

    panels.append(stat_panel(
        panel_id=5,
        title="Số lượng máy chủ",
        description="Số máy chủ được quét trong lịch sử đã chọn (áp dụng bộ lọc loại hiển thị).",
        sql=hosts_query("SELECT COUNT(DISTINCT host_id) AS value\nFROM filtered_hosts;"),
        grid={"h": 4, "w": 4, "x": 16, "y": 1},
        color_steps=[
            {"color": "#1ABC9C", "value": None},
            {"color": "#F39C12", "value": 10}
        ]
    ))

    panels.append(stat_panel(
        panel_id=6,
        title="Tổng số phát hiện",
        description="Tổng số phát hiện (mọi mức độ) đáp ứng bộ lọc.",
        sql=hosts_query("SELECT SUM(critical + high + medium + low + info) AS value\nFROM filtered_hosts;"),
        grid={"h": 4, "w": 4, "x": 20, "y": 1},
        color_steps=[
            {"color": "#2ECC71", "value": None},
            {"color": "#F39C12", "value": 100},
            {"color": "#E67E22", "value": 300},
            {"color": "#E74C3C", "value": 600}
        ]
    ))

    return panels

def pie_panel() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Tỷ lệ lỗ hổng theo từng mức độ nghiêm trọng trên các máy chủ phù hợp bộ lọc.",
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"hideFrom": {"legend": False, "tooltip": False, "viz": False}},
                "mappings": []
            },
            "overrides": []
        },
        "gridPos": {"h": 9, "w": 8, "x": 0, "y": 6},
        "id": 7,
        "options": {
            "displayLabels": ["name", "value", "percent"],
            "legend": {"displayMode": "list", "placement": "bottom", "show": True},
            "pieType": "pie",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "tooltip": {"mode": "single", "sort": "desc"}
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": hosts_query(
                    "SELECT 'Nghiêm trọng' AS name, SUM(critical) AS value FROM filtered_hosts\n"
                    "UNION ALL SELECT 'Cao' AS name, SUM(high) AS value FROM filtered_hosts\n"
                    "UNION ALL SELECT 'Trung bình' AS name, SUM(medium) AS value FROM filtered_hosts\n"
                    "UNION ALL SELECT 'Thấp' AS name, SUM(low) AS value FROM filtered_hosts\n"
                    "UNION ALL SELECT 'Thông tin' AS name, SUM(info) AS value FROM filtered_hosts;"
                ),
                "refId": "A"
            }
        ],
        "title": "Phân bố mức độ nghiêm trọng",
        "type": "piechart"
    }


def stacked_host_bar() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Top máy chủ có số lượng lỗ hổng cao nhất, hiển thị dạng cột chồng màu sắc.",
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {
                    "axisBorderShow": False,
                    "axisCenteredZero": False,
                    "axisColorMode": "text",
                    "axisPlacement": "auto",
                    "barAlignment": 0,
                    "drawStyle": "bars",
                    "fillOpacity": 80,
                    "gradientMode": "scheme",
                    "hideFrom": {"legend": False, "tooltip": False, "viz": False},
                    "stacking": {"group": "A", "mode": "normal"}
                },
                "mappings": []
            },
            "overrides": []
        },
        "gridPos": {"h": 9, "w": 8, "x": 8, "y": 6},
        "id": 8,
        "options": {
            "legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "show": True},
            "tooltip": {"mode": "multi", "sort": "desc"},
            "xAxis": {"axisLabel": "Máy chủ", "show": True},
            "yAxis": {"axisLabel": "Số lượng phát hiện", "show": True}
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": hosts_query(
                    "SELECT hostname AS metric, 'Nghiêm trọng' AS series, SUM(critical) AS value FROM filtered_hosts GROUP BY hostname HAVING SUM(critical) > 0\n"
                    "UNION ALL SELECT hostname AS metric, 'Cao' AS series, SUM(high) AS value FROM filtered_hosts GROUP BY hostname HAVING SUM(high) > 0\n"
                    "UNION ALL SELECT hostname AS metric, 'Trung bình' AS series, SUM(medium) AS value FROM filtered_hosts GROUP BY hostname HAVING SUM(medium) > 0\n"
                    "ORDER BY metric, series;"
                ),
                "refId": "A"
            }
        ],
        "title": "Top máy chủ theo mức độ rủi ro",
        "type": "barchart"
    }


def severity_trend() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Xu hướng số lượng phát hiện theo mức độ trong các lần quét gần đây của cùng bản quét.",
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {
                    "axisBorderShow": False,
                    "axisCenteredZero": False,
                    "axisColorMode": "text",
                    "axisPlacement": "auto",
                    "barAlignment": 0,
                    "drawStyle": "line",
                    "fillOpacity": 20,
                    "gradientMode": "scheme",
                    "hideFrom": {"legend": False, "tooltip": False, "viz": False},
                    "lineInterpolation": "smooth",
                    "lineWidth": 2,
                    "pointSize": 5,
                    "scaleDistribution": {"type": "linear"},
                    "showPoints": "never",
                    "stacking": {"group": "A", "mode": "none"}
                },
                "mappings": [],
                "thresholds": {"mode": "absolute", "steps": [{"color": "#2ECC71", "value": None}]}
            },
            "overrides": []
        },
        "gridPos": {"h": 9, "w": 8, "x": 16, "y": 6},
        "id": 9,
        "options": {
            "legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "show": True},
            "tooltip": {"mode": "single", "sort": "desc"},
            "xAxis": {"show": True},
            "yAxis": {"label": "Số phát hiện", "show": True}
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "time_series",
                "rawSql": host_findings_query(
                    "SELECT FROM_UNIXTIME(ph.scan_end) AS time, 'Nghiêm trọng' AS metric, COUNT(*) AS value\n"
                    "FROM host_findings hf\nJOIN processed_history ph ON ph.scan_id = hf.scan_id AND ph.history_id = hf.history_id\nJOIN plugins p ON p.plugin_id = hf.plugin_id\n"
                    "WHERE hf.scan_id = ${scan:raw}\n  AND hf.severity = 4\n  AND ({host_findings_filter})\n  AND (\n    {plugins_category}\n  )\nGROUP BY ph.scan_end\n"
                    "UNION ALL\nSELECT FROM_UNIXTIME(ph.scan_end) AS time, 'Cao' AS metric, COUNT(*) AS value\n"
                    "FROM host_findings hf\nJOIN processed_history ph ON ph.scan_id = hf.scan_id AND ph.history_id = hf.history_id\nJOIN plugins p ON p.plugin_id = hf.plugin_id\n"
                    "WHERE hf.scan_id = ${scan:raw}\n  AND hf.severity = 3\n  AND ({host_findings_filter})\n  AND (\n    {plugins_category}\n  )\nGROUP BY ph.scan_end\n"
                    "UNION ALL\nSELECT FROM_UNIXTIME(ph.scan_end) AS time, 'Trung bình' AS metric, COUNT(*) AS value\n"
                    "FROM host_findings hf\nJOIN processed_history ph ON ph.scan_id = hf.scan_id AND ph.history_id = hf.history_id\nJOIN plugins p ON p.plugin_id = hf.plugin_id\n"
                    "WHERE hf.scan_id = ${scan:raw}\n  AND hf.severity = 2\n  AND ({host_findings_filter})\n  AND (\n    {plugins_category}\n  )\nGROUP BY ph.scan_end\n"
                    "UNION ALL\nSELECT FROM_UNIXTIME(ph.scan_end) AS time, 'Thấp' AS metric, COUNT(*) AS value\n"
                    "FROM host_findings hf\nJOIN processed_history ph ON ph.scan_id = hf.scan_id AND ph.history_id = hf.history_id\nJOIN plugins p ON p.plugin_id = hf.plugin_id\n"
                    "WHERE hf.scan_id = ${scan:raw}\n  AND hf.severity = 1\n  AND ({host_findings_filter})\n  AND (\n    {plugins_category}\n  )\nGROUP BY ph.scan_end\nORDER BY time, metric;"
                ),
                "refId": "A"
            }
        ],
        "title": "Xu hướng mức độ theo lịch sử",
        "type": "timeseries"
    }

def timeline_panel() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Hiển thị trạng thái từng lịch chạy theo trục thời gian để dễ nhận biết tiến độ.",
        "fieldConfig": {
            "defaults": {
                "custom": {"lineWidth": 1, "spanNulls": False},
                "mappings": [
                    {
                        "options": {
                            "Hoàn thành": {"color": "#2ECC71", "index": 0},
                            "Đang chạy": {"color": "#F39C12", "index": 1},
                            "Đã dừng": {"color": "#E74C3C", "index": 2},
                            "Đã huỷ": {"color": "#E74C3C", "index": 3}
                        },
                        "type": "value"
                    }
                ],
                "thresholds": {"mode": "absolute", "steps": [{"color": "#2ECC71", "value": None}]}
            },
            "overrides": []
        },
        "gridPos": {"h": 7, "w": 14, "x": 0, "y": 16},
        "id": 10,
        "options": {
            "legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "show": True},
            "rowHeight": 0.9,
            "tooltip": {"mode": "single", "sort": "none"}
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": "SELECT\n  FROM_UNIXTIME(ph.scan_start) AS time,\n  FROM_UNIXTIME(ph.scan_end) AS timeend,\n  CONCAT('Lịch ', ph.history_id) AS metric,\n  CASE ph.status\n    WHEN 'completed' THEN 'Hoàn thành'\n    WHEN 'running' THEN 'Đang chạy'\n    WHEN 'canceled' THEN 'Đã huỷ'\n    WHEN 'stopped' THEN 'Đã dừng'\n    ELSE UPPER(ph.status)\n  END AS state\nFROM processed_history ph\nWHERE ph.scan_id = ${scan:raw}\nORDER BY ph.scan_start DESC\nLIMIT 50;",
                "refId": "A"
            }
        ],
        "title": "Dòng thời gian lịch quét",
        "type": "statetimeline"
    }


def history_table() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Bảng tổng hợp lịch sử chạy: thời gian, trạng thái, số máy chủ và tổng phát hiện.",
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "auto", "cellOptions": {"type": "auto"}},
                "mappings": [],
                "thresholds": {"mode": "absolute", "steps": [{"color": "#2ECC71", "value": None}]}
            },
            "overrides": []
        },
        "gridPos": {"h": 7, "w": 10, "x": 14, "y": 16},
        "id": 11,
        "options": {
            "cellHeight": "sm",
            "footer": {"countRows": False, "fields": "", "reducer": [], "show": False},
            "showHeader": True,
            "sortBy": [{"desc": True, "displayName": "history_id"}]
        },
        "pluginVersion": PLUGIN_VERSION,
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": "SELECT\n  ph.history_id,\n  FROM_UNIXTIME(ph.scan_start) AS bat_dau,\n  FROM_UNIXTIME(ph.scan_end) AS ket_thuc,\n  CASE ph.status\n    WHEN 'completed' THEN 'Hoàn thành'\n    WHEN 'running' THEN 'Đang chạy'\n    WHEN 'canceled' THEN 'Đã huỷ'\n    WHEN 'stopped' THEN 'Đã dừng'\n    ELSE UPPER(ph.status)\n  END AS trang_thai,\n  ROUND((ph.scan_end - ph.scan_start) / 60, 1) AS thoi_luong_phut,\n  COUNT(DISTINCT h.host_id) AS so_may_chu,\n  SUM(h.critical + h.high + h.medium + h.low + h.info) AS tong_lo_hong\nFROM processed_history ph\nLEFT JOIN hosts h ON h.scan_id = ph.scan_id AND h.history_id = ph.history_id\nWHERE ph.scan_id = ${scan:raw}\nGROUP BY ph.history_id, ph.scan_start, ph.scan_end, ph.status\nORDER BY ph.history_id DESC\nLIMIT 100;",
                "refId": "A"
            }
        ],
        "title": "Nhật ký lịch sử quét",
        "type": "table"
    }


def host_table() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Chi tiết số lượng phát hiện trên từng máy chủ, giúp khoanh vùng ưu tiên xử lý.",
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "auto", "cellOptions": {"mode": "gradient", "type": "color-text"}},
                "mappings": [],
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "#2ECC71", "value": None},
                        {"color": "#E67E22", "value": 1},
                        {"color": "#E74C3C", "value": 5}
                    ]
                }
            },
            "overrides": [
                {
                    "matcher": {"id": "byName", "options": "hostname"},
                    "properties": [{"id": "custom.width", "value": 220}]
                },
                {
                    "matcher": {"id": "byName", "options": "ip_address"},
                    "properties": [{"id": "custom.width", "value": 150}]
                },
                {
                    "matcher": {"id": "byName", "options": "operating_system"},
                    "properties": [{"id": "custom.width", "value": 220}]
                },
                {
                    "matcher": {"id": "byName", "options": "tong_lo_hong"},
                    "properties": [
                        {"id": "custom.cellOptions", "value": {"mode": "color-background", "type": "color-background"}},
                        {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                            {"color": "#2ECC71", "value": None},
                            {"color": "#F39C12", "value": 50},
                            {"color": "#E67E22", "value": 150},
                            {"color": "#E74C3C", "value": 300}
                        ]}}
                    ]
                }
            ]
        },
        "gridPos": {"h": 9, "w": 14, "x": 0, "y": 24},
        "id": 12,
        "options": {
            "cellHeight": "sm",
            "footer": {"countRows": False, "fields": "", "reducer": [], "show": False},
            "showHeader": True,
            "sortBy": [{"desc": True, "displayName": "tong_lo_hong"}]
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": hosts_query("SELECT hostname, ip_address, operating_system, critical, high, medium, low, info, (critical + high + medium + low + info) AS tong_lo_hong\nFROM filtered_hosts\nORDER BY tong_lo_hong DESC\nLIMIT 200;"),
                "refId": "A"
            }
        ],
        "title": "Bảng mức độ theo máy chủ",
        "type": "table"
    }


def host_priority_chart() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Tổng quan nhanh về số phát hiện nghiêm trọng/cao trên từng máy chủ.",
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {
                    "axisBorderShow": False,
                    "axisCenteredZero": False,
                    "axisColorMode": "text",
                    "axisPlacement": "auto",
                    "barAlignment": 0,
                    "drawStyle": "bars",
                    "fillOpacity": 80,
                    "gradientMode": "scheme",
                    "hideFrom": {"legend": False, "tooltip": False, "viz": False},
                    "stacking": {"group": "A", "mode": "normal"}
                },
                "mappings": []
            },
            "overrides": []
        },
        "gridPos": {"h": 9, "w": 10, "x": 14, "y": 24},
        "id": 13,
        "options": {
            "legend": {"calcs": [], "displayMode": "hidden", "placement": "bottom", "show": False},
            "tooltip": {"mode": "multi", "sort": "desc"},
            "xAxis": {"axisLabel": "Máy chủ", "show": True},
            "yAxis": {"axisLabel": "Số phát hiện", "show": True}
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": hosts_query("SELECT hostname AS metric, SUM(critical + high) AS value\nFROM filtered_hosts\nGROUP BY hostname\nORDER BY value DESC\nLIMIT 15;"),
                "refId": "A"
            }
        ],
        "title": "Máy chủ ưu tiên xử lý",
        "type": "barchart"
    }

def plugin_table() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Danh sách plugin rủi ro cao nhất theo tổng số phát hiện và điểm VPR/EPSS.",
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "auto", "cellOptions": {"type": "auto"}},
                "mappings": [],
                "thresholds": {"mode": "absolute", "steps": [{"color": "#2ECC71", "value": None}]}
            },
            "overrides": [
                {"matcher": {"id": "byName", "options": "plugin_name"}, "properties": [{"id": "custom.width", "value": 260}]},
                {"matcher": {"id": "byName", "options": "plugin_family"}, "properties": [{"id": "custom.width", "value": 200}]}
            ]
        },
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 34},
        "id": 14,
        "options": {
            "cellHeight": "sm",
            "footer": {"countRows": False, "fields": "", "reducer": [], "show": False},
            "showHeader": True,
            "sortBy": [{"desc": True, "displayName": "critical"}]
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": findings_query(
                    "SELECT\n  f.plugin_id,\n  p.plugin_name,\n  p.plugin_family,\n  SUM(f.count) AS tong_phat_hien,\n  SUM(CASE WHEN f.severity = 4 THEN f.count ELSE 0 END) AS critical,\n  SUM(CASE WHEN f.severity = 3 THEN f.count ELSE 0 END) AS high,\n  ROUND(MAX(f.vpr_score), 2) AS vpr_cao_nhat,\n  ROUND(MAX(f.epss_score), 4) AS epss_cao_nhat\nFROM findings f\nJOIN plugins p ON p.plugin_id = f.plugin_id\nWHERE f.scan_id = ${scan:raw}\n  AND f.history_id = ${history:raw}\n  AND ({findings_host_filter})\n  AND (\n    {plugins_category}\n  )\nGROUP BY f.plugin_id, p.plugin_name, p.plugin_family\nHAVING tong_phat_hien > 0\nORDER BY critical DESC, tong_phat_hien DESC\nLIMIT 25;"
                ),
                "refId": "A"
            }
        ],
        "title": "Plugin rủi ro cao nhất",
        "type": "table"
    }


def cve_table() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Các CVE nổi bật được ghi nhận trong bản quét, ưu tiên mức nghiêm trọng và điểm số cao.",
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "auto", "cellOptions": {"type": "auto"}},
                "mappings": [],
                "thresholds": {"mode": "absolute", "steps": [{"color": "#2ECC71", "value": None}]}
            },
            "overrides": [
                {"matcher": {"id": "byName", "options": "cve_id"}, "properties": [{"id": "custom.width", "value": 160}]}
            ]
        },
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 34},
        "id": 15,
        "options": {
            "cellHeight": "sm",
            "footer": {"countRows": False, "fields": "", "reducer": [], "show": False},
            "showHeader": True,
            "sortBy": [{"desc": True, "displayName": "so_lan_xuat_hien"}]
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": findings_query(
                    "SELECT\n  fc.cve_id,\n  MAX(c.cvss_v3) AS cvss_v3,\n  MAX(c.severity) AS muc_do,\n  COUNT(*) AS so_lan_xuat_hien,\n  GROUP_CONCAT(DISTINCT p.plugin_name ORDER BY p.plugin_name SEPARATOR '; ') AS plugin_lien_quan\nFROM finding_cves fc\nJOIN findings f ON f.id = fc.finding_id\nJOIN plugins p ON p.plugin_id = f.plugin_id\nLEFT JOIN cves c ON c.cve_id = fc.cve_id\nWHERE f.scan_id = ${scan:raw}\n  AND f.history_id = ${history:raw}\n  AND ({findings_host_filter})\n  AND (\n    {plugins_category}\n  )\nGROUP BY fc.cve_id\nORDER BY so_lan_xuat_hien DESC, cvss_v3 DESC\nLIMIT 25;"
                ),
                "refId": "A"
            }
        ],
        "title": "CVE trọng yếu",
        "type": "table"
    }


def host_findings_table() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Chi tiết lỗ hổng mức cao & nghiêm trọng theo từng máy chủ, dịch vụ, cổng và output Nessus.",
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "auto", "cellOptions": {"type": "auto"}},
                "mappings": [
                    {
                        "options": {
                            "4": {"color": "#E74C3C", "index": 0, "text": "Nghiêm trọng"},
                            "3": {"color": "#E67E22", "index": 1, "text": "Cao"}
                        },
                        "type": "value"
                    }
                ],
                "thresholds": {"mode": "absolute", "steps": [{"color": "#E67E22", "value": 3}]}
            },
            "overrides": [
                {"matcher": {"id": "byName", "options": "plugin_output"}, "properties": [{"id": "custom.width", "value": 500}]},
                {"matcher": {"id": "byName", "options": "hostname"}, "properties": [{"id": "custom.width", "value": 200}]},
                {"matcher": {"id": "byName", "options": "ip_address"}, "properties": [{"id": "custom.width", "value": 150}]},
                {"matcher": {"id": "byName", "options": "operating_system"}, "properties": [{"id": "custom.width", "value": 220}]}
            ]
        },
        "gridPos": {"h": 10, "w": 24, "x": 0, "y": 42},
        "id": 16,
        "options": {
            "cellHeight": "sm",
            "footer": {"countRows": False, "fields": "", "reducer": [], "show": False},
            "showHeader": True,
            "sortBy": [{"desc": True, "displayName": "severity"}]
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": host_findings_query(
                    "SELECT\n  COALESCE(hf.hostname, fh.hostname) AS hostname,\n  fh.ip_address,\n  fh.operating_system,\n  hf.port,\n  hf.protocol,\n  hf.svc_name,\n  hf.severity,\n  p.plugin_name,\n  p.plugin_family,\n  FROM_UNIXTIME(hf.first_found) AS lan_dau_phat_hien,\n  FROM_UNIXTIME(hf.last_found) AS lan_cuoi_phat_hien,\n  hf.state,\n  hf.plugin_output\nFROM host_findings hf\nJOIN filtered_hosts fh ON fh.scan_id = hf.scan_id AND fh.history_id = hf.history_id AND (hf.host_id = fh.host_id OR (hf.hostname IS NOT NULL AND hf.hostname = fh.hostname))\nJOIN plugins p ON p.plugin_id = hf.plugin_id\nWHERE hf.scan_id = ${scan:raw}\n  AND hf.history_id = ${history:raw}\n  AND hf.severity IN (3, 4)\n  AND ({host_findings_filter})\n  AND (\n    {plugins_category}\n  )\nORDER BY hf.severity DESC, hostname, hf.port;"
                ),
                "refId": "A"
            }
        ],
        "title": "Chi tiết lỗ hổng mức cao & nghiêm trọng",
        "type": "table"
    }


def vulnerability_detail_table() -> Dict[str, Any]:
    return {
        "datasource": datasource(),
        "description": "Bảng tổng hợp đầy đủ mô tả, giải pháp, điểm số và tham chiếu của từng lỗ hổng theo máy chủ.",
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "auto", "cellOptions": {"type": "auto"}},
                "mappings": [
                    {
                        "options": {
                            "4": {"color": "#E74C3C", "index": 0, "text": "Nghiêm trọng"},
                            "3": {"color": "#E67E22", "index": 1, "text": "Cao"},
                            "2": {"color": "#F1C40F", "index": 2, "text": "Trung bình"},
                            "1": {"color": "#3498DB", "index": 3, "text": "Thấp"},
                            "0": {"color": "#95A5A6", "index": 4, "text": "Thông tin"}
                        },
                        "type": "value"
                    }
                ],
                "thresholds": {"mode": "absolute", "steps": [{"color": "#E74C3C", "value": 4}]}
            },
            "overrides": [
                {"matcher": {"id": "byName", "options": "hostname"}, "properties": [{"id": "custom.width", "value": 160}]},
                {"matcher": {"id": "byName", "options": "ip_address"}, "properties": [{"id": "custom.width", "value": 140}]},
                {"matcher": {"id": "byName", "options": "operating_system"}, "properties": [{"id": "custom.width", "value": 200}]},
                {"matcher": {"id": "byName", "options": "plugin_name"}, "properties": [{"id": "custom.width", "value": 240}]},
                {"matcher": {"id": "byName", "options": "synopsis"}, "properties": [{"id": "custom.width", "value": 260}]},
                {"matcher": {"id": "byName", "options": "description"}, "properties": [{"id": "custom.width", "value": 320}]},
                {"matcher": {"id": "byName", "options": "solution"}, "properties": [{"id": "custom.width", "value": 260}]},
                {"matcher": {"id": "byName", "options": "see_also"}, "properties": [{"id": "custom.width", "value": 220}]},
                {"matcher": {"id": "byName", "options": "plugin_output"}, "properties": [{"id": "custom.width", "value": 320}]},
                {"matcher": {"id": "byName", "options": "vpr_drivers"}, "properties": [{"id": "custom.width", "value": 220}]}
            ]
        },
        "gridPos": {"h": 14, "w": 24, "x": 0, "y": 53},
        "id": 17,
        "options": {
            "cellHeight": "sm",
            "footer": {"countRows": False, "fields": "", "reducer": [], "show": False},
            "showHeader": True,
            "sortBy": [{"desc": True, "displayName": "severity"}]
        },
        "targets": [
            {
                "datasource": datasource(),
                "format": "table",
                "rawSql": host_findings_query(
                    "SELECT\n  COALESCE(hf.hostname, fh.hostname) AS hostname,\n  fh.ip_address,\n  fh.operating_system,\n  hf.severity,\n  hf.plugin_id,\n  MAX(p.plugin_name) AS plugin_name,\n  MAX(p.plugin_family) AS plugin_family,\n  MAX(p.plugin_type) AS plugin_type,\n  MAX(p.plugin_version) AS plugin_version,\n  MAX(p.risk_factor) AS risk_factor,\n  ROUND(MAX(agg.vpr_score), 2) AS vpr_score,\n  ROUND(MAX(agg.epss_score), 4) AS epss_score,\n  MAX(p.cvss2_base_score) AS cvss2_base_score,\n  MAX(p.cvss2_vector) AS cvss2_vector,\n  MAX(p.cvss3_base_score) AS cvss3_base_score,\n  MAX(p.cvss3_vector) AS cvss3_vector,\n  FROM_UNIXTIME(MAX(p.plugin_publication_date)) AS plugin_phat_hanh,\n  FROM_UNIXTIME(MAX(p.plugin_modification_date)) AS plugin_cap_nhat,\n  FROM_UNIXTIME(MAX(p.vulnerability_publication_date)) AS lo_hong_cong_bo,\n  MAX(p.synopsis) AS synopsis,\n  MAX(p.description) AS description,\n  MAX(p.solution) AS solution,\n  MAX(p.see_also) AS see_also,\n  MAX(p.cwe) AS cwe,\n  MAX(agg.cve_lien_quan) AS cve_lien_quan,\n  MAX(p.vpr_drivers) AS vpr_drivers,\n  hf.port,\n  hf.protocol,\n  hf.svc_name,\n  hf.plugin_output\nFROM host_findings hf\nJOIN filtered_hosts fh ON fh.scan_id = hf.scan_id AND fh.history_id = hf.history_id AND (hf.host_id = fh.host_id OR (hf.hostname IS NOT NULL AND hf.hostname = fh.hostname))\nJOIN plugins p ON p.plugin_id = hf.plugin_id\nLEFT JOIN (\n  SELECT\n    f.scan_id,\n    f.history_id,\n    f.plugin_id,\n    MAX(f.vpr_score) AS vpr_score,\n    MAX(f.epss_score) AS epss_score,\n    GROUP_CONCAT(DISTINCT fc.cve_id ORDER BY fc.cve_id SEPARATOR '; ') AS cve_lien_quan\n  FROM findings f\n  LEFT JOIN finding_cves fc ON fc.finding_id = f.id\n  WHERE f.hostname IS NULL\n  GROUP BY f.scan_id, f.history_id, f.plugin_id\n) agg ON agg.scan_id = hf.scan_id AND agg.history_id = hf.history_id AND agg.plugin_id = hf.plugin_id\nWHERE hf.scan_id = ${scan:raw}\n  AND hf.history_id = ${history:raw}\n  AND ({host_findings_filter})\n  AND (\n    {plugins_category}\n  )\nGROUP BY hostname, fh.ip_address, fh.operating_system, hf.severity, hf.plugin_id, hf.port, hf.protocol, hf.svc_name, hf.plugin_output\nORDER BY hf.severity DESC, hostname, hf.plugin_id, hf.port\nLIMIT 300;"
                ),
                "refId": "A"
            }
        ],
        "title": "Thông tin chi tiết từng lỗ hổng",
        "type": "table"
    }


def build_panels() -> List[Dict[str, Any]]:
    panels: List[Dict[str, Any]] = []
    panels.append(row_panel(100, "Tổng quan điều hành", 0))
    panels.extend(build_summary_panels())
    panels.append(row_panel(101, "Phân bổ rủi ro", 5))
    panels.extend([pie_panel(), stacked_host_bar(), severity_trend()])
    panels.append(row_panel(102, "Lịch chạy & tiến độ", 15))
    panels.extend([timeline_panel(), history_table()])
    panels.append(row_panel(103, "Phân tích theo máy chủ", 23))
    panels.extend([host_table(), host_priority_chart()])
    panels.append(row_panel(104, "Chi tiết lỗ hổng & CVE", 33))
    panels.extend([plugin_table(), cve_table(), host_findings_table()])
    panels.append(row_panel(105, "Thông tin chi tiết từng lỗ hổng", 52))
    panels.append(vulnerability_detail_table())
    return panels


def build_dashboard() -> Dict[str, Any]:
    return {
        "__inputs": [
            {
                "name": "DS_MYSQL_NESSUS",
                "label": "mysql_nessus",
                "description": "",
                "type": "datasource",
                "pluginId": "mysql",
                "pluginName": "MySQL"
            }
        ],
        "__elements": {},
        "__requires": [
            {"type": "grafana", "id": "grafana", "name": "Grafana", "version": "11.2.0"},
            {"type": "datasource", "id": "mysql", "name": "MySQL", "version": "11.2.0"},
            {"type": "panel", "id": "row", "name": "Row", "version": ""},
            {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
            {"type": "panel", "id": "piechart", "name": "Pie chart", "version": ""},
            {"type": "panel", "id": "barchart", "name": "Bar chart", "version": ""},
            {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
            {"type": "panel", "id": "statetimeline", "name": "State timeline", "version": ""},
            {"type": "panel", "id": "table", "name": "Table", "version": ""}
        ],
        "annotations": {
            "list": [
                {
                    "builtIn": 1,
                    "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                    "enable": True,
                    "hide": True,
                    "iconColor": "rgba(0, 211, 255, 1)",
                    "name": "Chú thích & Cảnh báo",
                    "type": "dashboard"
                }
            ]
        },
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 0,
        "links": [],
        "liveNow": False,
        "panels": build_panels(),
        "refresh": "30s",
        "schemaVersion": 39,
        "tags": ["nessus", "mysql", "vulnerability"],
        "templating": {
            "list": [
                {
                    "current": {},
                    "datasource": datasource(),
                    "definition": "",
                    "hide": 0,
                    "includeAll": False,
                    "label": "Bản quét",
                    "multi": False,
                    "name": "scan",
                    "options": [],
                    "query": "SELECT DISTINCT scan_id AS __value, CONCAT(scan_id, ' - ', MAX(scan_name)) AS __text FROM processed_history GROUP BY scan_id ORDER BY scan_id DESC;",
                    "refresh": 1,
                    "regex": "",
                    "skipUrlSync": False,
                    "sort": 0,
                    "type": "query"
                },
                {
                    "current": {},
                    "datasource": datasource(),
                    "definition": "",
                    "hide": 0,
                    "includeAll": False,
                    "label": "Lịch sử",
                    "multi": False,
                    "name": "history",
                    "options": [],
                    "query": "SELECT history_id AS __value, CONCAT(history_id, ' (', status, ')') AS __text FROM processed_history WHERE scan_id=${scan:raw} ORDER BY history_id DESC;",
                    "refresh": 1,
                    "regex": "",
                    "skipUrlSync": False,
                    "sort": 0,
                    "type": "query"
                },
                {
                    "current": {},
                    "datasource": datasource(),
                    "definition": "",
                    "hide": 2,
                    "includeAll": True,
                    "label": "Máy chủ (bộ lọc tùy chọn)",
                    "multi": True,
                    "name": "host",
                    "options": [],
                    "query": "SELECT DISTINCT hostname AS __text, hostname AS __value FROM hosts WHERE scan_id=${scan:raw} AND history_id=${history:raw} ORDER BY hostname;",
                    "refresh": 1,
                    "regex": "",
                    "skipUrlSync": False,
                    "sort": 0,
                    "type": "query"
                },
                {
                    "current": {},
                    "datasource": datasource(),
                    "definition": "",
                    "hide": 0,
                    "includeAll": True,
                    "label": "Địa chỉ IP",
                    "multi": True,
                    "name": "ip",
                    "options": [],
                    "query": "SELECT DISTINCT ip_address AS __text, ip_address AS __value FROM hosts WHERE scan_id=${scan:raw} AND history_id=${history:raw} AND ip_address IS NOT NULL AND ip_address <> '' ORDER BY ip_address;",
                    "refresh": 1,
                    "regex": "",
                    "skipUrlSync": False,
                    "sort": 0,
                    "type": "query"
                },
                {
                    "current": {},
                    "datasource": datasource(),
                    "definition": "",
                    "hide": 0,
                    "includeAll": True,
                    "label": "Hệ điều hành",
                    "multi": True,
                    "name": "os_filter",
                    "options": [],
                    "query": "SELECT DISTINCT operating_system AS __text, operating_system AS __value FROM hosts WHERE scan_id=${scan:raw} AND history_id=${history:raw} AND operating_system IS NOT NULL AND operating_system <> '' ORDER BY operating_system;",
                    "refresh": 1,
                    "regex": "",
                    "skipUrlSync": False,
                    "sort": 0,
                    "type": "query"
                },
                {
                    "current": {"selected": True, "text": "Tất cả", "value": "tatca"},
                    "hide": 0,
                    "includeAll": False,
                    "label": "Loại hiển thị",
                    "multi": False,
                    "name": "phan_loai",
                    "options": [
                        {"selected": True, "text": "Tất cả", "value": "tatca"},
                        {"selected": False, "text": "Web", "value": "web"},
                        {"selected": False, "text": "Hệ điều hành", "value": "os"}
                    ],
                    "query": "tatca,web,os",
                    "queryValue": "",
                    "refresh": 0,
                    "skipUrlSync": False,
                    "sort": 0,
                    "type": "custom"
                }
            ]
        },
        "time": {"from": "now-30d", "to": "now"},
        "timepicker": {},
        "timezone": "browser",
        "title": "Tổng quan Lỗ hổng Nessus (MySQL) - Chuyên nghiệp",
        "uid": "nessus-mysql-dashboard-pro",
        "version": 1,
        "weekStart": ""
    }


def main() -> None:
    dashboard = build_dashboard()
    output_path = Path(__file__).resolve().parent.parent / "Nessus Vulnerability Professional (MySQL).json"
    output_path.write_text(json.dumps(dashboard, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
