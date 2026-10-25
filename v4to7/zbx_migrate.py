#!/usr/bin/env python3
"""
Миграция Zabbix 4.4 -> 7.2 через API в два этапа (без истории и трендов).

Этап 1 — prepare (подключается к 4.4 и 7.2, в 7.2 НИЧЕГО не меняет):
  сравнивает 4.4 с 7.2 и готовит пакет:
    package/manifest.json        — план: что импортировать (флаги "import"/"apply" можно править)
    package/templates/*.json     — выгрузки шаблонов (только отсутствующих в 7.2)
    package/hosts/*.json         — выгрузки узлов (только отсутствующих в 7.2)
    package/drules/*.json        — правила сетевого обнаружения
    package/actions/*.json       — действия, ссылки на объекты — по ИМЕНАМ, а не ID
    package/*.csv                — таблицы сравнения для просмотра в Excel (с колонкой «что сделать»)
    package/problems.csv         — всё, что НЕ перенесётся, и предупреждения: причина + что сделать
  Сравнение:
    шаблоны   — есть ли в 7.2 по имени; замены через template_map;
    узлы      — есть ли в 7.2 по имени или по IP/DNS (под другим именем);
                для существующих — каких шаблонов и групп не хватает;
    обнаружение — правила сетевого обнаружения: по имени и по диапазону IP
                (LLD-правила переносятся в составе шаблонов и узлов);
    способы   — есть ли в 7.2 (по имени или media_type_map) -> подключить существующий;
    действия  — есть ли по имени; есть ли дубль с теми же условиями под другим именем;
                какие действия 7.2 уже работают на те же группы/узлы/шаблоны.

Этап 2 — apply (подключается только к 7.2):
  импортирует пакет в порядке: шаблоны -> узлы -> дополнение существующих узлов ->
  пустые группы для действий -> правила обнаружения -> способы оповещения -> действия.
  Код возврата 1, если были ошибки. В конце — сводка «что не перенесено и что сделать»
  (включая отсеянное при prepare): package/apply_problems_<время>.csv.

Требуется Python 3.8+ и пакет requests. Всё, что уже есть в 7.2, пропускается — ничего не перезаписывается.

Перед каждым этапом скрипт показывает рекомендации отдельно для старого (4.4) и нового (7.2)
сервера и просит подтвердить каждый блок ответом «да»; ключ --yes отключает вопросы.

  python3 zbx_migrate.py prepare -c config.json -p package
  (проверить package/*.csv, при необходимости поправить package/manifest.json)
  python3 zbx_migrate.py apply   -c config.json -p package --dry-run
  python3 zbx_migrate.py apply   -c config.json -p package
"""
import argparse
import csv
import json
import logging
import os
import re
import shutil
import sys
from collections import Counter
from datetime import datetime

import requests
import urllib3

log = logging.getLogger("zbx_migrate")

CMU = {"createMissing": True, "updateExisting": False, "deleteMissing": False}

TEMPLATE_RULES = {
    "template_groups": {"createMissing": True, "updateExisting": False},
    "host_groups": {"createMissing": True, "updateExisting": False},
    "templates": {"createMissing": True, "updateExisting": False},
    "templateLinkage": {"createMissing": True, "deleteMissing": False},
    "items": CMU, "triggers": CMU, "graphs": CMU, "discoveryRules": CMU,
    "httptests": CMU, "valueMaps": CMU, "templateDashboards": CMU,
}

HOST_RULES = {
    "host_groups": {"createMissing": True, "updateExisting": False},
    "hosts": {"createMissing": True, "updateExisting": False},
    "templateLinkage": {"createMissing": True, "deleteMissing": False},
    "items": CMU, "triggers": CMU, "graphs": CMU, "discoveryRules": CMU,
    "httptests": CMU, "valueMaps": CMU,
}

# kind -> (src_method, src_id, src_name, dst_method, dst_id, dst_name)
KINDS = {
    "hostgroup": ("hostgroup.get", "groupid", "name", "hostgroup.get", "groupid", "name"),
    "host":      ("host.get", "hostid", "host", "host.get", "hostid", "host"),
    "template":  ("template.get", "templateid", "host", "template.get", "templateid", "host"),
    "user":      ("user.get", "userid", "alias", "user.get", "userid", "username"),
    "usergroup": ("usergroup.get", "usrgrpid", "name", "usergroup.get", "usrgrpid", "name"),
    "proxy":     ("proxy.get", "proxyid", "host", "proxy.get", "proxyid", "name"),
    "drule":     ("drule.get", "druleid", "name", "drule.get", "druleid", "name"),
    "mediatype": (None, None, None, "mediatype.get", "mediatypeid", "name"),
}
KIND_RU = {"hostgroup": "группа узлов", "host": "узел", "template": "шаблон",
           "user": "пользователь", "usergroup": "группа пользователей", "proxy": "прокси",
           "drule": "правило обнаружения", "mediatype": "способ оповещения"}
COND_KINDS = {0: "hostgroup", 1: "host", 13: "template", 18: "drule", 20: "proxy"}
SCOPE_TYPES = {0, 1, 13}  # условия «на что» действует: группа, узел, шаблон
ES_NAMES = {0: "триггеры", 1: "обнаружение", 2: "авторегистрация", 3: "внутренние"}
IGNORE_ADDR = {"127.0.0.1", "0.0.0.0", "::1", "localhost"}
STEPS = ("templates", "hosts", "existing", "hostgroups", "drules", "mediatypes", "actions")
PACKAGE_DIRS = ("templates", "hosts", "drules", "actions", "raw")
SCRIPT_FIELDS = ("type", "command", "execute_on", "port", "authtype", "username",
                 "password", "publickey", "privatekey")
DCHECK_TYPES = {0: "SSH", 1: "LDAP", 2: "SMTP", 3: "FTP", 4: "HTTP", 5: "POP", 6: "NNTP",
                7: "IMAP", 8: "TCP", 9: "Zabbix agent", 10: "SNMPv1", 11: "SNMPv2c",
                12: "ICMP", 13: "SNMPv3", 14: "HTTPS", 15: "Telnet"}
SNMPV3_FIELDS = ("snmpv3_securityname", "snmpv3_securitylevel", "snmpv3_authpassphrase",
                 "snmpv3_privpassphrase", "snmpv3_authprotocol", "snmpv3_privprotocol",
                 "snmpv3_contextname")


class ZabbixError(Exception):
    pass


class Unmappable(Exception):
    """Объект нельзя перенести без потери смысла: причина + что сделать."""

    def __init__(self, reason, fix=""):
        super().__init__(reason)
        self.fix = fix


NOT_MIGRATED = "НЕ ПЕРЕНЕСЕНО"
WARNING = "ПРЕДУПРЕЖДЕНИЕ"
RERUN = "затем повторите prepare с --force"

# типичные ошибки, которые возвращает Zabbix 7.2, -> что сделать (порядок важен: от частного к общему)
ADVICE = [
    (r"visible name", "Видимое имя уже занято другим узлом 7.2: переименуйте узел в 4.4 или в 7.2, " + RERUN + "."),
    (r"[Ii]tem with key .* already exists|key .* already exists on",
     "Конфликт ключей элементов данных: на узле/шаблоне уже есть элемент с тем же ключом из другого шаблона. "
     "Оставьте один из шаблонов (template_map) или удалите дублирующий элемент, затем повторите apply."),
    (r"[Cc]annot link template|[Cc]annot inherit|link.*template",
     "Шаблон нельзя привязать (конфликт элементов/триггеров с уже привязанными шаблонами). "
     "Сравните шаблоны, оставьте один из них и повторите apply."),
    (r"already exists|value must be unique|is not unique",
     "Объект с таким именем уже есть в 7.2 (создан вручную или другим запуском). Сравните его с переносимым; "
     "если нужен перенесённый — удалите/переименуйте существующий и повторите apply, иначе ничего не делайте."),
    (r"does not exist|[Nn]ot found|[Cc]annot find|missing|[Nn]o such",
     "Не найден связанный объект (шаблон, группа, прокси, способ оповещения): проверьте, что он создался на "
     "предыдущем шаге apply (ошибки по нему — в этом же отчёте) или есть в 7.2, затем повторите apply."),
    (r"[Pp]roxy",
     "Прокси не найден в 7.2: создайте прокси 7.2 с тем же именем или задайте proxy_map/drop_missing_proxy, " + RERUN + "."),
    (r"[Tt]rigger expression|[Ii]ncorrect trigger|[Ii]nvalid expression|[Ii]ncorrect expression",
     "Выражение триггера не сконвертировалось: исправьте триггер в шаблоне/узле 4.4 (или в файле пакета) и повторите."),
    (r"[Nn]o permissions|[Nn]ot authori[sz]ed|[Pp]ermission denied|[Ss]ession terminated",
     "Недостаточно прав у пользователя API 7.2: используйте токен пользователя с типом «Супер-администратор»."),
    (r"[Aa]llowed memory size|memory",
     "Не хватило памяти PHP: увеличьте memory_limit на веб-сервере 7.2 (1G для больших шаблонов) и повторите apply."),
    (r"413|[Ee]ntity [Tt]oo [Ll]arge",
     "Слишком большой запрос: увеличьте post_max_size (PHP) и client_max_body_size (nginx) на 7.2 и повторите apply."),
    (r"ошибка HTTP/сети|[Tt]imed? ?out|[Cc]onnection|50[234]",
     "Сеть или таймаут: проверьте доступность 7.2, увеличьте max_execution_time (PHP) и fastcgi_read_timeout (nginx), "
     "повторите apply — уже созданное будет пропущено."),
    (r"[Ii]nvalid parameter|[Ii]ncorrect value|[Uu]nexpected parameter|cannot be empty|must be",
     "7.2 не принял значение после конвертации: исправьте указанное в ошибке поле в файле пакета (или в 4.4 и "
     "повторите prepare --force), затем повторите apply; либо перенесите объект вручную."),
]


def advise(error, file=""):
    text = str(error)
    for pattern, fix in ADVICE:
        if re.search(pattern, text):
            break
    else:
        fix = ("Разберите текст ошибки; исправьте объект в 4.4 (и повторите prepare --force) или в файле пакета, "
               "затем повторите apply — уже созданное будет пропущено. При необходимости перенесите вручную.")
    return fix + (f" Файл пакета: {file}" if file else "")


class ZabbixAPI:
    def __init__(self, name, url, user=None, password=None, token=None,
                 verify=True, legacy=False):
        self.name, self.url, self.verify, self.legacy = name, url, verify, legacy
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.s = requests.Session()
        self.s.headers["Content-Type"] = "application/json-rpc"
        self.auth = None
        self.id = 0
        if token and not legacy:
            self.s.headers["Authorization"] = f"Bearer {token}"
        else:
            key = "user" if legacy else "username"
            sid = self.call("user.login", {key: user, "password": password}, auth=False)
            if legacy:
                self.auth = sid
            else:
                self.s.headers["Authorization"] = f"Bearer {sid}"
        self.version = self.call("apiinfo.version", auth=False)
        log.info("[%s] подключено, версия API %s", name, self.version)

    def call(self, method, params=None, auth=True):
        self.id += 1
        body = {"jsonrpc": "2.0", "method": method,
                "params": {} if params is None else params, "id": self.id}
        if auth and self.legacy and self.auth:
            body["auth"] = self.auth
        # apiinfo.version / user.login не принимают авторизацию; None убирает заголовок сессии
        hdrs = None if auth else {"Authorization": None}
        try:
            r = self.s.post(self.url, json=body, verify=self.verify, timeout=600, headers=hdrs)
            r.raise_for_status()
            data = r.json()
        except (requests.RequestException, ValueError) as e:
            raise ZabbixError(f"[{self.name}] {method}: ошибка HTTP/сети: {e}") from e
        if "error" in data:
            e = data["error"]
            raise ZabbixError(f"[{self.name}] {method}: {e.get('message')} {e.get('data')}")
        return data["result"]


# ---------- файлы ----------
def save_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_csv(path, rows):
    if not rows:
        return
    fields = []
    for r in rows:
        fields += [k for k in r if k not in fields]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig — кириллица в Excel
        w = csv.DictWriter(f, fieldnames=fields, delimiter=";")
        w.writeheader()
        w.writerows(rows)
    log.info("таблица: %s", path)


def safe_name(s):
    return re.sub(r"[^\w.-]+", "_", s, flags=re.UNICODE)[:80]


def j(items):
    return ", ".join(items)


def match_dcheck(dchecks, dtype, ports, key):
    """Найти проверку обнаружения по типу/портам/ключу (у ICMP порты не учитываются)."""
    for c in dchecks:
        if (int(c["type"]) == dtype and (c.get("key_") or "") == (key or "")
                and (dtype == 12 or (c.get("ports") or "") == (ports or ""))):
            return c["dcheckid"]
    return None


def script_name(name):
    # в 6.0+ "/" в имени скрипта — это путь меню (menu_path), в имени он недопустим
    return name.replace("/", "-")


class Base:
    def __init__(self, cfg, dst, pkg):
        self.cfg, self.dst, self.pkg = cfg, dst, pkg
        self._dst_cache = {}
        self.problems = []

    def problem(self, level, typ, obj, reason, fix):
        self.problems.append({"уровень": level, "тип": typ, "объект": obj,
                              "причина": reason, "что сделать": fix})

    def report_problems(self, fname, title, limit=40):
        """Сводка «что не перенесено и что сделать»: в консоль (первые limit) и полностью в CSV."""
        path = self.path(fname)
        if os.path.exists(path):
            os.remove(path)
        if not self.problems:
            print(f"\n{title}: проблем нет.")
            return
        save_csv(path, self.problems)
        lv = Counter(p["уровень"] for p in self.problems)
        print(f"\n{'#' * 78}\n {title}: {NOT_MIGRATED.lower()} {lv.get(NOT_MIGRATED, 0)}, "
              f"предупреждений {lv.get(WARNING, 0)}\n{'#' * 78}")
        ordered = sorted(self.problems, key=lambda p: (p["уровень"] != NOT_MIGRATED, p["тип"]))
        for p in ordered[:limit]:
            print(f"[{p['уровень']}] {p['тип']} '{p['объект']}'\n"
                  f"    причина:     {p['причина']}\n"
                  f"    что сделать: {p['что сделать']}")
        if len(ordered) > limit:
            print(f"... и ещё {len(ordered) - limit}.")
        print(f"Полный список с причинами и рекомендациями: {path}")

    def dst_ids(self, kind):
        if kind not in self._dst_cache:
            m, i, n = KINDS[kind][3:]
            self._dst_cache[kind] = {r[n]: r[i] for r in self.dst.call(m, {"output": [i, n]})}
        return self._dst_cache[kind]

    def dst_rev(self, kind):
        return {v: k for k, v in self.dst_ids(kind).items()}

    def drop_cache(self, *kinds):
        for k in kinds:
            self._dst_cache.pop(k, None)

    def path(self, rel):
        return os.path.join(self.pkg, rel)


# =====================================================================
#  ЭТАП 1: prepare
# =====================================================================
class Preparer(Base):
    def __init__(self, cfg, src, dst, pkg):
        super().__init__(cfg, dst, pkg)
        self.src = src
        self.tmap = cfg.get("template_map", {})          # 4.4 имя -> 7.2 имя ("" = отвязать)
        self.mt_name_map = cfg.get("media_type_map", {})  # 4.4 имя -> существующее в 7.2
        self.proxy_map = cfg.get("proxy_map", {})
        self.host_alias = {}   # имя узла 4.4 -> имя того же узла в 7.2 (найден по адресу)
        self.drule_alias = {}  # правило 4.4 -> правило 7.2 с тем же диапазоном
        self.dst_visible = {}  # видимое имя -> техническое имя узла в 7.2
        self.planned = {k: set() for k in KINDS}
        self._src_cache = {}
        self.mt_plan = {}      # src mediatypeid -> имя в 7.2 (None = перенести нельзя)
        self._notes = []
        self._note_fixes = []
        self._pending_groups = []
        self._src_dchecks = None
        self._dst_users = None
        self.rows = {"templates": [], "hosts": [], "drules": [], "mediatypes": [], "actions": []}
        self.manifest = {
            "prepared_at": datetime.now().isoformat(timespec="seconds"),
            "src_url": cfg["src"]["url"], "dst_url": cfg["dst"]["url"],
            "templates": [], "hosts": [], "existing_hosts": [], "hostgroups": [], "drules": [],
            "mediatypes": [], "actions": [],
        }

    def src_names(self, kind):
        if kind not in self._src_cache:
            m, i, n = KINDS[kind][:3]
            self._src_cache[kind] = {r[i]: r[n] for r in self.src.call(m, {"output": [i, n]})}
        return self._src_cache[kind]

    def export(self, what, ids):
        raw = self.src.call("configuration.export", {"format": "json", "options": {what: list(ids)}})
        return json.loads(raw)

    def remap_links(self, exp):
        ze = exp["zabbix_export"]
        for key in ("templates", "hosts"):
            for obj in ze.get(key) or []:
                links = obj.get("templates")
                if not links:
                    continue
                new, seen = [], set()
                for l in links:
                    n = self.tmap.get(l["name"], l["name"])
                    if n and n not in seen:
                        new.append({"name": n})
                        seen.add(n)
                obj["templates"] = new

    def mapped_templates(self, h):
        res = []
        for p in h["parentTemplates"]:
            n = self.tmap.get(p["host"], p["host"])
            if n and n not in res:
                res.append(n)
        return res

    # ----- ссылки по имени -----
    def ref(self, kind, src_id):
        sname = self.src_names(kind).get(str(src_id))
        if sname is None:
            raise Unmappable(f"{KIND_RU[kind]} id={src_id} не найден в 4.4 (удалён, но остался в действии)",
                             "Исправьте действие в 4.4 (уберите ссылку на удалённый объект) и " + RERUN +
                             ", либо создайте действие в 7.2 вручную.")
        dname = sname
        if kind == "template":
            dname = self.tmap.get(sname, sname)
            if not dname:
                raise Unmappable(f"шаблон '{sname}' в template_map помечен как отвязываемый (\"\")",
                                 f"Укажите в template_map шаблон 7.2 на замену '{sname}' вместо \"\", " + RERUN + ".")
        elif kind == "proxy":
            dname = self.proxy_map.get(sname, sname)
        elif kind == "host":
            dname = self.host_alias.get(sname, sname)
        elif kind == "drule":
            dname = self.drule_alias.get(sname, sname)
        if dname in self.dst_ids(kind) or dname in self.planned[kind]:
            return {"$ref": kind, "name": dname}
        if kind == "hostgroup" and self.cfg.get("create_missing_groups", True):
            # группа есть в 4.4, но в 7.2 её нет и с узлами она не приедет — создадим пустую
            self.planned["hostgroup"].add(dname)
            self._pending_groups.append(dname)
            return {"$ref": kind, "name": dname}
        raise Unmappable(f"{KIND_RU[kind]} '{dname}' нет в 7.2 и не переносится", self.missing_fix(kind, dname))

    def missing_fix(self, kind, name):
        fixes = {
            "host": f"Узел '{name}' не переносится — причина в problems.csv / hosts.csv; устраните её, {RERUN}.",
            "template": f"Добавьте '{name}' в extra_templates или укажите замену в template_map, {RERUN}.",
            "proxy": f"Создайте в 7.2 прокси '{name}' (версии 7.2) или задайте proxy_map, {RERUN}.",
            "drule": f"Правило '{name}' не переносится — причина в drules.csv; устраните её "
                     f"(например, skip_drules_same_range: false), {RERUN}.",
            "hostgroup": f"Создайте группу узлов '{name}' в 7.2 или включите create_missing_groups: true, {RERUN}.",
            "user": f"Создайте в 7.2 пользователя '{name}' (с медиа), {RERUN}; или добавьте получателя вручную после apply.",
            "usergroup": f"Создайте в 7.2 группу пользователей '{name}' с участниками, {RERUN}; "
                         f"или добавьте получателя вручную после apply.",
        }
        return fixes.get(kind, f"Создайте '{name}' в 7.2, {RERUN}.")

    def dst_triggers(self, host, desc):
        return self.dst.call("trigger.get", {"output": ["triggerid"], "host": host,
                                             "filter": {"description": desc}})

    def trigger_ref(self, tid):
        q = {"output": ["description", "templateid"], "selectHosts": ["host"]}
        r = self.src.call("trigger.get", dict(q, triggerids=[tid]))
        if not r or not r[0]["hosts"]:
            raise Unmappable(f"триггер id={tid} не найден в 4.4 (удалён, но остался в действии)",
                             "Исправьте условие действия в 4.4 и " + RERUN + ".")
        desc, host = r[0]["description"], r[0]["hosts"][0]["host"]
        root, t = None, r[0]  # шаблон, из которого изначально унаследован триггер
        for _ in range(20):
            if str(t.get("templateid") or "0") == "0":
                break
            p = self.src.call("trigger.get", dict(q, triggerids=[t["templateid"]]))
            if not p or not p[0]["hosts"]:
                break
            t, root = p[0], p[0]["hosts"][0]["host"]
        if host in self.tmap:
            if not self.tmap[host]:
                raise Unmappable(f"триггер '{desc}' на шаблоне '{host}', который отвязывается (template_map: \"\")",
                                 f"Укажите в template_map замену для '{host}', {RERUN}; либо создайте действие вручную.")
            host = self.tmap[host]
        else:
            host = self.host_alias.get(host, host)
        ref = {"$ref": "trigger", "host": host, "description": desc}
        if self.dst_triggers(host, desc):
            return ref
        if host not in self.planned["host"] and host not in self.planned["template"]:
            raise Unmappable(f"триггер '{desc}' на '{host}' нет в 7.2",
                             f"Создайте действие в 7.2 вручную, выбрав нужный триггер на '{host}', либо замените в 4.4 "
                             f"условие «Триггер» на «Имя события»/тег и {RERUN}.")
        if root in self.tmap:  # узел приедет, но этот шаблон на нём заменяется новым
            tgt = self.tmap[root]
            if not tgt or not self.dst_triggers(tgt, desc):
                raise Unmappable(f"триггер '{desc}' из шаблона '{root}', который заменяется на "
                                 f"'{tgt or '—'}', а там такого триггера нет",
                                 f"В новом шаблоне триггеры называются иначе: после apply создайте действие в 7.2 "
                                 f"вручную, выбрав аналогичный триггер, или используйте условие по тегу/имени события.")
        return ref

    def dcheck_ref(self, dcheckid):
        if self._src_dchecks is None:
            self._src_dchecks = {}
            for r in self.src.call("drule.get", {"output": ["name"], "selectDChecks": "extend"}):
                for c in r["dchecks"]:
                    self._src_dchecks[c["dcheckid"]] = (r["name"], c)
        if str(dcheckid) not in self._src_dchecks:
            raise Unmappable(f"проверка обнаружения id={dcheckid} не найдена в 4.4",
                             "Исправьте условие действия в 4.4 и " + RERUN + ".")
        sn, c = self._src_dchecks[str(dcheckid)]
        dn = self.drule_alias.get(sn, sn)
        ref = {"$ref": "dcheck", "drule": dn, "type": int(c["type"]),
               "ports": c.get("ports") or "", "key_": c.get("key_") or ""}
        if dn in self.planned["drule"]:
            return ref
        if dn in self.dst_ids("drule"):
            d = self.dst.call("drule.get", {"output": ["name"], "selectDChecks": "extend",
                                            "filter": {"name": dn}})
            if d and match_dcheck(d[0]["dchecks"], ref["type"], ref["ports"], ref["key_"]):
                return ref
            chk = f"{DCHECK_TYPES.get(ref['type'], ref['type'])} {ref['ports']} {ref['key_']}".rstrip()
            raise Unmappable(f"в правиле 7.2 '{dn}' нет проверки {chk}",
                             f"Добавьте в правило 7.2 '{dn}' проверку {chk} и {RERUN}; либо создайте действие вручную.")
        raise Unmappable(f"правило обнаружения '{dn}' нет в 7.2 и не переносится", self.missing_fix("drule", dn))

    @staticmethod
    def key_of(v):
        if isinstance(v, dict) and "$ref" in v:
            if v["$ref"] == "trigger":
                return f"trigger:{v['host']}:{v['description']}"
            if v["$ref"] == "dcheck":
                return f"dcheck:{v['drule']}:{v['type']}:{v['ports']}:{v['key_']}"
            return f"{v['$ref']}:{v['name']}"
        return str(v)

    # ----- узлы 4.4 и 7.2 -----
    def load_src_hosts(self):
        p = {"output": ["hostid", "host", "name", "flags", "status"],
             "selectParentTemplates": ["templateid", "host"],
             "selectGroups": ["name"], "selectInterfaces": ["ip", "dns"]}
        if self.cfg.get("host_groups"):
            g = self.src.call("hostgroup.get", {"output": ["groupid", "name"],
                                                "filter": {"name": self.cfg["host_groups"]}})
            missing = set(self.cfg["host_groups"]) - {x["name"] for x in g}
            if missing:  # пустой groupids API может трактовать как «без фильтра»
                raise SystemExit(f"Группы из host_groups не найдены в 4.4: {sorted(missing)}")
            p["groupids"] = [x["groupid"] for x in g]
        if self.cfg.get("hosts"):
            p["filter"] = {"host": self.cfg["hosts"]}
        hosts = [h for h in self.src.call("host.get", p) if str(h["flags"]) != "4"]
        log.info("узлов 4.4 в выборке: %d (обнаруженные LLD не переносятся)", len(hosts))
        return hosts

    def load_dst_hosts(self):
        rows = self.dst.call("host.get", {"output": ["hostid", "host", "name"],
                                          "selectParentTemplates": ["host"],
                                          "selectHostGroups": ["name"],
                                          "selectInterfaces": ["ip", "dns"]})
        by_name, by_addr = {h["host"]: h for h in rows}, {}
        self.dst_visible = {h.get("name") or h["host"]: h["host"] for h in rows}
        for h in rows:
            for i in h["interfaces"]:
                for a in (i.get("ip"), i.get("dns")):
                    if a and a not in IGNORE_ADDR:
                        by_addr.setdefault(a, set()).add(h["host"])
        return by_name, by_addr

    def classify_hosts(self, hosts):
        by_name, by_addr = self.load_dst_hosts()
        taken = {h["host"]: h["host"] for h in hosts if h["host"] in by_name}  # узел 7.2 -> узел 4.4
        new, existing = [], []
        for h in hosts:
            d, how, note = by_name.get(h["host"]), "по имени", ""
            if not d and self.cfg.get("match_hosts_by_ip", True):
                cands = set()
                for i in h["interfaces"]:
                    for a in (i.get("ip"), i.get("dns")):
                        if a and a not in IGNORE_ADDR:
                            cands |= by_addr.get(a, set())
                free = cands - set(taken)
                if len(free) == 1:
                    dn = free.pop()
                    d, how = by_name[dn], f"по адресу, в 7.2 называется '{dn}'"
                    self.host_alias[h["host"]] = dn
                    taken[dn] = h["host"]
                elif free:
                    note = f"адрес совпадает с несколькими узлами 7.2: {j(sorted(free))} — проверьте"
                elif cands:
                    note = (f"адрес совпадает с узлом 7.2 {j(sorted(cands))}, который уже сопоставлен "
                            f"с '{taken[sorted(cands)[0]]}' — проверьте, не дубль ли")
            if d:
                existing.append((h, d, how))
            else:
                new.append((h, note))
        log.info("узлы: новых %d, уже есть в 7.2 %d (из них по адресу %d)",
                 len(new), len(existing), len(self.host_alias))
        return new, existing

    # ----- шаблоны -----
    def check_template_map(self):
        targets = sorted({v for v in self.tmap.values() if v})
        have = set()
        if targets:
            have = {t["host"] for t in self.dst.call("template.get", {
                "output": ["host"], "filter": {"host": targets}})}
        missing = [t for t in targets if t not in have]
        if missing:
            raise SystemExit(f"Шаблоны-замены из template_map отсутствуют в 7.2: {missing}")

    def action_template_ids(self, actions):
        """Шаблоны, на которые ссылаются действия (условие «шаблон», операции привязки)."""
        ids = set()
        for a in actions:
            for c in (a.get("filter") or {}).get("conditions") or []:
                if int(c["conditiontype"]) == 13:
                    ids.add(str(c["value"]))
            for op in self.all_ops(a):
                ids |= {str(x["templateid"]) for x in op.get("optemplate") or []}
        return ids

    def plan_templates(self, hosts, extra_ids=()):
        all_t = self.src.call("template.get", {"output": ["templateid", "host"],
                                               "selectParentTemplates": ["templateid", "host"]})
        by_id = {t["templateid"]: t for t in all_t}
        usage = Counter(p["host"] for h in hosts for p in h["parentTemplates"])
        if self.cfg.get("migrate_all_templates"):
            start = list(by_id)
        else:
            start = [p["templateid"] for h in hosts for p in h["parentTemplates"]]
            start += [t["templateid"] for t in all_t if t["host"] in self.cfg.get("extra_templates", [])]
            start += list(extra_ids)
        need, stack = set(), list(start)
        while stack:
            tid = stack.pop()
            if tid in need or tid not in by_id or by_id[tid]["host"] in self.tmap:
                continue
            need.add(tid)
            stack += [p["templateid"] for p in by_id[tid]["parentTemplates"]]

        order, seen = [], set()

        def visit(tid):  # сначала родительские шаблоны
            if tid in seen:
                return
            seen.add(tid)
            for p in by_id[tid]["parentTemplates"]:
                if p["templateid"] in need:
                    visit(p["templateid"])
            order.append(tid)

        for tid in sorted(need, key=lambda x: by_id[x]["host"]):
            visit(tid)

        exist = set(self.dst_ids("template"))
        for name in sorted(n for n in usage if n in self.tmap):
            tgt = self.tmap[name]
            self.rows["templates"].append({
                "шаблон 4.4": name, "узлов 4.4": usage[name],
                "результат": f"заменяется на '{tgt}'" if tgt else "отвязывается (template_map)"})
        for idx, tid in enumerate(order):
            n = by_id[tid]["host"]
            row = {"шаблон 4.4": n, "узлов 4.4": usage.get(n, 0)}
            if n in exist:
                row["результат"] = "уже есть в 7.2 — пропуск"
            else:
                try:
                    exp = self.export("templates", [tid])
                except ZabbixError as e:
                    log.error("шаблон '%s': выгрузка не удалась: %s", n, e)
                    fix = ("Проверьте, выгружается ли шаблон в веб-интерфейсе 4.4 (Настройка → Шаблоны → Экспорт); "
                           "увеличьте memory_limit/max_execution_time PHP на 4.4, " + RERUN +
                           ". Узлы с этим шаблоном тоже не перенесутся.")
                    row.update({"результат": f"ОШИБКА выгрузки: {e}", "что сделать": fix})
                    self.problem(NOT_MIGRATED, "шаблон", n, f"выгрузка из 4.4 не удалась: {e}", fix)
                    self.rows["templates"].append(row)
                    continue
                self.remap_links(exp)
                rel = f"templates/{idx:04d}_{safe_name(n)}.json"
                save_json(self.path(rel), exp)
                self.manifest["templates"].append({"name": n, "file": rel, "import": True})
                self.planned["template"].add(n)
                row["результат"] = "к импорту"
            self.rows["templates"].append(row)
        log.info("шаблоны: нужно %d, уже есть %d, к импорту %d, заменяются %d",
                 len(order), len(order) - len(self.manifest["templates"]),
                 len(self.manifest["templates"]), sum(1 for n in usage if n in self.tmap))

    # ----- узлы -----
    def write_hosts(self, new):
        dst_proxies = set(self.dst_ids("proxy"))
        avail_t = set(self.dst_ids("template")) | self.planned["template"]
        for idx, (h, note) in enumerate(new):
            # issues: (блокирует импорт?, причина, что сделать)
            issues = [(False, note, "Проверьте, не тот же ли это узел: если да — поставьте \"import\": false "
                                    "у узла в manifest.json (или переименуйте в 7.2 и " + RERUN + ").")] if note else []
            try:
                exp = self.export("hosts", [h["hostid"]])
            except ZabbixError as e:
                log.error("узел '%s': выгрузка не удалась: %s", h["host"], e)
                exp = None
                issues.append((True, f"выгрузка из 4.4 не удалась: {e}",
                               "Проверьте экспорт узла в веб-интерфейсе 4.4; увеличьте memory_limit/max_execution_time "
                               "PHP на 4.4, " + RERUN + "."))
            if exp is not None:
                self.remap_links(exp)
                visible = h.get("name") or h["host"]
                owner = self.dst_visible.get(visible)
                if owner:  # в 7.2 видимые имена узлов тоже уникальны — импорт упадёт
                    issues.append((True, f"видимое имя '{visible}' уже занято в 7.2 узлом '{owner}'",
                                   f"Если это тот же узел — ничего не делайте (или переименуйте узел в 7.2 в "
                                   f"'{h['host']}' и {RERUN}, чтобы сравнить шаблоны); если разные — смените "
                                   f"видимое имя в 4.4 или 7.2 и {RERUN}."))
                for x in exp["zabbix_export"].get("hosts") or []:
                    pr = x.get("proxy")
                    if pr and pr.get("name"):
                        target = self.proxy_map.get(pr["name"], pr["name"])
                        if target in dst_proxies:
                            x["proxy"] = {"name": target}
                        elif self.cfg.get("drop_missing_proxy"):
                            x.pop("proxy", None)
                            x.pop("monitored_by", None)
                            issues.append((False, f"прокси '{target}' нет в 7.2 — узел будет мониторить сервер",
                                           f"Если узел недоступен с сервера 7.2 — создайте прокси '{target}' "
                                           f"(версии 7.2) и назначьте его узлу вручную."))
                        else:
                            issues.append((True, f"прокси '{target}' нет в 7.2",
                                           f"Создайте в 7.2 прокси '{target}' (версии 7.2) или задайте proxy_map "
                                           f"{{\"{pr['name']}\": \"<прокси 7.2>\"}}, либо drop_missing_proxy: true; "
                                           + RERUN + "."))
            want = self.mapped_templates(h)
            lost = [t for t in want if t not in avail_t]
            if lost:
                issues.append((True, f"нет шаблонов в 7.2: {j(lost)}",
                               "Эти шаблоны не выгрузились или не найдены (см. шаблоны в problems.csv): "
                               "импортируйте их в 7.2 или укажите замену в template_map, " + RERUN + "."))
            imp = exp is not None and not any(block for block, _, _ in issues)
            reason = "; ".join(r for _, r, _ in issues)
            fix = " | ".join(f for _, _, f in issues)
            for block, r, f in issues:
                self.problem(NOT_MIGRATED if block else WARNING, "узел", h["host"], r, f)
            if exp is not None:
                rel = f"hosts/{idx:05d}_{safe_name(h['host'])}.json"
                save_json(self.path(rel), exp)
                self.manifest["hosts"].append({"host": h["host"], "file": rel, "import": imp,
                                               "note": reason, "fix": fix})
            if imp:
                self.planned["host"].add(h["host"])
                self.planned["hostgroup"] |= {g["name"] for g in h["groups"]}
            self.rows["hosts"].append({
                "узел 4.4": h["host"], "статус 4.4": "выкл" if str(h["status"]) == "1" else "вкл",
                "результат": "к импорту" if imp else "НЕ импортируется",
                "шаблоны (после замены)": j(want), "группы 4.4": j(g["name"] for g in h["groups"]),
                "узел в 7.2": "", "шаблоны в 7.2": "", "не хватает шаблонов": "",
                "не хватает групп": "", "примечание": reason, "что сделать": fix})

    def plan_existing(self, existing):
        avail_t = set(self.dst_ids("template")) | self.planned["template"]
        do_sync = bool(self.cfg.get("sync_existing_hosts", False))
        for h, d, how in existing:
            want = self.mapped_templates(h)
            have = {p["host"] for p in d["parentTemplates"]}
            add_t = [t for t in want if t not in have]
            lost = [t for t in add_t if t not in avail_t]
            add_t = [t for t in add_t if t in avail_t]
            have_g = {g["name"] for g in d.get("hostgroups") or []}
            add_g = sorted({g["name"] for g in h["groups"]} - have_g)
            notes, fixes = [], []
            if lost:
                notes.append(f"шаблонов нет в 7.2: {j(lost)}")
                fixes.append("Эти шаблоны не выгрузились или не найдены: импортируйте их в 7.2 или укажите "
                             "замену в template_map, " + RERUN + ".")
                self.problem(NOT_MIGRATED, "существующий узел", d["host"],
                             f"не будут привязаны шаблоны {j(lost)}: их нет в 7.2", fixes[-1])
            if add_t or add_g:
                self.manifest["existing_hosts"].append({
                    "host_44": h["host"], "host": d["host"],
                    "add_templates": add_t, "add_groups": add_g, "apply": do_sync})
                if do_sync:
                    self.planned["hostgroup"] |= set(add_g)
                    res = f"есть в 7.2 ({how}); будет дополнен"
                else:
                    res = f"есть в 7.2 ({how}); отличается — не дополняется"
                    diff = j(([f"шаблоны: {j(add_t)}"] if add_t else []) + ([f"группы: {j(add_g)}"] if add_g else []))
                    fixes.append("Включите sync_existing_hosts: true (или \"apply\": true у узла в разделе "
                                 "existing_hosts в manifest.json) и выполните apply, либо добавьте вручную.")
                    self.problem(WARNING, "существующий узел", d["host"],
                                 f"узел уже есть в 7.2 ({how}), но в 7.2 не хватает — {diff}", fixes[-1])
            else:
                res = f"есть в 7.2 ({how}); совпадает"
            self.rows["hosts"].append({
                "узел 4.4": h["host"], "статус 4.4": "выкл" if str(h["status"]) == "1" else "вкл",
                "результат": res, "шаблоны (после замены)": j(want),
                "группы 4.4": j(g["name"] for g in h["groups"]), "узел в 7.2": d["host"],
                "шаблоны в 7.2": j(sorted(have)), "не хватает шаблонов": j(add_t),
                "не хватает групп": j(add_g), "примечание": "; ".join(notes),
                "что сделать": " | ".join(fixes)})

    # ----- правила сетевого обнаружения -----
    @staticmethod
    def convert_dcheck(c):
        t = int(c["type"])
        d = {"type": t, "uniq": c.get("uniq", "0"),
             "host_source": c.get("host_source", "1"), "name_source": c.get("name_source", "0")}
        if t != 12 and c.get("ports") not in (None, ""):
            d["ports"] = c["ports"]
        if t in (9, 10, 11, 13) and c.get("key_"):
            d["key_"] = c["key_"]
        if t in (10, 11) and c.get("snmp_community"):
            d["snmp_community"] = c["snmp_community"]
        if t == 13:
            for k in SNMPV3_FIELDS:
                if c.get(k) not in (None, ""):
                    d[k] = c[k]
        return d

    def plan_drules(self):
        p = {"output": "extend", "selectDChecks": "extend"}
        if self.cfg.get("drules"):
            p["filter"] = {"name": self.cfg["drules"]}
        rules = self.src.call("drule.get", p)
        dst = self.dst.call("drule.get", {"output": ["name", "iprange"]})
        dst_names = {d["name"] for d in dst}
        norm = lambda s: ",".join(sorted(x.strip() for x in s.split(",") if x.strip()))
        by_range = {}
        for d in dst:
            by_range.setdefault(norm(d["iprange"]), []).append(d["name"])
        src_proxies = self.src_names("proxy")
        keep_status = self.cfg.get("drules_status", "disabled") == "keep"
        for idx, r in enumerate(rules):
            checks = j(DCHECK_TYPES.get(int(c["type"]), c["type"]) +
                       (f":{c['ports']}" if c.get("ports") and int(c["type"]) != 12 else "")
                       for c in r["dchecks"])
            row = {"правило 4.4": r["name"], "диапазон": r["iprange"], "проверки": checks,
                   "статус 4.4": "выкл" if str(r["status"]) == "1" else "вкл",
                   "результат": "", "примечание": ""}
            self.rows["drules"].append(row)
            if r["name"] in dst_names:
                row["результат"] = "уже есть в 7.2 (по имени) — пропуск"
                continue
            imp, notes, fixes = True, [], []
            try:
                dchecks = [self.convert_dcheck(c) for c in r["dchecks"]]
            except (KeyError, ValueError) as e:
                fix = "Создайте правило в 7.2 вручную (Сбор данных → Обнаружение) по образцу из 4.4."
                row.update({"результат": f"ОШИБКА конвертации проверок: {e!r}", "что сделать": fix})
                self.problem(NOT_MIGRATED, "правило обнаружения", r["name"],
                             f"не удалось сконвертировать проверки: {e!r}", fix)
                continue
            body = {"name": r["name"], "iprange": r["iprange"], "delay": r["delay"],
                    "status": r["status"] if keep_status else 1, "dchecks": dchecks}
            pid = str(r.get("proxy_hostid") or "0")
            if pid != "0":
                pname = src_proxies.get(pid)
                pname = self.proxy_map.get(pname, pname)
                if pname in self.dst_ids("proxy"):
                    body["proxyid"] = {"$ref": "proxy", "name": pname}
                else:
                    imp = False
                    notes.append(f"прокси '{pname}' нет в 7.2")
                    fixes.append(f"Создайте в 7.2 прокси '{pname}' (версии 7.2) или задайте proxy_map, " + RERUN + ".")
                    self.problem(NOT_MIGRATED, "правило обнаружения", r["name"], notes[-1], fixes[-1])
            same = by_range.get(norm(r["iprange"]))
            if same:
                notes.append(f"тот же диапазон уже сканирует 7.2: {j(same)}")
                if self.cfg.get("skip_drules_same_range", True):
                    imp = False
                    if len(same) == 1:
                        self.drule_alias[r["name"]] = same[0]
                        notes.append(f"действия будут ссылаться на правило 7.2 '{same[0]}'")
                    fixes.append("Обычно ничего делать не нужно — диапазон уже сканируется. Если правило 4.4 нужно "
                                 "отдельно — поставьте \"import\": true у него в manifest.json (или "
                                 "skip_drules_same_range: false и " + RERUN + ").")
                    self.problem(NOT_MIGRATED, "правило обнаружения", r["name"], "; ".join(notes), fixes[-1])
            rel = f"drules/{idx:04d}_{safe_name(r['name'])}.json"
            save_json(self.path(rel), body)
            self.manifest["drules"].append({"name": r["name"], "file": rel, "import": imp,
                                            "note": "; ".join(notes), "fix": " | ".join(fixes)})
            if imp:
                self.planned["drule"].add(r["name"])
            row["результат"] = ("к импорту" + (" (выключенным)" if body["status"] == 1 else "")
                                if imp else "НЕ импортируется")
            row["примечание"] = "; ".join(notes)
            row["что сделать"] = " | ".join(fixes)

    # ----- способы оповещения -----
    @staticmethod
    def all_ops(a):
        return ((a.get("operations") or []) + (a.get("recoveryOperations") or [])
                + (a.get("acknowledgeOperations") or []))

    @staticmethod
    def convert_mediatype(m, name):
        t = int(m["type"])
        b = {"name": name, "type": t, "status": m.get("status", "0")}
        for k in ("maxsessions", "maxattempts", "attempt_interval"):
            if k in m:
                b[k] = m[k]
        if m.get("name") and m.get("description"):
            b["description"] = m["description"]
        if t == 0:
            for k in ("smtp_server", "smtp_helo", "smtp_email", "smtp_port", "smtp_security",
                      "smtp_verify_peer", "smtp_verify_host", "smtp_authentication",
                      "username", "passwd", "content_type"):
                if m.get(k) not in (None, ""):
                    b[k] = m[k]
        elif t == 1:
            b["exec_path"] = m["exec_path"]
            params = (m.get("exec_params") or "").split("\n")
            while params and params[-1] == "":
                params.pop()
            b["parameters"] = [{"sortorder": i, "value": v} for i, v in enumerate(params)]
        elif t == 2:
            b["gsm_modem"] = m["gsm_modem"]
        elif t == 4:
            for k in ("script", "timeout", "process_tags", "show_event_menu",
                      "event_menu_url", "event_menu_name"):
                if m.get(k) not in (None, ""):
                    b[k] = m[k]
            b["parameters"] = [{"name": p["name"], "value": p["value"]}
                               for p in m.get("parameters") or []]
        else:
            return None  # Jabber / Ez Texting в 7.x нет
        return b

    def plan_mediatypes(self, actions):
        usage, uses_all = {}, False
        for a in actions:
            for op in self.all_ops(a):
                m = op.get("opmessage")
                if m and int(op["operationtype"]) == 0:
                    mt = str(m.get("mediatypeid", "0"))
                    if mt == "0":
                        uses_all = True
                    else:
                        usage.setdefault(mt, set()).add(a["name"])
        if uses_all or self.cfg.get("include_user_media"):
            for u in self.src.call("user.get", {"output": ["userid"], "selectMedias": ["mediatypeid"]}):
                for md in u.get("medias") or []:
                    usage.setdefault(str(md["mediatypeid"]), set()).add("(медиа пользователей)")
        if not usage:
            return
        src_mts = self.src.call("mediatype.get", {"output": "extend", "mediatypeids": sorted(usage)})
        dst_names = set(self.dst_ids("mediatype"))
        for m in src_mts:
            sname = m.get("name") or m.get("description")
            target = self.mt_name_map.get(sname, sname)
            note, fix, err = "", "", None
            used_in = j(sorted(usage.get(m["mediatypeid"], [])))
            if target in dst_names:
                mode, body = "reuse", None
                res = f"подключить существующий в 7.2 '{target}' (не изменяется)"
            else:
                try:
                    body = self.convert_mediatype(m, target)
                except (KeyError, ValueError) as e:
                    log.error("способ '%s': ошибка конвертации %r", sname, e)
                    body, err = None, e
                mode = "create" if body else "unsupported"
                if body:
                    res = "создать в 7.2"
                    if str(m.get("smtp_authentication", "0")) == "1" and not m.get("passwd"):
                        note = "пароль SMTP не получен из API 4.4"
                        fix = (f"После apply задайте пароль в 7.2: Оповещения → Способы оповещения → '{target}' "
                               f"(иначе письма не уйдут).")
                        self.problem(WARNING, "способ оповещения", target, note, fix)
                else:
                    if err is not None:
                        note = f"ошибка конвертации: {err!r}"
                    else:
                        note = f"тип {m['type']} (Jabber / Ez Texting) в 7.2 не существует"
                    fix = (f"Создайте в 7.2 замену (например, вебхук Telegram/Slack/e-mail из комплекта 7.2) и укажите "
                           f"её в media_type_map {{\"{sname}\": \"<способ 7.2>\"}}, " + RERUN +
                           f". Без этого операции с этим способом в действиях ({used_in}) будут пропущены.")
                    res = "НЕ переносится"
                    self.problem(NOT_MIGRATED, "способ оповещения", sname, note, fix)
            self.mt_plan[m["mediatypeid"]] = target if mode != "unsupported" else None
            if mode == "create":
                self.planned["mediatype"].add(target)
            self.manifest["mediatypes"].append({"name_44": sname, "target": target, "mode": mode,
                                                "import": mode == "create", "body": body})
            self.manifest["mediatypes"][-1].update(note=note, fix=fix)
            self.rows["mediatypes"].append({
                "способ 4.4": sname, "тип": m["type"], "результат": res,
                "используется в": used_in, "примечание": note, "что сделать": fix})

    # ----- действия -----
    def conv_condition(self, c):
        ct = int(c["conditiontype"])
        o = {"conditiontype": ct, "operator": int(c["operator"]), "value": c["value"]}
        if c.get("formulaid"):
            o["formulaid"] = c["formulaid"]
        if c.get("value2"):
            o["value2"] = c["value2"]
        if ct in COND_KINDS:
            o["value"] = self.ref(COND_KINDS[ct], c["value"])
        elif ct == 2:
            o["value"] = self.trigger_ref(c["value"])
        elif ct == 19:
            o["value"] = self.dcheck_ref(c["value"])
        elif ct == 15:  # Application -> тег Application (как при апгрейде на 5.4)
            o.update(conditiontype=26, value2="Application")
            self.note(f"условие Application '{c['value']}' заменено на тег события Application — "
                      f"сработает, только если у триггеров 7.2 есть такой тег",
                      "Проверьте в 7.2, что у нужных триггеров есть тег Application (или замените условие на другой "
                      "тег/группу), затем включите действие.")
        return o

    def load_dst_users(self):
        if self._dst_users is None:
            mt = self.dst_rev("mediatype")
            media, groups = {}, {}
            for u in self.dst.call("user.get", {"output": ["username"],
                                                "selectMedias": ["mediatypeid", "active"],
                                                "selectUsrgrps": ["name"]}):
                media[u["username"]] = {mt.get(m["mediatypeid"]) for m in u.get("medias") or []
                                        if str(m.get("active", "0")) == "0"}
                for g in u.get("usrgrps") or []:
                    groups.setdefault(g["name"], set()).add(u["username"])
            self._dst_users = (media, groups)
        return self._dst_users

    def note(self, text, fix=None):
        """Примечание к действию; с fix — это предупреждение, попадёт в problems.csv."""
        if text not in self._notes:
            self._notes.append(text)
            if fix:
                self._note_fixes.append((text, fix))

    def media_note(self, grp, usr, target):
        """Получат ли оповещение: у пользователей 7.2 должно быть медиа этого способа."""
        if target in self.planned["mediatype"]:
            return (f"способ '{target}' будет создан, но у получателей в 7.2 ещё нет такого медиа",
                    f"После apply добавьте пользователям-получателям медиа '{target}' "
                    f"(Пользователи → пользователь → Медиа), иначе оповещения не дойдут.")
        media, groups = self.load_dst_users()
        names = {u["userid"]["name"] for u in usr}
        for g in grp:
            names |= groups.get(g["usrgrpid"]["name"], set())
        ok = [n for n in names if (target in media.get(n, set()) if target else media.get(n))]
        if not ok:
            return (f"ни у одного получателя в 7.2 нет активного медиа '{target or 'любого способа'}' — "
                    f"оповещения не дойдут",
                    f"Добавьте получателям ({j(sorted(names)) or 'нет пользователей'}) в 7.2 медиа "
                    f"'{target or 'нужного способа'}' (Пользователи → пользователь → Медиа) и включите его.")
        return None

    def conv_recipients(self, op):
        grp, usr = [], []
        for kind, key, lst, out in (("usergroup", "usrgrpid", op.get("opmessage_grp"), grp),
                                    ("user", "userid", op.get("opmessage_usr"), usr)):
            for x in lst or []:
                try:
                    out.append({key: self.ref(kind, x[key])})
                except Unmappable as e:
                    self.note(f"получатель пропущен: {e}", e.fix)
        return grp, usr

    def script_spec(self, src):
        return {k: src[k] for k in SCRIPT_FIELDS if src.get(k) not in (None, "")}

    def conv_op(self, op, kind, a, idx):
        t = int(op["operationtype"])
        es = int(a["eventsource"])
        o = {"operationtype": t}
        # эскалация есть только у действий на триггеры и внутренние события,
        # условия операций — только у триггеров; для обнаружения/авторегистрации 7.2 эти поля отвергнет
        if kind == "op" and es in (0, 3):
            for k in ("esc_period", "esc_step_from", "esc_step_to"):
                if k in op:
                    o[k] = op[k]
            if es == 0:
                if "evaltype" in op:
                    o["evaltype"] = op["evaltype"]
                if op.get("opconditions"):
                    o["opconditions"] = [{"conditiontype": x["conditiontype"], "operator": x["operator"],
                                          "value": x["value"]} for x in op["opconditions"]]
        if t in (0, 11, 12):
            m = op.get("opmessage") or {}
            if str(m.get("default_msg", "1")) == "1":  # в 7.x тексты по умолчанию — в способе, подставляем явно
                pref = {"op": "def", "rec": "r", "ack": "ack"}[kind]
                subj, body = a.get(f"{pref}_shortdata", ""), a.get(f"{pref}_longdata", "")
            else:
                subj, body = m.get("subject", ""), m.get("message", "")
            o["opmessage"] = {"default_msg": 0, "subject": subj, "message": body}
            if t == 0:
                mt = str(m.get("mediatypeid", "0"))
                target = None
                if mt == "0":
                    o["opmessage"]["mediatypeid"] = "0"
                elif self.mt_plan.get(mt):
                    target = self.mt_plan[mt]
                    o["opmessage"]["mediatypeid"] = {"$ref": "mediatype", "name": target}
                else:
                    self.note(f"операция «отправить сообщение» пропущена: способ оповещения id={mt} не переносится",
                              "Причина — в problems.csv (тип «способ оповещения»): укажите замену в media_type_map, "
                              + RERUN + "; или добавьте операцию вручную после apply.")
                    return None
                grp, usr = self.conv_recipients(op)
                if not grp and not usr:
                    self.note("операция «отправить сообщение» пропущена: ни одного получателя нет в 7.2",
                              "Создайте в 7.2 пользователей/группы пользователей с теми же именами, что в 4.4, "
                              + RERUN + "; или добавьте операцию вручную после apply.")
                    return None
                o["opmessage_grp"], o["opmessage_usr"] = grp, usr
                mn = self.media_note(grp, usr, target)
                if mn:
                    self.note(*mn)
        elif t == 1:
            c = op["opcommand"]
            if int(c.get("type", 0)) == 4:
                s = self.src.call("script.get", {"output": "extend", "scriptids": [c["scriptid"]]})
                if not s:
                    raise Unmappable(f"глобальный скрипт id={c['scriptid']} не найден в 4.4",
                                     "Скрипт удалён в 4.4: исправьте операцию действия в 4.4 и " + RERUN + ".")
                name, spec = script_name(s[0]["name"]), self.script_spec(s[0])
            else:
                name, spec = script_name(f"[mig] {a['name']} #{kind}{idx}"), self.script_spec(c)
            if not spec.get("command"):
                raise Unmappable(f"у удалённой команды '{name}' пустой текст команды",
                                 "Укажите команду в операции действия в 4.4 и " + RERUN + ".")
            o["opcommand"] = {"scriptid": {"$ref": "script", "name": name, "spec": spec}}
            self.note(f"команда -> скрипт 7.2 '{name}'")
            o["opcommand_hst"] = [{"hostid": "0" if str(h["hostid"]) == "0" else self.ref("host", h["hostid"])}
                                  for h in op.get("opcommand_hst") or []]
            o["opcommand_grp"] = [{"groupid": self.ref("hostgroup", g["groupid"])}
                                  for g in op.get("opcommand_grp") or []]
        elif t in (4, 5):
            o["opgroup"] = [{"groupid": self.ref("hostgroup", g["groupid"])} for g in op.get("opgroup") or []]
        elif t in (6, 7):
            o["optemplate"] = [{"templateid": self.ref("template", x["templateid"])}
                               for x in op.get("optemplate") or []]
        elif t == 10:
            o["opinventory"] = {"inventory_mode": op["opinventory"]["inventory_mode"]}
        return o

    def conv_action(self, a):
        es = int(a["eventsource"])
        f = a.get("filter") or {}
        flt = {"evaltype": int(f.get("evaltype", 0)),
               "conditions": [self.conv_condition(c) for c in f.get("conditions") or []]}
        if flt["evaltype"] == 3:
            flt["formula"] = f["formula"]
        status = a["status"] if self.cfg.get("actions_status", "disabled") == "keep" else 1
        n = {"name": a["name"], "eventsource": es, "status": status, "filter": flt}
        if es in (0, 3):
            n["esc_period"] = a.get("esc_period", "1h")
        if es == 0:
            n["pause_suppressed"] = a.get("pause_suppressed", "1")

        def ops(lst, kind):
            return [x for i, op in enumerate(lst or []) if (x := self.conv_op(op, kind, a, i))]

        n["operations"] = ops(a.get("operations"), "op")
        if es in (0, 3):
            r = ops(a.get("recoveryOperations"), "rec")
            if r:
                n["recovery_operations"] = r
        if es == 0:
            u = ops(a.get("acknowledgeOperations"), "ack")
            if u:
                n["update_operations"] = u
        if not (n["operations"] or n.get("recovery_operations") or n.get("update_operations")):
            raise Unmappable("не осталось ни одной операции: " + "; ".join(self._notes),
                             " | ".join(f for _, f in self._note_fixes) or
                             "Устраните причины пропуска операций (см. причину) и " + RERUN + ".")
        return n

    def dst_action_index(self):
        acts = self.dst.call("action.get", {"output": ["name", "eventsource"], "selectFilter": "extend"})
        tids = {c["value"] for a in acts for c in a["filter"]["conditions"] if int(c["conditiontype"]) == 2}
        trig = {}
        if tids:
            for t in self.dst.call("trigger.get", {"triggerids": sorted(tids), "output": ["description"],
                                                   "selectHosts": ["host"]}):
                h = t["hosts"][0]["host"] if t["hosts"] else "?"
                trig[t["triggerid"]] = f"trigger:{h}:{t['description']}"
        dchecks = {}
        if any(int(c["conditiontype"]) == 19 for a in acts for c in a["filter"]["conditions"]):
            for r in self.dst.call("drule.get", {"output": ["name"], "selectDChecks": "extend"}):
                for c in r["dchecks"]:
                    dchecks[c["dcheckid"]] = (f"dcheck:{r['name']}:{int(c['type'])}:"
                                              f"{c.get('ports', '')}:{c.get('key_', '')}")
        rev = {k: self.dst_rev(k) for k in COND_KINDS.values()}
        index = []
        for a in acts:
            keys = []
            for c in a["filter"]["conditions"]:
                ct, v = int(c["conditiontype"]), c["value"]
                if ct in COND_KINDS:
                    v = f"{COND_KINDS[ct]}:{rev[COND_KINDS[ct]].get(v, v)}"
                elif ct == 2:
                    v = trig.get(v, f"trigger-id:{v}")
                elif ct == 19:
                    v = dchecks.get(v, f"dcheck-id:{v}")
                keys.append((ct, int(c["operator"]), v, c.get("value2") or ""))
            index.append({"name": a["name"], "es": int(a["eventsource"]),
                          "sig": (int(a["eventsource"]), int(a["filter"]["evaltype"]), tuple(sorted(keys))),
                          "scope": {k[2] for k in keys if k[0] in SCOPE_TYPES}})
        return index

    @staticmethod
    def scope_text(scope):
        ru = {"hostgroup": "группа", "host": "узел", "template": "шаблон"}
        return j(f"{ru[s.split(':', 1)[0]]} {s.split(':', 1)[1]}" for s in sorted(scope)) or "все узлы"

    def plan_actions(self, actions):
        index = self.dst_action_index()
        names = {x["name"] for x in index}
        skip_dup = self.cfg.get("skip_duplicate_actions", True)
        skip_scope = self.cfg.get("skip_actions_with_same_scope", False)
        for idx, a in enumerate(actions):
            es = int(a["eventsource"])
            row = {"действие 4.4": a["name"], "события": ES_NAMES.get(es, es),
                   "статус 4.4": "выкл" if str(a["status"]) == "1" else "вкл",
                   "результат": "", "область": "", "дубль в 7.2": "", "пересекается в 7.2 с": "",
                   "примечание": ""}
            self.rows["actions"].append(row)
            if a["name"] in names:
                row["результат"] = "уже есть в 7.2 (по имени) — пропуск"
                continue
            self._notes, self._note_fixes, self._pending_groups = [], [], []
            try:
                n = self.conv_action(a)
            except Unmappable as e:
                # условие не выкидываем (действие стало бы шире) — пропускаем целиком
                fix = e.fix or "Создайте действие в 7.2 вручную по образцу из 4.4."
                row.update({"результат": f"НЕ переносится: {e}", "что сделать": fix})
                self.problem(NOT_MIGRATED, "действие", a["name"], str(e), fix)
                self.planned["hostgroup"] -= set(self._pending_groups)
                continue
            except Exception as e:  # неожиданная структура данных — не роняем весь prepare
                log.exception("действие '%s': ошибка конвертации", a["name"])
                fix = "Создайте действие в 7.2 вручную по образцу из 4.4; подробности ошибки — в prepare.log."
                row.update({"результат": f"ОШИБКА конвертации: {e!r}", "что сделать": fix})
                self.problem(NOT_MIGRATED, "действие", a["name"], f"ошибка конвертации: {e!r}", fix)
                self.planned["hostgroup"] -= set(self._pending_groups)
                continue
            for g in self._pending_groups:
                if g not in self.manifest["hostgroups"]:
                    self.manifest["hostgroups"].append(g)
                    self._notes.append(f"будет создана пустая группа узлов '{g}'")
            keys = [(c["conditiontype"], c["operator"], self.key_of(c["value"]), c.get("value2") or "")
                    for c in n["filter"]["conditions"]]
            sig = (es, n["filter"]["evaltype"], tuple(sorted(keys)))
            scope = {k[2] for k in keys if k[0] in SCOPE_TYPES}
            dup = next((x["name"] for x in index if x["sig"] == sig), "")
            overlaps = [x["name"] + ("" if x["scope"] else " (без условия на группу/узел/шаблон)") for x in index
                        if x["es"] == es and x["name"] != dup
                        and (not x["scope"] or not scope or x["scope"] & scope)]
            imp, res = True, "к импорту" + (" (выключенным)" if n["status"] == 1 else "")
            skip_reason = skip_fix = ""
            if dup and skip_dup:
                imp, res = False, "дубль — пропуск"
                skip_reason = f"в 7.2 уже есть действие '{dup}' с теми же условиями"
                skip_fix = (f"Обычно ничего не нужно: '{dup}' уже делает то же. Сравните операции; если нужно и это "
                            f"действие — поставьте \"import\": true у него в manifest.json и выполните apply.")
            elif overlaps and skip_scope:
                imp, res = False, "есть действия на ту же область — пропуск"
                skip_reason = f"в 7.2 есть действия на ту же область: {j(overlaps)}"
                skip_fix = ("Сравните с действиями 7.2; если нужно — поставьте \"import\": true у него в manifest.json "
                            "(или skip_actions_with_same_scope: false и " + RERUN + ").")
            if skip_reason:
                self.problem(NOT_MIGRATED, "действие", a["name"], skip_reason, skip_fix)
            if imp:  # переносится, но частично/с оговорками
                for text, fix in self._note_fixes:
                    self.problem(WARNING, "действие", a["name"], text, fix)
            fixes = skip_fix if skip_reason else " | ".join(f for _, f in self._note_fixes)
            rel = f"actions/{idx:04d}_{safe_name(a['name'])}.json"
            save_json(self.path(rel), n)
            self.manifest["actions"].append({"name": a["name"], "file": rel, "import": imp,
                                             "duplicate_of": dup, "overlaps": overlaps,
                                             "note": skip_reason or "; ".join(self._notes), "fix": fixes})
            row.update({"результат": res, "область": self.scope_text(scope), "дубль в 7.2": dup,
                        "пересекается в 7.2 с": j(overlaps), "примечание": "; ".join(self._notes),
                        "что сделать": fixes})

    def load_src_actions(self):
        p = {"output": "extend", "selectFilter": "extend", "selectOperations": "extend",
             "selectRecoveryOperations": "extend", "selectAcknowledgeOperations": "extend"}
        if self.cfg.get("actions"):
            p["filter"] = {"name": self.cfg["actions"]}
        acts = self.src.call("action.get", p)
        save_json(self.path("raw/actions_44.json"), acts)
        log.info("действий в 4.4: %d", len(acts))
        return acts

    def run(self):
        self.check_template_map()
        hosts = self.load_src_hosts()
        actions = self.load_src_actions()
        new, existing = self.classify_hosts(hosts)
        self.plan_templates(hosts, self.action_template_ids(actions))
        self.write_hosts(new)
        self.plan_existing(existing)
        self.plan_drules()
        self.plan_mediatypes(actions)
        self.plan_actions(actions)
        self.manifest["problems"] = self.problems  # apply покажет и то, что отсеялось при подготовке
        save_json(self.path("manifest.json"), self.manifest)
        for k, rows in self.rows.items():
            save_csv(self.path(f"{k}.csv"), rows)
        m = self.manifest
        cnt = lambda lst, f="import": sum(1 for x in lst if x.get(f))
        print("\n===== ПАКЕТ ПОДГОТОВЛЕН:", self.pkg, "=====")
        print(f"шаблоны к импорту:        {cnt(m['templates'])}")
        print(f"узлы к импорту:           {cnt(m['hosts'])} из {len(m['hosts'])} новых")
        print(f"существующие узлы с отличиями: {len(m['existing_hosts'])} "
              f"(дополнить: {cnt(m['existing_hosts'], 'apply')})")
        print(f"правила обнаружения:      {cnt(m['drules'])} из {len(self.rows['drules'])}")
        if m["hostgroups"]:
            print(f"пустые группы для действий: {j(m['hostgroups'])}")
        print(f"способы оповещения: создать {cnt(m['mediatypes'])}, "
              f"подключить существующие {sum(1 for x in m['mediatypes'] if x['mode'] == 'reuse')}")
        print(f"действия к импорту:       {cnt(m['actions'])} из {len(self.rows['actions'])}")
        self.report_problems("problems.csv", "ЧТО НЕ ПЕРЕНЕСЕТСЯ И ЧТО СДЕЛАТЬ (prepare)")
        print("\nПроверьте *.csv (колонки «примечание» и «что сделать»), при необходимости поправьте "
              "manifest.json (import/apply), затем запустите apply.")


# =====================================================================
#  ЭТАП 2: apply
# =====================================================================
class Applier(Base):
    def __init__(self, cfg, dst, pkg, dry):
        super().__init__(cfg, dst, pkg)
        self.dry = dry
        self.m = load_json(self.path("manifest.json"))
        self.results = []
        self._warned_agent = False

    def res(self, typ, name, result, fix="", file="", level=None):
        """Записать итог; ошибки и непереносимое — ещё и в список проблем с рекомендацией."""
        err = result.startswith("ОШИБКА")
        if err and not fix:
            fix = advise(result, file)
        if err or level:
            reason = result[len("ОШИБКА: "):] if result.startswith("ОШИБКА: ") else result
            self.problem(level or NOT_MIGRATED, typ, name, reason, fix)
        self.results.append({"тип": typ, "объект": name, "результат": result, "что сделать": fix})
        (log.error if err else log.info)("%s '%s': %s", typ, name, result)

    def excluded(self, typ, name, item):
        """Объект исключён при подготовке (или вручную в manifest) — причина и что сделать из manifest."""
        reason = item.get("note") or "исключён вручную в manifest.json"
        self.res(typ, name, f"не переносится: {reason}", item.get("fix") or "Если объект нужен — поставьте \"import\": true у него в manifest.json и повторите apply.", level=NOT_MIGRATED)

    def do_import(self, rel, rules):
        if self.dry:
            return None
        try:
            self.dst.call("configuration.import", {"format": "json", "rules": rules,
                                                   "source": json.dumps(load_json(self.path(rel)),
                                                                        ensure_ascii=False)})
            return None
        except ZabbixError as e:
            return str(e)

    def step_templates(self):
        exist = set(self.dst_ids("template"))
        for t in self.m["templates"]:
            if not t["import"]:
                self.excluded("шаблон", t["name"], t)
            elif t["name"] in exist:
                self.res("шаблон", t["name"], "уже есть в 7.2 — пропуск")
            else:
                err = self.do_import(t["file"], TEMPLATE_RULES)
                self.res("шаблон", t["name"], f"ОШИБКА: {err}" if err else
                         ("будет импортирован" if self.dry else "импортирован"), file=t["file"])
        self.drop_cache("template")

    def step_hosts(self):
        exist = set(self.dst_ids("host"))
        imported = []
        for h in self.m["hosts"]:
            if not h["import"]:
                self.excluded("узел", h["host"], h)
            elif h["host"] in exist:
                self.res("узел", h["host"], "уже есть в 7.2 — пропуск")
            else:
                err = self.do_import(h["file"], HOST_RULES)
                self.res("узел", h["host"], f"ОШИБКА: {err}" if err else
                         ("будет импортирован" if self.dry else "импортирован"), file=h["file"])
                if not err:
                    imported.append(h["host"])
        self.drop_cache("host", "hostgroup")
        if imported and self.cfg.get("hosts_disabled") and not self.dry:
            ids = self.dst_ids("host")
            try:
                self.dst.call("host.massupdate", {"hosts": [{"hostid": ids[n]} for n in imported if n in ids],
                                                  "status": 1})
                log.info("импортированные узлы деактивированы (hosts_disabled): %d", len(imported))
            except ZabbixError as e:
                self.res("узлы", "деактивация импортированных", f"ОШИБКА: {e}",
                         "Узлы импортированы, но остались включёнными: выключите их вручную "
                         "(Мониторинг → Узлы сети → выделить → Деактивировать), если 4.4 ещё работает.")

    def step_existing(self):
        for e in self.m["existing_hosts"]:
            if not e["apply"]:
                diff = j(e["add_templates"] + e["add_groups"])
                self.res("существующий узел", e["host"], f"не дополнен (apply: false), не хватает: {diff}",
                         "Включите \"apply\": true у узла в разделе existing_hosts manifest.json (или "
                         "sync_existing_hosts: true и prepare --force) и повторите apply --steps existing; "
                         "либо добавьте вручную.", level=WARNING)
                continue
            cur = self.dst.call("host.get", {"output": ["hostid"], "filter": {"host": e["host"]},
                                             "selectParentTemplates": ["host"],
                                             "selectHostGroups": ["name"]})
            if not cur:
                self.res("существующий узел", e["host"], "ОШИБКА: не найден в 7.2",
                         "Узел удалили или переименовали в 7.2 после prepare: повторите prepare с --force.")
                continue
            hid = cur[0]["hostid"]
            have_t = {x["host"] for x in cur[0].get("parentTemplates") or []}
            have_g = {x["name"] for x in cur[0].get("hostgroups") or []}
            for t in e["add_templates"]:
                if t in have_t:
                    self.res("существующий узел", e["host"], f"шаблон '{t}' уже привязан")
                    continue
                tid = self.dst_ids("template").get(t)
                if not tid and self.dry and t in {x["name"] for x in self.m["templates"] if x["import"]}:
                    tid = f"<из пакета: {t}>"
                if not tid:
                    self.res("существующий узел", e["host"], f"ОШИБКА: шаблона '{t}' нет в 7.2",
                             f"Шаблон '{t}' не импортировался на шаге templates (см. ошибку по нему выше) — "
                             f"устраните её и повторите apply --steps templates,existing.")
                    continue
                try:
                    if not self.dry:
                        self.dst.call("host.massadd", {"hosts": [{"hostid": hid}],
                                                       "templates": [{"templateid": tid}]})
                    self.res("существующий узел", e["host"], f"привязан шаблон '{t}'")
                except ZabbixError as ex:
                    self.res("существующий узел", e["host"], f"ОШИБКА привязки '{t}': {ex}",
                             advise(ex) + " Или привяжите шаблон вручную.")
            for g in e["add_groups"]:
                if g in have_g:
                    self.res("существующий узел", e["host"], f"уже в группе '{g}'")
                    continue
                try:
                    gid = self.dst_ids("hostgroup").get(g)
                    if not gid and not self.dry:
                        gid = self.dst.call("hostgroup.create", {"name": g})["groupids"][0]
                        self.drop_cache("hostgroup")
                    if not self.dry:
                        self.dst.call("host.massadd", {"hosts": [{"hostid": hid}], "groups": [{"groupid": gid}]})
                    self.res("существующий узел", e["host"], f"добавлен в группу '{g}'")
                except ZabbixError as ex:
                    self.res("существующий узел", e["host"], f"ОШИБКА группы '{g}': {ex}")

    def step_hostgroups(self):
        for g in self.m.get("hostgroups", []):
            if g in self.dst_ids("hostgroup"):
                self.res("группа узлов", g, "уже есть в 7.2 — пропуск")
                continue
            try:
                if not self.dry:
                    self.dst.call("hostgroup.create", {"name": g})
                self.res("группа узлов", g, "будет создана" if self.dry else "создана (нужна действиям)")
            except ZabbixError as e:
                self.res("группа узлов", g, f"ОШИБКА: {e}")
        self.drop_cache("hostgroup")

    def step_drules(self):
        for r in self.m.get("drules", []):
            if not r["import"]:
                self.excluded("правило обнаружения", r["name"], r)
            elif r["name"] in self.dst_ids("drule"):
                self.res("правило обнаружения", r["name"], "уже есть в 7.2 — пропуск")
            else:
                try:
                    body = self.resolve(load_json(self.path(r["file"])))
                    if not self.dry:
                        self.dst.call("drule.create", body)
                    self.res("правило обнаружения", r["name"], "будет создано" if self.dry else "создано")
                except Unmappable as e:
                    self.res("правило обнаружения", r["name"], f"ОШИБКА: {e}", e.fix)
                except ZabbixError as e:
                    self.res("правило обнаружения", r["name"], f"ОШИБКА: {e}", file=r["file"])
        self.drop_cache("drule")

    def step_mediatypes(self):
        for m in self.m["mediatypes"]:
            name = m["target"]
            if m["mode"] == "reuse":
                self.res("способ оповещения", name, "существующий в 7.2, не изменяется")
            elif m["mode"] == "unsupported" or not m["import"]:
                self.excluded("способ оповещения", m["name_44"], m)
            elif name in self.dst_ids("mediatype"):
                self.res("способ оповещения", name, "уже есть в 7.2 — не изменяется")
            else:
                try:
                    if not self.dry:
                        self.dst.call("mediatype.create", m["body"])
                    self.res("способ оповещения", name, "будет создан" if self.dry else "создан")
                except ZabbixError as e:
                    self.res("способ оповещения", name, f"ОШИБКА: {e}",
                             advise(e) + f" Тело способа — в manifest.json (mediatypes → '{name}'); "
                             f"либо создайте способ вручную с тем же именем — действия к нему подключатся.")
        self.drop_cache("mediatype")

    def ensure_script(self, spec, name):
        rows = self.dst.call("script.get", {"output": ["scriptid", "scope"], "filter": {"name": name}})
        for r in rows:
            if int(r["scope"]) == 1:
                return r["scriptid"]
        if rows:  # одноимённый скрипт для ручного запуска в действиях использовать нельзя
            return self.ensure_script(spec, f"{name} (action)")
        t = int(spec.get("type", 0))
        b = {"name": name, "scope": 1, "type": t, "command": spec["command"], "groupid": "0"}
        if t == 0:
            b["execute_on"] = spec.get("execute_on", "1")
            if str(b["execute_on"]) == "0" and not self._warned_agent:
                log.warning("есть команды на агенте: на агентах 7.x нужен AllowKey=system.run[*]")
                self._warned_agent = True
        elif t in (2, 3):
            for k in ("port", "username", "password") + (("authtype", "publickey", "privatekey") if t == 2 else ()):
                if k in spec:
                    b[k] = spec[k]
        if self.dry:
            return f"<новый скрипт: {name}>"
        sid = self.dst.call("script.create", b)["scriptids"][0]
        self.res("скрипт", name, "создан")
        return sid

    def resolve(self, obj):
        if isinstance(obj, list):
            return [self.resolve(x) for x in obj]
        if isinstance(obj, dict):
            if "$ref" in obj:
                return self.resolve_ref(obj)
            return {k: self.resolve(v) for k, v in obj.items()}
        return obj

    def resolve_ref(self, r):
        k = r["$ref"]
        if k == "script":
            return self.ensure_script(r["spec"], r["name"])
        if k == "trigger":
            t = self.dst.call("trigger.get", {"output": ["triggerid"], "host": r["host"],
                                              "filter": {"description": r["description"]}})
            if t:
                return t[0]["triggerid"]
            what = f"триггер '{r['description']}' на '{r['host']}'"
        elif k == "dcheck":
            for d in self.dst.call("drule.get", {"output": ["name"], "selectDChecks": "extend",
                                                 "filter": {"name": r["drule"]}}):
                found = match_dcheck(d["dchecks"], r["type"], r["ports"], r["key_"])
                if found:
                    return found
            what = f"проверка {DCHECK_TYPES.get(r['type'])} в правиле '{r['drule']}'"
        else:
            did = self.dst_ids(k).get(r["name"])
            if did:
                return did
            what = f"{KIND_RU[k]} '{r['name']}'"
        if self.dry:
            return f"<нет сейчас: {what}>"
        raise Unmappable(f"{what} не найден в 7.2",
                         "Он должен был появиться на предыдущих шагах apply — посмотрите ошибки по нему выше в "
                         "этом отчёте, устраните их (или создайте объект в 7.2 вручную) и повторите apply.")

    def step_actions(self):
        exist = {a["name"] for a in self.dst.call("action.get", {"output": ["name"]})}
        for a in self.m["actions"]:
            if not a["import"]:
                self.excluded("действие", a["name"], a)
                continue
            if a["name"] in exist:
                self.res("действие", a["name"], "уже есть в 7.2 — пропуск")
                continue
            try:
                body = self.resolve(load_json(self.path(a["file"])))
                if not self.dry:
                    self.dst.call("action.create", body)
                self.res("действие", a["name"], "будет создано" if self.dry else "создано")
            except Unmappable as e:
                self.res("действие", a["name"], f"ОШИБКА: {e}", e.fix)
            except ZabbixError as e:
                self.res("действие", a["name"], f"ОШИБКА: {e}", file=a["file"])

    def run(self, steps):
        log.info("пакет от %s, источник %s", self.m["prepared_at"], self.m["src_url"])
        if self.m["dst_url"].rstrip("/") != self.cfg["dst"]["url"].rstrip("/"):
            raise SystemExit(f"Пакет готовился для {self.m['dst_url']}, а в конфиге {self.cfg['dst']['url']}")
        unknown = steps - set(STEPS)
        if unknown:
            raise SystemExit(f"Неизвестные шаги: {sorted(unknown)}; допустимые: {j(STEPS)}")
        for step in STEPS:
            if step in steps:
                getattr(self, f"step_{step}")()
        # то, что отсеялось ещё при подготовке и в пакет не попало, + напоминания (пароли, медиа и т.п.)
        seen = {(p["тип"], p["объект"]) for p in self.problems}
        for p in self.m.get("problems", []):
            if (p["тип"], p["объект"]) not in seen:
                self.problems.append(dict(p, причина=f"(при подготовке) {p['причина']}"))
        stamp = "dryrun" if self.dry else f"{datetime.now():%Y%m%d_%H%M%S}"
        name = f"apply_{stamp}.csv"
        save_csv(self.path(name), self.results)
        errs = [r for r in self.results if r["результат"].startswith("ОШИБКА")]
        print(f"\n===== APPLY{' (DRY-RUN)' if self.dry else ''}: операций {len(self.results)}, "
              f"ошибок {len(errs)} =====")
        print("Полный отчёт по всем объектам:", self.path(name))
        self.report_problems(f"apply_problems_{stamp}.csv",
                             f"ЧТО НЕ ПЕРЕНЕСЕНО И ЧТО СДЕЛАТЬ (apply{' --dry-run' if self.dry else ''})")
        if errs:
            print("\nПосле исправления просто повторите apply: уже созданное будет пропущено.")
        return len(errs)


# =====================================================================
#  Рекомендации перед запуском и подтверждение
# =====================================================================
RECOMMENDATIONS = {
    "prepare": {
        "old": [
            "Пользователь API — с типом «Супер-администратор Zabbix»: без этого action.get, "
            "mediatype.get, user.get и script.get вернут не всё и пакет будет неполным.",
            "Сделайте резервную копию БД (mysqldump / pg_dump). Скрипт на этом этапе только читает, "
            "но копия понадобится, если что-то пойдёт не так дальше.",
            "Заморозьте изменения конфигурации на время миграции: всё, что поменяют после prepare, "
            "в пакет не попадёт (тогда prepare нужно повторить с --force).",
            "Для больших выгрузок поднимите лимиты PHP веб-интерфейса: memory_limit (512M и больше), "
            "max_execution_time (300 и больше), иначе configuration.export может оборваться.",
        ],
        "new": [
            "Создайте API-токен пользователя с типом «Супер-администратор» "
            "(Пользователи → API токены) и укажите его в dst.token.",
            "Импортируйте официальные шаблоны 7.2, на которые ссылается template_map: "
            "скрипт остановится, если какого-то из них нет.",
            "Создайте прокси 7.2 с теми же именами, что в 4.4 (или заполните proxy_map). "
            "Прокси 4.4 с сервером 7.2 не работают: нужны прокси версии 7.2.",
            "Заведите группы пользователей и пользователей с теми же именами, что в 4.4, и добавьте им "
            "медиа (e-mail, телефон и т.п.): пользователи не переносятся, без них получатели "
            "в действиях будут пропущены.",
            "На этом этапе в 7.2 ничего не изменяется — только чтение и сравнение.",
        ],
    },
    "apply": {
        "old": [
            "Конфигурацию 4.4 после prepare не меняли (иначе повторите prepare с --force).",
            "Не отключайте 4.4 до проверки результата в 7.2: это ваш путь отката.",
            "Спланируйте переключение: после включения действий в 7.2 выключите соответствующие действия "
            "в 4.4, иначе оповещения будут приходить дважды.",
            "Правила сетевого обнаружения: при включении в 7.2 выключайте их в 4.4, "
            "иначе узлы будут обнаруживаться и создаваться дважды.",
        ],
        "new": [
            "ОБЯЗАТЕЛЬНО сделайте резервную копию БД 7.2 — это единственный надёжный откат.",
            "Поднимите лимиты для импорта: PHP memory_limit (512M и больше), max_execution_time, "
            "post_max_size (32M и больше); в nginx — client_max_body_size и fastcgi_read_timeout.",
            "Просмотрите package/*.csv и при необходимости поправьте package/manifest.json (import/apply).",
            "Агенты: добавьте адрес сервера/прокси 7.2 в Server= и ServerActive= в конфигурации агентов, "
            "иначе данные не пойдут; для удалённых команд нужен AllowKey=system.run[*].",
            "Сеть: от сервера/прокси 7.2 до агентов открыт порт 10050, от агентов к 7.2 — порт 10051, "
            "для SNMP — 161/udp.",
            "Запускайте в спокойное время: импорт создаёт много элементов данных и нагружает БД.",
            "Сначала выполните apply --dry-run, затем обычный запуск.",
        ],
    },
}
YES = {"да", "д", "yes", "y"}


def apply_summary(cfg, manifest, dry):
    m = manifest
    cnt = lambda lst, f="import": sum(1 for x in lst if x.get(f))
    status = lambda key: ("с исходным статусом" if cfg.get(key, "disabled") == "keep" else "ВЫКЛЮЧЕННЫМИ")
    lines = [
        f"Пакет подготовлен {m['prepared_at']} из {m['src_url']}",
        f"Будет: шаблонов {cnt(m['templates'])}, узлов {cnt(m['hosts'])}"
        f"{' (выключенными)' if cfg.get('hosts_disabled') else ''}, "
        f"дополнение существующих узлов {cnt(m['existing_hosts'], 'apply')}, "
        f"пустых групп {len(m.get('hostgroups', []))}, "
        f"правил обнаружения {cnt(m.get('drules', []))} ({status('drules_status')}), "
        f"способов оповещения {cnt(m['mediatypes'])}, действий {cnt(m['actions'])} ({status('actions_status')})",
    ]
    try:
        age = datetime.now() - datetime.fromisoformat(m["prepared_at"])
        if age.total_seconds() > 24 * 3600:
            lines.append(f"ВНИМАНИЕ: пакету {age.days} дн. {age.seconds // 3600} ч — "
                         f"если конфигурация менялась, повторите prepare")
    except ValueError:
        pass
    if dry:
        lines.append("Режим --dry-run: в 7.2 ничего не будет изменено.")
    return lines


def confirm_server(stage, title, url, items, extra, assume_yes):
    print(f"\n{'=' * 78}\n ПЕРЕД ЗАПУСКОМ «{stage}» — {title}\n {url}\n{'=' * 78}")
    for line in extra:
        print(f" {line}")
    if extra:
        print()
    for i, text in enumerate(items, 1):
        print(f" {i}. {text}")
    question = f"\nРекомендации для сервера «{title}» выполнены, продолжить? [да/нет]: "
    if assume_yes:
        print(question.strip() + " да (--yes)")
        return
    if not sys.stdin.isatty():
        raise SystemExit("Нет терминала для подтверждения: запустите интерактивно или добавьте --yes.")
    try:
        answer = input(question).strip().lower()
    except EOFError:
        answer = ""
    if answer not in YES:
        raise SystemExit("Отменено пользователем — ничего не выполнялось.")


def confirm_run(stage, cfg, manifest, dry, assume_yes):
    rec = RECOMMENDATIONS[stage]
    old_url = manifest["src_url"] if manifest else cfg["src"]["url"]
    extra = apply_summary(cfg, manifest, dry) if stage == "apply" else []
    confirm_server(stage, "СТАРЫЙ Zabbix 4.4", old_url, rec["old"], [], assume_yes)
    confirm_server(stage, "НОВЫЙ Zabbix 7.2", cfg["dst"]["url"], rec["new"], extra, assume_yes)
    log.info("рекомендации перед «%s» подтверждены для обоих серверов%s",
             stage, " (--yes)" if assume_yes else "")


def check_version(api, major):
    if not str(api.version).startswith(f"{major}."):
        raise SystemExit(f"[{api.name}] ожидалась версия {major}.x, а сервер отвечает {api.version} — "
                         f"проверьте src/dst в конфиге (не перепутаны ли).")


def main():
    ap = argparse.ArgumentParser(description="Миграция Zabbix 4.4 -> 7.2 через API в два этапа")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("prepare", help="сравнить 4.4 и 7.2 и подготовить пакет (7.2 не меняется)")
    p2 = sub.add_parser("apply", help="импортировать подготовленный пакет в 7.2")
    for p in (p1, p2):
        p.add_argument("-c", "--config", required=True)
        p.add_argument("-p", "--package", default="package", help="каталог пакета")
        p.add_argument("-v", "--verbose", action="store_true")
        p.add_argument("-y", "--yes", action="store_true",
                       help="не спрашивать подтверждение рекомендаций (для автоматического запуска)")
    p1.add_argument("--force", action="store_true", help="перезаписать существующий пакет")
    p2.add_argument("--dry-run", action="store_true", help="показать, что будет сделано, ничего не создавая")
    p2.add_argument("--steps", default=",".join(STEPS), help=f"через запятую из: {','.join(STEPS)}")
    args = ap.parse_args()

    # все проверки, не требующие серверов, — до вопросов, чтобы не подтверждать зря
    has_pkg = os.path.exists(os.path.join(args.package, "manifest.json"))
    if args.cmd == "prepare" and has_pkg and not args.force:
        raise SystemExit(f"В {args.package} уже есть пакет (возможно, с вашими правками). "
                         f"Укажите другой -p или --force.")
    if args.cmd == "apply" and not has_pkg:
        raise SystemExit(f"В {args.package} нет manifest.json — сначала выполните prepare")
    steps = set()
    if args.cmd == "apply":
        steps = {x.strip() for x in args.steps.split(",") if x.strip()}
        unknown = steps - set(STEPS)
        if unknown:
            raise SystemExit(f"Неизвестные шаги: {sorted(unknown)}; допустимые: {j(STEPS)}")
    cfg = load_json(args.config)
    manifest = load_json(os.path.join(args.package, "manifest.json")) if args.cmd == "apply" else None

    os.makedirs(args.package, exist_ok=True)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s",
                        handlers=[logging.StreamHandler(sys.stdout),
                                  logging.FileHandler(os.path.join(args.package, f"{args.cmd}.log"),
                                                      encoding="utf-8")])
    # рекомендации и подтверждение — до любого подключения к серверам и изменения файлов
    confirm_run(args.cmd, cfg, manifest, getattr(args, "dry_run", False), args.yes)

    if args.cmd == "prepare" and has_pkg:
        # чтобы в пакете не остались файлы прошлой подготовки (и старый manifest при сбое)
        for sub_dir in PACKAGE_DIRS:
            shutil.rmtree(os.path.join(args.package, sub_dir), ignore_errors=True)
        for f in os.listdir(args.package):
            if f == "manifest.json" or f.endswith(".csv"):
                os.remove(os.path.join(args.package, f))

    d = cfg["dst"]
    dst = ZabbixAPI("7.2", d["url"], d.get("user"), d.get("password"), d.get("token"),
                    verify=d.get("verify_ssl", True))
    check_version(dst, 7)
    if args.cmd == "prepare":
        s = cfg["src"]
        src = ZabbixAPI("4.4", s["url"], s.get("user"), s.get("password"),
                        verify=s.get("verify_ssl", True), legacy=True)
        check_version(src, 4)
        Preparer(cfg, src, dst, args.package).run()
    else:
        if Applier(cfg, dst, args.package, args.dry_run).run(steps):
            sys.exit(1)


if __name__ == "__main__":
    main()
