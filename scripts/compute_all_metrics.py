#!/usr/bin/env python3
"""
Calcula TP/FP/FN para todas las herramientas de todas las fases
contra el ground truth verificado (196 CVEs).
"""
import json, csv, sys
import re
from pathlib import Path

PROJ = Path(__file__).parent.parent
RES  = PROJ / 'tests' / 'sca_results'
DOCS = PROJ / 'docs'

# ── Cargar Ground Truth ───────────────────────────────────────────────────────
def load_gt(path):
    gt = {}
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            cid = row['cve_id'].strip()
            gt[cid] = row
    return gt

gt_all  = load_gt(DOCS / 'ground_truth.csv')          # 196 CVEs (todas las fases)
# 'phases_detectable' contiene valores como "1,3" o "1,2,3" o "2,3" o "3"
gt_p1   = {k: v for k, v in gt_all.items() if '1' in v.get('phases_detectable', '').split(',')}
gt_p2   = {k: v for k, v in gt_all.items() if '2' in v.get('phases_detectable', '').split(',')}
gt_p3   = gt_all   # fase 3 usa GT completo (196)

try:
    gt_p3eff = load_gt(DOCS / 'ground_truth_phase3_effective.csv')  # 37 CVEs
except FileNotFoundError:
    gt_p3eff = {}

print(f"GT total: {len(gt_all)} | P1: {len(gt_p1)} | P2: {len(gt_p2)} | P3_eff: {len(gt_p3eff)}")


# ── Extractores de CVEs por herramienta ──────────────────────────────────────

def extract_grype(path):
    data = json.load(open(path, encoding='utf-8'))
    cves = set()
    for m in data.get('matches', []):
        vid = m.get('vulnerability', {}).get('id', '')
        if vid.startswith('CVE'):
            cves.add(vid)
    return cves

def extract_trivy(path):
    data = json.load(open(path, encoding='utf-8'))
    cves = set()
    results = data if isinstance(data, list) else data.get('Results', [])
    for r in results:
        for v in r.get('Vulnerabilities', []) or []:
            vid = v.get('VulnerabilityID', '')
            if vid.startswith('CVE'):
                cves.add(vid)
    return cves

def extract_snyk_p1(path):
    data = json.load(open(path, encoding='utf-8'))
    cves = set()
    # Phase 1: list of project scan results
    items = data if isinstance(data, list) else [data]
    for item in items:
        for v in item.get('vulnerabilities', []):
            for ident in v.get('identifiers', {}).get('CVE', []):
                if ident.startswith('CVE'):
                    cves.add(ident)
    return cves

def extract_snyk_p2(path):
    """Phase 2 --unmanaged: formato diferente"""
    data = json.load(open(path, encoding='utf-8'))
    cves = set()
    # puede ser list o dict
    if isinstance(data, list):
        for item in data:
            if isinstance(item, list):
                for sub in item:
                    for v in sub.get('vulnerabilities', []):
                        for c in v.get('identifiers', {}).get('CVE', []):
                            cves.add(c)
            else:
                for v in item.get('vulnerabilities', []):
                    for c in v.get('identifiers', {}).get('CVE', []):
                        cves.add(c)
    elif isinstance(data, dict):
        for v in data.get('vulnerabilities', []):
            for c in v.get('identifiers', {}).get('CVE', []):
                cves.add(c)
    return cves

def extract_dtrack(path):
    data = json.load(open(path, encoding='utf-8'))
    cves = set()
    for finding in data if isinstance(data, list) else data.get('findings', []):
        vuln = finding.get('vulnerability', {}) if isinstance(finding, dict) else {}
        vid = vuln.get('vulnId', '')
        if vid.startswith('CVE'):
            cves.add(vid)
    return cves

def extract_cbt(path):
    data = json.load(open(path, encoding='utf-8'))
    cves = set()
    for item in data:
        cve = item.get('cve_number') or item.get('CVE', '')
        if str(cve).startswith('CVE'):
            cves.add(str(cve))
    return cves

def extract_owasp_dc(path):
    data = json.load(open(path, encoding='utf-8'))
    cves = set()
    for dep in data.get('dependencies', []):
        for vuln in dep.get('vulnerabilities', []):
            name = vuln.get('name', '')
            if name.startswith('CVE'):
                cves.add(name)
    return cves

def extract_emba(path):
    """
    Extrae CVEs de EMBA usando el JSON de estado (`phase3_emba_latest.json`).
    Busca CVEs en:
    1) log_file de ejecucion
    2) report_path (recursivo)
    """
    status = json.load(open(path, encoding='utf-8'))
    cves = set()
    cve_re = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)

    def collect_from_file(file_path: Path):
        if not file_path.is_file():
            return
        try:
            # Evita lecturas pesadas de binarios/artefactos grandes.
            if file_path.stat().st_size > 5 * 1024 * 1024:
                return
            text = file_path.read_text(encoding='utf-8', errors='ignore')
            for m in cve_re.findall(text):
                cves.add(m.upper())
        except Exception:
            return

    def collect_from_tree(root: Path):
        if not root.is_dir():
            return
        for p in root.rglob('*'):
            collect_from_file(p)

    log_file = status.get('log_file', '')
    if log_file:
        collect_from_file(Path(log_file))

    report_path = status.get('report_path', '')
    if report_path:
        report_dir = Path(report_path)
        collect_from_tree(report_dir)

    # Fallback: si latest no tiene CVEs parseables, usar el artefacto EMBA
    # mas reciente con contenido util para no perder visibilidad en metricas.
    if not cves:
        candidates = []
        candidates.extend(sorted(RES.glob('emba_forced_run*')))
        candidates.extend(sorted(RES.glob('emba_out_*')))
        for candidate in sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True):
            before = len(cves)
            if candidate.is_dir():
                collect_from_tree(candidate)
            if len(cves) > before:
                break

    return cves


# ── Calcular métricas ────────────────────────────────────────────────────────
def metrics(detected, ground_truth_set):
    tp = detected & ground_truth_set
    fp = detected - ground_truth_set
    fn = ground_truth_set - detected
    n_tp, n_fp, n_fn = len(tp), len(fp), len(fn)
    prec = n_tp / (n_tp + n_fp) if (n_tp + n_fp) else 0
    rec  = n_tp / len(ground_truth_set) if ground_truth_set else 0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    return {
        'TP': n_tp, 'FP': n_fp, 'FN': n_fn,
        'Precision': round(prec * 100, 1),
        'Recall': round(rec * 100, 1),
        'F1': round(f1, 3),
        'tp_cves': sorted(tp),
        'fp_cves': sorted(fp),
        'fn_cves': sorted(fn)
    }

def safe_extract(extractor, path, label):
    try:
        cves = extractor(path)
        print(f"  {label}: {len(cves)} CVEs detectados")
        return cves
    except Exception as e:
        print(f"  {label}: ERROR — {e}")
        return set()


# ── FASE 1 ────────────────────────────────────────────────────────────────────
print("\n=== FASE 1 (GT=", len(gt_p1), "CVEs) ===")
gt1 = set(gt_p1.keys())

grype1  = safe_extract(extract_grype,   RES/'phase1_grype_latest.json',  'Grype P1')
trivy1  = safe_extract(extract_trivy,   RES/'trivy_fase1_sbom.json',     'Trivy P1')
snyk1   = safe_extract(extract_snyk_p1, RES/'phase1_snyk_latest.json',   'Snyk P1')
dtrack1 = safe_extract(extract_dtrack,  RES/'phase1_dtrack_latest.json', 'D-Track P1')

m_grype1  = metrics(grype1,  gt1)
m_trivy1  = metrics(trivy1,  gt1)
m_snyk1   = metrics(snyk1,   gt1)
m_dtrack1 = metrics(dtrack1, gt1)

# ── FASE 2 ────────────────────────────────────────────────────────────────────
print("\n=== FASE 2 (GT=", len(gt_p2), "CVEs) ===")
gt2 = set(gt_p2.keys())

snyk2  = safe_extract(extract_snyk_p2,  RES/'phase2_snyk_latest.json',   'Snyk P2 --unmanaged')
dc2    = safe_extract(extract_owasp_dc, RES/'phase2_dc_latest.json',     'OWASP DC')

m_snyk2 = metrics(snyk2, gt2)
m_dc2   = metrics(dc2,   gt2)

# ── FASE 3 ────────────────────────────────────────────────────────────────────
print("\n=== FASE 3 — GT completo (GT=", len(gt_p3), "CVEs) ===")
gt3      = set(gt_p3.keys())
gt3eff   = set(gt_p3eff.keys())

cbt3    = safe_extract(extract_cbt,    RES/'phase3_cbt_latest.json',    'CBT P3')
grype3  = safe_extract(extract_grype,  RES/'phase3_grype_latest.json',  'Grype P3 binary')
trivy3  = safe_extract(extract_trivy,  RES/'phase3_trivy_latest.json',  'Trivy P3 binary')
emba3   = safe_extract(extract_emba,   RES/'phase3_emba_latest.json',   'EMBA P3 firmware')

m_cbt3     = metrics(cbt3,   gt3)
m_cbt3eff  = metrics(cbt3,   gt3eff)
m_grype3   = metrics(grype3, gt3)
m_trivy3   = metrics(trivy3, gt3)
m_emba3    = metrics(emba3,  gt3)


# ── Imprimir tabla ────────────────────────────────────────────────────────────
def print_table(rows):
    hdr = f"{'Herramienta':<35} {'GT':>5} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec%':>7} {'Rec%':>7} {'F1':>6}"
    print(hdr)
    print('-' * len(hdr))
    for tool, gt_n, m in rows:
        print(f"{tool:<35} {gt_n:>5} {m['TP']:>4} {m['FP']:>4} {m['FN']:>4} "
              f"{m['Precision']:>6.1f}% {m['Recall']:>6.1f}% {m['F1']:>6.3f}")

print("\n" + "="*80)
print("RESULTADOS COMPLETOS")
print("="*80)
print("\nFASE 1 — SBOM")
print_table([
    ('Grype v0.109',           len(gt1), m_grype1),
    ('Dependency-Track v4.11', len(gt1), m_dtrack1),
    ('Snyk v1.x',              len(gt1), m_snyk1),
    ('Trivy v0.69',            len(gt1), m_trivy1),
])

print("\nFASE 2 — VENDORING")
print_table([
    ('Snyk --unmanaged',       len(gt2), m_snyk2),
    ('OWASP Dependency Check', len(gt2), m_dc2),
])

print("\nFASE 3 — BINARIO (GT completo, 196 CVEs)")
print_table([
    ('CVE-Binary-Tool v3.4',   len(gt3), m_cbt3),
    ('Grype (binary)',         len(gt3), m_grype3),
    ('Trivy (binary)',         len(gt3), m_trivy3),
    ('EMBA (firmware)',        len(gt3), m_emba3),
])

if gt3eff:
    print("\nFASE 3 — BINARIO (GT efectivo, 37 CVEs)")
    print_table([
        ('CVE-Binary-Tool v3.4 (GT_eff)', len(gt3eff), m_cbt3eff),
    ])

# ── Detalle FP/FN relevantes ──────────────────────────────────────────────────
print("\n--- GRYPE P1 FP:", m_grype1['FP'], "---")
for c in m_grype1['fp_cves'][:15]: print(f"  {c}")

print("\n--- SNYK P2 FP:", m_snyk2['FP'], "FN:", m_snyk2['FN'], "---")
print("  FP:", m_snyk2['fp_cves'])
print("  FN:", m_snyk2['fn_cves'])

print("\n--- OWASP DC P2 TP/FP:", m_dc2['TP'], "/", m_dc2['FP'], "---")
if m_dc2['tp_cves']:
    print("  TP:", m_dc2['tp_cves'])
if m_dc2['fp_cves']:
    print("  FP:", m_dc2['fp_cves'][:10])

print("\n--- CBT P3 TP/FP/FN:", m_cbt3['TP'], "/", m_cbt3['FP'], "/", m_cbt3['FN'], "---")
print("  TP:", m_cbt3['tp_cves'])
print("  FP:", m_cbt3['fp_cves'])

print("\n--- EMBA P3 TP/FP/FN:", m_emba3['TP'], "/", m_emba3['FP'], "/", m_emba3['FN'], "---")
print("  TP:", m_emba3['tp_cves'])
print("  FP:", m_emba3['fp_cves'])

# ── Guardar métricas ──────────────────────────────────────────────────────────
result = {
    'phase1': {
        'grype':   {k: v for k, v in m_grype1.items()  if k not in ('tp_cves','fp_cves','fn_cves')},
        'dtrack':  {k: v for k, v in m_dtrack1.items() if k not in ('tp_cves','fp_cves','fn_cves')},
        'snyk':    {k: v for k, v in m_snyk1.items()   if k not in ('tp_cves','fp_cves','fn_cves')},
        'trivy':   {k: v for k, v in m_trivy1.items()  if k not in ('tp_cves','fp_cves','fn_cves')},
    },
    'phase2': {
        'snyk_unmanaged': {k: v for k, v in m_snyk2.items() if k not in ('tp_cves','fp_cves','fn_cves')},
        'owasp_dc':       {k: v for k, v in m_dc2.items()   if k not in ('tp_cves','fp_cves','fn_cves')},
    },
    'phase3_full_gt': {
        'cbt':   {k: v for k, v in m_cbt3.items()   if k not in ('tp_cves','fp_cves','fn_cves')},
        'grype': {k: v for k, v in m_grype3.items() if k not in ('tp_cves','fp_cves','fn_cves')},
        'trivy': {k: v for k, v in m_trivy3.items() if k not in ('tp_cves','fp_cves','fn_cves')},
        'emba':  {k: v for k, v in m_emba3.items()  if k not in ('tp_cves','fp_cves','fn_cves')},
    },
    'phase3_effective_gt': {
        'cbt': {k: v for k, v in m_cbt3eff.items() if k not in ('tp_cves','fp_cves','fn_cves')},
    } if gt3eff else {}
}

out = DOCS / 'metrics_final.json'
with open(out, 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=2)
print(f"\nMétricas guardadas en {out}")
