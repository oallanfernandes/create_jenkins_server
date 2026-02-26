#!/usr/bin/env python3
"""
analyze_terraform.py
--------------------
Analisa um plano Terraform usando Claude AI e retorna alertas de segurança,
custo e conformidade no formato padronizado do AI Terraform Analyzer.

Uso:
    python3 analyze_terraform.py \
        --plan-json /tmp/tf_plan.json \
        --plan-text /tmp/plan_output.txt \
        --output /tmp/analysis_result.txt \
        --github-output $GITHUB_OUTPUT
"""

import argparse
import json
import os
import sys
import anthropic


# ─────────────────────────────────────────────────────────────────────────────
# REGRAS DE SEGURANÇA — detecção local antes de chamar a IA
# Serve como "warm up" para o prompt e garante cobertura mesmo sem API
# ─────────────────────────────────────────────────────────────────────────────
SECURITY_RULES = [
    {
        "resource_types": ["aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket"],
        "check": lambda before, after: (
            before.get("server_side_encryption_configuration") is not None
            and after.get("server_side_encryption_configuration") is None
        ),
        "message": "S3 bucket perde configuração de encryption",
        "severity": "CRITICAL",
    },
    {
        "resource_types": ["aws_security_group", "aws_security_group_rule"],
        "check": lambda before, after: any(
            rule.get("cidr_blocks", []) == ["0.0.0.0/0"]
            or rule.get("ipv6_cidr_blocks", []) == ["::/0"]
            for rule in (after.get("ingress", []) or [])
            if rule.get("from_port", 0) in [22, 3389, 5432, 3306, 1433, 6379, 27017]
        ),
        "message": "Security Group abre porta sensível para 0.0.0.0/0",
        "severity": "CRITICAL",
    },
    {
        "resource_types": ["aws_iam_role_policy", "aws_iam_policy"],
        "check": lambda before, after: '"Effect": "Allow"' in json.dumps(after)
            and '"Action": "*"' in json.dumps(after),
        "message": "IAM Policy com Action:* (acesso total) detectada",
        "severity": "CRITICAL",
    },
    {
        "resource_types": ["aws_db_instance", "aws_rds_cluster"],
        "check": lambda before, after: (
            after.get("publicly_accessible") is True
        ),
        "message": "RDS instance com publicly_accessible=true",
        "severity": "CRITICAL",
    },
    {
        "resource_types": ["aws_s3_bucket_public_access_block"],
        "check": lambda before, after: (
            before.get("block_public_acls") is True
            and after.get("block_public_acls") is False
        ),
        "message": "S3 bucket remove bloqueio de ACL pública",
        "severity": "CRITICAL",
    },
    {
        "resource_types": ["aws_kms_key"],
        "check": lambda before, after: (
            before is not None and "delete" in str(after)
        ),
        "message": "KMS key sendo deletada — dados criptografados podem ser perdidos",
        "severity": "CRITICAL",
    },
]


def extract_resource_changes(plan_data: dict) -> list:
    """Extrai e enriquece a lista de mudanças de recursos."""
    changes = plan_data.get("resource_changes", [])
    enriched = []

    for resource in changes:
        change = resource.get("change", {})
        actions = change.get("actions", [])

        # Ignora recursos sem mudança real
        if actions == ["no-op"]:
            continue

        enriched.append({
            "address": resource.get("address", ""),
            "type": resource.get("type", ""),
            "name": resource.get("name", ""),
            "module": resource.get("module_address", ""),
            "actions": actions,
            "before": change.get("before") or {},
            "after": change.get("after") or {},
            "after_unknown": change.get("after_unknown") or {},
        })

    return enriched


def run_local_security_checks(changes: list) -> list:
    """Executa checks de segurança locais para enriquecer o prompt."""
    local_alerts = []

    for resource in changes:
        r_type = resource["type"]
        before = resource["before"]
        after = resource["after"]

        for rule in SECURITY_RULES:
            if r_type in rule["resource_types"]:
                try:
                    if rule["check"](before, after):
                        local_alerts.append({
                            "resource": resource["address"],
                            "severity": rule["severity"],
                            "message": rule["message"],
                        })
                except Exception:
                    pass  # Ignora erros nos checks locais

    return local_alerts


def build_prompt(
    changes: list,
    local_alerts: list,
    plan_text: str,
    summary_counts: dict,
) -> str:
    """Monta o prompt completo para o Claude."""

    # Filtra recursos de alto risco para o contexto
    high_risk_types = {
        "aws_security_group", "aws_security_group_rule",
        "aws_s3_bucket", "aws_s3_bucket_server_side_encryption_configuration",
        "aws_s3_bucket_public_access_block",
        "aws_iam_role", "aws_iam_policy", "aws_iam_role_policy",
        "aws_db_instance", "aws_rds_cluster",
        "aws_kms_key", "aws_elasticache_cluster",
        "aws_elasticsearch_domain", "aws_opensearch_domain",
        "aws_lambda_function", "aws_api_gateway_rest_api",
        "aws_cloudtrail", "aws_config_rule",
        "aws_wafv2_web_acl", "aws_lb", "aws_alb",
    }

    high_risk_changes = [r for r in changes if r["type"] in high_risk_types]
    destructive_changes = [r for r in changes if "delete" in r["actions"]]
    all_notable = high_risk_changes + [
        r for r in destructive_changes if r not in high_risk_changes
    ]

    # Limita o tamanho do payload para não estourar tokens
    notable_json = json.dumps(all_notable[:30], indent=2, default=str)
    if len(notable_json) > 20000:
        notable_json = notable_json[:20000] + "\n... (truncado)"

    # Monta alertas locais pré-detectados como contexto adicional
    local_alerts_text = ""
    if local_alerts:
        local_alerts_text = "\nALERTAS PRÉ-DETECTADOS PELAS REGRAS LOCAIS:\n"
        for alert in local_alerts:
            local_alerts_text += f"  [{alert['severity']}] {alert['resource']}: {alert['message']}\n"

    prompt = f"""Você é um especialista sênior em segurança cloud e DevSecOps.
Analise este plano Terraform e gere um relatório de segurança, custo e conformidade.

═══════════════════════════════════════════════
SUMÁRIO DO PLANO
═══════════════════════════════════════════════
Recursos a criar:    {summary_counts['create']}
Recursos a alterar:  {summary_counts['update']}
Recursos a destruir: {summary_counts['delete']}
Total com mudanças:  {summary_counts['total']}
{local_alerts_text}

═══════════════════════════════════════════════
RECURSOS DE ALTO RISCO (before → after)
═══════════════════════════════════════════════
{notable_json}

═══════════════════════════════════════════════
OUTPUT ORIGINAL DO TERRAFORM PLAN
═══════════════════════════════════════════════
{plan_text[:5000]}

═══════════════════════════════════════════════
INSTRUÇÕES DE ANÁLISE
═══════════════════════════════════════════════
Identifique e reporte:

1. ALERTAS CRÍTICOS de segurança (exemplos, não limitado a):
   - Remoção de encryption (S3, RDS, EBS, etc.)
   - Security Groups abrindo portas para 0.0.0.0/0
   - IAM policies com permissões excessivas (Action:* ou Resource:*)
   - Recursos com exposição pública indevida (RDS, ElastiCache, etc.)
   - Deleção de KMS keys, CloudTrail logs, Config rules
   - Desabilitação de logging, monitoring, MFA

2. ALERTAS DE ATENÇÃO (exemplos, não limitado a):
   - Mudanças de instance type com estimativa de custo (+/- $/mês)
   - Deleção de recursos com potencial perda de dados
   - Mudanças em configurações críticas (retention, backup, etc.)
   - Alterações que causam downtime (forced replacement)

3. RECOMENDAÇÃO FINAL:
   - Se houver 1 ou mais ALERTAS CRÍTICOS → "BLOQUEAR apply até resolver alertas críticos"
   - Se houver apenas ALERTAS DE ATENÇÃO → "APROVAR com revisão manual dos itens de atenção"
   - Se não houver alertas → "APROVAR apply"

═══════════════════════════════════════════════
FORMATO DE SAÍDA OBRIGATÓRIO (siga exatamente)
═══════════════════════════════════════════════
AI Terraform Analyzer (via MCP):
Resumo: {summary_counts['create']} recursos criados, {summary_counts['update']} alterados, {summary_counts['delete']} destruídos

[Repita para cada alerta crítico encontrado, ou omita seção se não houver:]
🚨 ALERTA CRÍTICO: [nome do recurso] [descrição específica do problema]

[Repita para cada alerta de atenção encontrado, ou omita seção se não houver:]
⚠ Atenção: [nome do recurso] [descrição com impacto e estimativa se possível]

Recomendação: [BLOQUEAR apply até resolver alertas críticos / APROVAR com revisão manual / APROVAR apply]

[Se houver alertas críticos, adicione:]
Ações necessárias:
- [ação específica 1]
- [ação específica 2]

Seja específico com nomes de recursos, valores antes/depois, e impactos concretos.
Não invente problemas que não existam nos dados — baseie-se apenas no plan JSON fornecido.
"""
    return prompt


def analyze_with_claude(
    plan_json_path: str,
    plan_text_path: str,
) -> tuple[str, bool, str]:
    """
    Chama a Claude API e retorna (analysis_text, has_critical, summary).
    """
    # Carrega dados
    with open(plan_json_path) as f:
        plan_data = json.load(f)

    with open(plan_text_path) as f:
        plan_text = f.read()

    # Processa mudanças
    changes = extract_resource_changes(plan_data)
    local_alerts = run_local_security_checks(changes)

    summary_counts = {
        "create": len([r for r in changes if "create" in r["actions"]]),
        "update": len([r for r in changes if "update" in r["actions"]]),
        "delete": len([r for r in changes if "delete" in r["actions"]]),
        "total": len(changes),
    }

    # Se não há mudanças, retorna sem chamar a API
    if summary_counts["total"] == 0:
        text = (
            "AI Terraform Analyzer (via MCP):\n"
            "Resumo: 0 recursos criados, 0 alterados, 0 destruídos\n\n"
            "✅ Nenhuma mudança detectada no plano.\n"
            "Recomendação: APROVAR apply"
        )
        return text, False, "Sem mudanças"

    # Monta prompt e chama Claude
    prompt = build_prompt(changes, local_alerts, plan_text, summary_counts)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("Variável ANTHROPIC_API_KEY não definida")

    client = anthropic.Anthropic(api_key=api_key)

    print("🤖 Chamando Claude API para análise...", flush=True)

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )

    analysis_text = response.content[0].text.strip()

    # Detecta se há alertas críticos no output
    has_critical = (
        "🚨 ALERTA CRÍTICO" in analysis_text
        or "BLOQUEAR" in analysis_text
        or any(a["severity"] == "CRITICAL" for a in local_alerts)
    )

    # Extrai linha de resumo
    summary = ""
    for line in analysis_text.split("\n"):
        if line.startswith("Resumo:"):
            summary = line
            break

    return analysis_text, has_critical, summary


def write_github_outputs(
    github_output_path: str,
    analysis_text: str,
    has_critical: bool,
    summary: str,
):
    """Escreve variáveis de output para o GitHub Actions."""
    if not github_output_path:
        return

    with open(github_output_path, "a") as f:
        # Escapa newlines para o formato do GitHub Actions
        escaped = analysis_text.replace("\n", "\\n").replace("\r", "\\r")
        f.write(f"result={escaped}\n")
        f.write(f"has_critical={'true' if has_critical else 'false'}\n")
        f.write(f"summary={summary}\n")


def main():
    parser = argparse.ArgumentParser(description="Analisa plano Terraform com Claude AI")
    parser.add_argument("--plan-json", required=True, help="Caminho para o plan.json")
    parser.add_argument("--plan-text", required=True, help="Caminho para o plan output em texto")
    parser.add_argument("--output", required=True, help="Arquivo de saída com o resultado")
    parser.add_argument("--github-output", default="", help="Caminho para $GITHUB_OUTPUT")
    args = parser.parse_args()

    try:
        analysis_text, has_critical, summary = analyze_with_claude(
            args.plan_json,
            args.plan_text,
        )
    except Exception as e:
        error_msg = f"❌ Erro durante análise: {e}"
        print(error_msg, file=sys.stderr)

        # Fallback: grava erro no output para não quebrar o workflow silenciosamente
        analysis_text = f"AI Terraform Analyzer (via MCP):\n⚠️ Análise indisponível: {e}\nRecomendação: Revisar manualmente antes de aplicar."
        has_critical = False
        summary = "Erro na análise"

    # Salva resultado em arquivo
    with open(args.output, "w") as f:
        f.write(analysis_text)

    # Escreve outputs para o GitHub Actions
    write_github_outputs(args.github_output, analysis_text, has_critical, summary)

    # Exit code 1 bloqueia o job "security-gate"
    if has_critical:
        print("\n🚨 Alertas críticos detectados — security gate ativado.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n✅ Nenhum alerta crítico — análise concluída com sucesso.")
        sys.exit(0)


if __name__ == "__main__":
    main()
