import json
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Este diccionario contiene toda la información necesaria para 
# generar el manual de mitigación, actuando como una base de datos.
# Cada entrada nueva agranda la efectividad del manual a la hora de
# detectar y mitigar vulnerabilidades.
mitigation_manual_db = {
    #Bandit
    "B307": {
        "herramienta": "Bandit",
        "titulo": "Uso de eval()",
        "descripcion": "eval() puede ejecutar código arbitrario si recibe entrada externa.",
        "impacto": "Permite ejecución remota no deseada.",
        "recomendacion": "Usar ast.literal_eval() o evitar eval() completamente.",
        "ej_inseguro": "eval(user_input)",
        "ej_seguro": "import ast\nast.literal_eval(user_input)"
    },
    "B602": {
        "herramienta": "Bandit",
        "titulo": "Uso de subprocess con shell=True",
        "descripcion": "El uso de shell=True puede permitir ejecución de comandos arbitrarios.",
        "impacto": "Posible inyección de comandos del sistema.",
        "recomendacion": "Evitar shell=True y usar listas de argumentos.",
        "ej_inseguro": 'subprocess.run("ls " + user_input, shell=True)',
        "ej_seguro": 'subprocess.run(["ls", user_input])'
    },
    "B605": {
        "herramienta": "Bandit",
        "titulo": "Uso de os.system con entrada sin sanitizar",
        "descripcion": "`os.system()` ejecuta comandos del sistema operativo directamente.",
        "impacto": "Si se pasa entrada del usuario sin sanitizar, puede permitir ejecución de comandos arbitrarios.",
        "mitigacion": "Evita `os.system()` siempre que sea posible. Usa `subprocess.run()` con listas y sin `shell=True`.",
        "ej_inseguro": 'os.system("ls " + user_input)',
        "ej_seguro": 'import subprocess\nsubprocess.run(["ls", user_input])'
    },
    "B102": {
        "herramienta": "Bandit",
        "titulo": "Uso de exec()",
        "descripcion": "`exec()` ejecuta código dinámico, lo que es extremadamente peligroso si se usa con datos no confiables.",
        "impacto": "Puede llevar a ejecución arbitraria de código.",
        "mitigacion": "Evitar completamente `exec()` y usar alternativas como funciones o diccionarios.",
        "ej_inseguro": 'exec("print(1 + 1)")',
        "ej_seguro": '# Usar funciones seguras\nresult = eval("1 + 1", {"__builtins__": {}})'
    },
    #TFLint
    "terraform_required_version": {
        "herramienta": "TFLint",
        "titulo": "No se tiene el bloque required_version",
        "descripcion": "No se ha definido una versión mínima de Terraform.",
        "impacto": "Podría ejecutarse con versiones incompatibles.",
        "recomendacion": 'Agregar el bloque:\n```hcl\nterraform {\n  required_version = ">= 1.0.0"\n}\n```'
    },
    "terraform_required_providers": {
        "herramienta": "TFLint",
        "titulo": "Faltan restricciones en required_providers",
        "descripcion": "No se especifica la versión del proveedor.",
        "impacto": "Puede usarse una versión inestable o insegura.",
        "recomendacion": 'Agregar restricciones:\n```hcl\nterraform {\n'\
              '  required_providers {\n    null = {\n'\
                      '      source = "hashicorp/null"\n      version = "~> 3.0"\n    }\n  }\n}\n```'
    },
    "terraform_deprecated_interpolation": {
        "herramienta": "TFLint",
        "titulo": "Uso de interpolaciones obsoletas",
        "descripcion": "Se están utilizando expresiones `${}` innecesarias en strings.",
        "impacto": "Causa warnings en Terraform >= 0.12 y puede ser eliminado en futuras versiones.",
        "recomendacion": 'Reemplazar `${var.foo}` por `var.foo` directamente.'
    },
    # Checkov
    "CKV_CUSTOM_1": {
        "herramienta": "Checkov",
        "titulo": "Etiquetas obligatorias ausentes",
        "descripcion": "El recurso no tiene las etiquetas `Name`, `Owner` y `Env`.",
        "impacto": "Los recursos no son trazables ni gobernables.",
        "recomendacion": 'Agregar etiquetas:\n```hcl\ntriggers = {\n  Name  = "resource-name"\n  Owner = "equipo"\n  Env   = "entorno"\n}\n```'
    },
    "CKV_CUSTOM_2": {
        "herramienta": "Checkov",
        "titulo": "Formato no válido de etiquetas",
        "descripcion": "Las etiquetas deben seguir el formato `^[a-z0-9-]+$`.",
        "impacto": "No cumplen con el estándar organizacional.",
        "recomendacion": 'Usar nombres válidos:\n```hcl\nName = "web-app"\nOwner = "team-name"\nEnv = "prod"\n```'
    },
    #Network issues
    "ip peligrosa": {
        "herramienta": "Network validator",
        "titulo": "IP peligrosa permitida: 0.0.0.0/0",
        "descripcion": "Se permite acceso desde cualquier IP pública sin restricciones.",
        "impacto": "Riesgo elevado de accesos no autorizados o ataques remotos.",
        "recomendacion": "Restringe los rangos de IPs a los estrictamente necesarios, usando listas blancas específicas."
    },

    "puerto inseguro": {
        "herramienta": "Network validator",
        "titulo": "Puerto inseguro (<1024) habilitado",
        "descripcion": "Se permite tráfico hacia puertos reservados del sistema.",
        "impacto": "Podrían estar asociados a servicios sensibles o inseguros.",
        "recomendacion": "Verifica si el servicio en ese puerto es necesario. Usa autenticación fuerte o cambia a puertos no reservados si es posible."
    },

    "puerto de alto riesgo": {
        "herramienta": "Network validator",
        "titulo": "Puerto de alto riesgo habilitado",
        "descripcion": "Se habilitó un puerto conocido por su historial de vulnerabilidades.",
        "impacto": "Puede ser explotado por atacantes si no está bien protegido.",
        "recomendacion": "Evita exponer puertos como 21, 23, 445, etc., salvo que sea absolutamente necesario y estén protegidos."
    },

    "rango de puertos amplio": {
        "herramienta": "Network validator",
        "titulo": "Rango de puertos muy amplio",
        "descripcion": "Se han habilitado más de 100 puertos simultáneamente.",
        "impacto": "Aumenta la superficie de ataque y complica el control de seguridad.",
        "recomendacion": "Restringe el rango de puertos al mínimo indispensable para tu aplicación."
    },

    "nombre de red por defecto": {
        "herramienta": "Network validator",
        "titulo": "Uso de nombre de red por defecto",
        "descripcion": "Se está utilizando un nombre genérico como 'dummy-network'.",
        "impacto": "Puede generar confusión en entornos compartidos o errores de configuración.",
        "recomendacion": "Usa nombres significativos que reflejen la función o contexto de la red."
    },

    "protocolo permisivo": {
        "herramienta": "Network Validator",
        "titulo": "Uso de protocolo permisivo ('all')",
        "descripcion": "Se permite todo tipo de tráfico de red sin restricción de protocolo.",
        "impacto": "Puede habilitar tráfico no deseado o no controlado.",
        "recomendacion": "Limita los protocolos a los estrictamente necesarios, como 'tcp', 'udp' o 'icmp'."
    }

}

# Esta función extrae los errores relacionados con etiquetas obligatorias de TFLint.
def get_tflint_tag_errors(tflint_file):
    tag_errors = []

    with open(tflint_file) as f:
        json_tflint = json.load(f)
        for entry in json_tflint["issues"]:
            if (
                "missing tag" in entry["message"]
                or "Attribute validation error for tag" in entry["message"]
            ):
                tag_errors.append(
                    {
                        "file": entry["range"]["filename"],
                        "line": entry["range"]["start"]["line"],
                        "message": entry["message"],
                    }
                )
    return tag_errors


# Esta función extrae los problemas de seguridad detectados por Bandit.
def get_bandit_issues(bandit_file, severity="HIGH"):
    issues = []

    with open(bandit_file) as f:
        json_bandit = json.load(f)
        for result in json_bandit.get("results", []):
            if isinstance(severity, list):
                if result["issue_severity"] in severity:
                    issues.append(
                        {
                            "file": result["filename"],
                            "line": result["line_number"],
                            "test_id": result["test_id"],
                            "issue_text": result["issue_text"],
                        }
                    )
            if result["issue_severity"] == severity:
                issues.append(
                    {
                        "file": result["filename"],
                        "line": result["line_number"],
                        "test_id": result["test_id"],
                        "issue_text": result["issue_text"],
                    }
                )
    return issues


# Esta función extrae los problemas de seguridad detectados por TFLint.
def get_tflint_issues(tflint_files):
    rules_violated = []
    for tflint_file in tflint_files:
        with open(tflint_file) as f:
            json_tflint = json.load(f)
            for entry in json_tflint["issues"]:
                rule_info = entry.get("rule")
                if rule_info:
                    rules_violated.append(
                        {
                            "file": entry["range"]["filename"],
                            "line": entry["range"]["start"]["line"],
                            "severity": rule_info.get("severity", "0"),
                            "message": entry["message"],
                            "rule_name": rule_info.get("name"),
                            "link": rule_info.get("link", "N/A"),
                        }
                    )
    return rules_violated


# Esta función extrae los problemas de Checkov relacionados con etiquetas obligatorias.
# El filtro cambiará en el sprint 2.
def get_checkov_issues(findings_file):
    issues = []
   
    with open(findings_file) as f:
        json_checkov = json.load(f)
        failed_checks = json_checkov.get("results", {}).get("failed_checks", [])

        for entry in failed_checks:
            # Filtra solo los resultados correspondientes al ruleset personalizado
            if entry.get("check_id", "").startswith("CKV_CUSTOM"):
                issues.append({
                    "file": entry["file_path"],
                    "start_line": entry["file_line_range"][0],
                    "end_line": entry["file_line_range"][1],
                    "resource": entry["resource"],
                    "check_id": entry["check_id"],
                    "severity": entry["severity"],
                    "message": entry["check_name"],
                    "guideline": entry["guideline"]
                })
    
    return issues

# Esta función extrae los problemas detectados en la configuración de red simulada
def get_network_json_issues(network_report_file):
    network_issues = []

    with open(network_report_file) as f:
        report = json.load(f)

        # Procesar los errores reportados 
        for error in report.get("errores", []):
            network_issues.append({
                "file": report.get("archivo_analizado", "unknown"),
                "type": "error",
                "message": error
            })

        # Procesar las advertencias reportadas
        for warning in report.get("advertencias", []):
            network_issues.append({
                "file": report.get("archivo_analizado", "unknown"),
                "type": "warning",
                "message": warning
            })

    return network_issues

# Genera un informe de seguridad en formato Markdown.
def generate_security_report(
    bandit_issues, tflint_tag_issues, tflint_issues, checkov_missing_tags, network_json_issues, output_file
):
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Security Report\n\n")

        # Listar las vulnerabilidades Bandit
        f.write("### Bandit - Vulnerabilidades nivel HIGH\n\n")
        if not bandit_issues:
            f.write("No se encontraron vulnerabilidades de nivel high.\n")
        else:
            for issue in bandit_issues:
                f.write(
                    f"- **Archivo**: `{issue['file']}` - Línea: {issue['line']} - ID: `{issue['test_id']}`\n\n"
                )
                f.write(f"  - {issue['issue_text']}\n\n")
                recommendation = mitigation_manual_db.get(issue["test_id"])["recomendacion"]
                f.write(f"  - **Recomendación**: {recommendation}\n\n")
        
        # Listar las reglas violadas halladas con TFLint
        f.write("### TFLint - Reglas violadas\n\n")
        if not tflint_issues:
            f.write("No se encontraron reglas violadas en TFLint.\n\n")
        else:
            for rule in tflint_issues:
                f.write(
                    f"- **Archivo**: `{rule['file']}` - Línea: {rule['line']} - Severidad: `{rule['severity']}`\n"
                )
                f.write(f"  - **Regla**: `{rule['rule_name']}`\n")
                f.write(f"  - {rule['message']}\n")
                if rule["link"]:
                    f.write(f"  - [Más información]({rule['link']})\n")
                f.write("\n")
                recommendation = mitigation_manual_db.get(rule["rule_name"])["recomendacion"]
                f.write(f"  - **Recomendación**: {recommendation}\n\n")
        
        # Listar específicamente los errores de tags obligatorios
        f.write("#### Errores de tags obligatorios\n\n")
        if not tflint_tag_issues:
            f.write("No se encontraron errores relacionados con tags obligatorios.\n\n")
        else:
            for error in tflint_tag_issues:
                f.write(f"- **Archivo**: `{error['file']}` - Linea: {error['line']}\n")
                f.write(f"  - {error['message']}\n\n")
                recommendation = mitigation_manual_db.get(error["rule_name"])["recomendacion"]
                f.write(f"  - **Recomendación**: {recommendation}\n\n")

        # Listar lo hallado con checkov
        f.write("## Checkov - Recursos con errores de etiqueta\n\n")
        if not checkov_missing_tags:
            f.write(" No se encontraron recursos con errores de etiqueta.\n\n")
        else:
            for entry in checkov_missing_tags:
                f.write(
                    f"- **Archivo**: `{entry['file']}` ({entry['start_line']} - {entry['end_line']})\n"
                )
                f.write(f"  - Recurso: `{entry['resource']}`\n")
                f.write(f"  - Severidad: `{entry['severity']}`\n")
                f.write(
                    f"  - Mensaje: {entry['message']} (Check: `{entry['check_id']}`)\n"
                )
                if entry["guideline"]:
                    f.write(f"  - [Guía]({entry['guideline']})\n")
                f.write("\n")

                recommendation = mitigation_manual_db.get(entry["check_id"])["recomendacion"]
                f.write(f"  - **Recomendación**: {recommendation}\n\n")

        # Listar los errores y advertencias hallados en la configuración de red
        f.write("### Configuracion de red local\n\n")
        if not network_json_issues:
            f.write(" No se detectaron problemas de configuración de red en network_config.json.\n\n")
        else:
            for issue in network_json_issues:
                f.write(f"- **Archivo**: `{issue['file']}` - Tipo: `{issue['type']}`\n")
                f.write(f"  - {issue['message']}\n\n")

# Esta función genera un dashboard HTML usando un template.
def generate_security_dashboard(
    bandit_issues, tflint_tag_issues, tflint_issues, checkov_missing_tags, network_issues, graphic_file
):
    enviroment = Environment(
        loader=FileSystemLoader("templates"), autoescape=select_autoescape()
    )
    template = enviroment.get_template("security_report_template.html")

    html_file = template.render(
        bandit_issues=bandit_issues,
        tflint_issues=tflint_issues,
        checkov_issues=checkov_missing_tags,
        tflint_tag_issues=tflint_tag_issues,
        network_issues=network_issues,
        svg_file=graphic_file,
    )

    output_file = "reports/dashboard.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_file)
    pass

def generate_mitigation_manual(detected_ids, output_file="docs/manual_mitigacion.md"):
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Manual de mitigación de riesgos\n\n")
        f.write("Este documento proporciona sugerencias para mitigar vulnerabilidades detectadas en el análisis de")
        f.write("seguridad realizado con las herramientas Bandit, Checkov y TFLint.\n\n")
        for current_id in sorted(set(detected_ids)):
            entry = mitigation_manual_db.get(current_id)
            if not entry:
                continue
            f.write(f"## {entry['herramienta']} - {entry['titulo']}\n")
            f.write(f"- **Descripción**: {entry['descripcion']}\n")
            f.write(f"- **Impacto**: {entry['impacto']}\n")
            f.write(f"- **Recomendación**: {entry['recomendacion']}\n")
            if "ej_inseguro" in entry:
                f.write(f"- **Ejemplo inseguro**:\n```python\n{entry['ej_inseguro']}\n```\n")
            if "ej_seguro" in entry:
                f.write(f"- **Ejemplo seguro**:\n```python\n{entry['ej_seguro']}\n```\n")
            f.write("\n")

# Función auxiliar para obtener los identificadores de las vulnerabilidades detectadas
def get_ids(bandit_issues, tflint_issues, checkov_issues):
    ids = []
    for issue in bandit_issues:
        ids.append(issue.get("test_id"))
    
    for issue in tflint_issues:
        ids.append(issue.get("rule_name"))
    
    for issue in checkov_issues:
        ids.append(issue.get("check_id"))

    for issue in network_issues:
        msg = issue.get("message", "").lower()
        for key in mitigation_manual_db:
            if key in msg:
                ids.append(key)
                break  
    return ids

# Función main
if __name__ == "__main__":
    tflint_tag_issues = get_tflint_tag_errors("reports/tflint_iac.json")
    tflint_issues = get_tflint_issues(["reports/tflint_iac.json", "reports/tflint_network_dummy.json"])
    bandit_issues = get_bandit_issues("reports/bandit.json")
    checkov_missing_tags = get_checkov_issues("reports/checkov.json")
    network_issues = get_network_json_issues("reports/network_validation_report.json")

    generate_security_report(
        bandit_issues,
        tflint_tag_issues,
        tflint_issues,
        checkov_missing_tags,
        network_issues,
        "reports/security_report.md",
    )

    generate_security_dashboard(
        bandit_issues, tflint_tag_issues, tflint_issues, 
        checkov_missing_tags, network_issues, "summary_chart.svg"
    )

    ids = get_ids(bandit_issues, tflint_issues, checkov_missing_tags)
    generate_mitigation_manual(ids, "docs/manual_mitigacion.md")