#!/usr/bin/env python3
import json
import sys
import re
from datetime import datetime
from pathlib import Path

def load_template(template_path):
    """Carga la plantilla HTML"""
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()

def load_zap_json(json_path):
    """Carga el JSON generado por ZAP"""
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_risk_string(risk_level):
    """Convierte el nivel de riesgo a string"""
    risk_map = {
        3: "High",
        2: "Medium",
        1: "Low",
        0: "Informational"
    }
    return risk_map.get(risk_level, "Unknown")

def count_alerts_by_risk(alerts):
    """Cuenta las alertas por nivel de riesgo"""
    counts = {3: 0, 2: 0, 1: 0, 0: 0}
    for alert in alerts:
        risk = int(alert.get('risk', 0))
        counts[risk] = counts.get(risk, 0) + 1
    return counts

def generate_html(template, zap_data):
    """Genera el HTML final reemplazando los placeholders de Thymeleaf"""
    
    # Extraer datos del JSON
    site = zap_data.get('site', [''])[0] if zap_data.get('site') else ''
    all_alerts = zap_data.get('site', [{}])[0].get('alerts', []) if zap_data.get('site') else []
    
    # Filtrar alertas para omitir las de nivel Informational (0)
    alerts = [alert for alert in all_alerts if int(alert.get('risk', 0)) > 0]
    
    # Contar alertas por riesgo (solo las filtradas)
    alert_counts = count_alerts_by_risk(alerts)
    
    # Generar fecha actual
    current_date = datetime.now().strftime('%a, %d %b %Y %H:%M:%S')
    
    html = template
    
    # Reemplazar título
    html = re.sub(r'<th:block th:text="\$\{reportTitle\}">.*?</th:block>', 'ZAP Scanning Report', html)
    
    # Reemplazar fecha
    html = re.sub(
        r'<th:block\s+th:text="#\{report\.generated\([^)]+\)\}">.*?</th:block>',
        f'Report generated at: {current_date}',
        html
    )
    
    # Reemplazar versión de ZAP
    html = re.sub(
        r'<th:block th:text="#\{report\.zapVersion\([^)]+\)\}">.*?</th:block>',
        f'ZAP Version: {zap_data.get("@version", "Unknown")}',
        html
    )
    
    # Generar tabla de resumen de alertas
    summary_section = '''
	<h3 class="left-header">Summary of Alerts</h3>
	<table class="summary">
		<tr>
			<th width="45%" height="24">Risk Level</th>
			<th width="55%" align="center">Number of Alerts</th>
		</tr>'''
    
    # Solo mostrar High, Medium y Low (omitir Informational)
    for risk_level in [3, 2, 1]:
        risk_name = get_risk_string(risk_level)
        count = alert_counts.get(risk_level, 0)
        summary_section += f'''
		<tr>
			<td class="risk-{risk_level}">
				<div>{risk_name}</div>
			</td>
			<td align="center">
				<div>{count}</div>
			</td>
		</tr>'''
    
    summary_section += '''
	</table>
	<div class="spacer-lg"></div>'''
    
    # Reemplazar sección de resumen
    html = re.sub(
        r'<th:block th:if="\$\{reportData\.isIncludeSection\(\'alertcount\'\)\}">.*?</th:block>',
        summary_section,
        html,
        flags=re.DOTALL
    )
    
    # Generar lista de alertas
    alert_list_section = '''
	<h3>Alerts</h3>
	<table class="alerts">
		<tr>
			<th width="60%" height="24">Name</th>
			<th width="20%" align="center">Risk Level</th>
			<th width="20%" align="center">Number of Instances</th>
		</tr>'''
    
    for alert in alerts:
        plugin_id = alert.get('pluginid', '')
        name = alert.get('name', 'Unknown Alert')
        risk = int(alert.get('risk', 0))
        risk_name = get_risk_string(risk)
        instances = alert.get('instances', [])
        instance_count = len(instances)
        
        alert_list_section += f'''
		<tr>
			<td><a href="#{plugin_id}">{name}</a></td>
			<td align="center" class="risk-{risk}">{risk_name}</td>
			<td align="center">{instance_count}</td>
		</tr>'''
    
    alert_list_section += '''
	</table>
	<div class="spacer-lg"></div>'''
    
    # Reemplazar sección de lista de alertas
    html = re.sub(
        r'<th:block th:if="\$\{reportData\.isIncludeSection\(\'instancecount\'\)\}">.*?</th:block>',
        alert_list_section,
        html,
        flags=re.DOTALL
    )
    
    # Generar detalles de alertas
    alert_details_section = '''
	<h3>Alert Detail</h3>'''
    
    for alert in alerts:
        plugin_id = alert.get('pluginid', '')
        name = alert.get('name', 'Unknown Alert')
        risk = int(alert.get('risk', 0))
        risk_name = get_risk_string(risk)
        instances = alert.get('instances', [])
        instance_count = len(instances)
        
        description = alert.get('desc', '').replace('\n', '<br>')
        solution = alert.get('solution', '').replace('\n', '<br>')
        reference = alert.get('reference', '')
        references_html = '<br>'.join([f'<a href="{ref}">{ref}</a>' for ref in reference.split('\n') if ref.strip()])
        
        cweid = int(alert.get('cweid', 0)) if alert.get('cweid') else 0
        wascid = int(alert.get('wascid', 0)) if alert.get('wascid') else 0
        
        # Instancias
        instances_html = ""
        for instance in instances:
            uri = instance.get('uri', '')
            method = instance.get('method', '')
            param = instance.get('param', '')
            attack = instance.get('attack', '')
            evidence = instance.get('evidence', '')
            
            instances_html += f'''
			<tr>
				<td width="20%" class="indent1">URL</td>
				<td width="80%"><a href="{uri}">{uri}</a></td>
			</tr>
			<tr>
				<td width="20%" class="indent2">Method</td>
				<td width="80%">{method}</td>
			</tr>
			<tr>
				<td width="20%" class="indent2">Param</td>
				<td width="80%">{param}</td>
			</tr>
			<tr>
				<td width="20%" class="indent2">Attack</td>
				<td width="80%">{attack}</td>
			</tr>
			<tr>
				<td width="20%" class="indent2">Evidence</td>
				<td width="80%">{evidence}</td>
			</tr>'''
        
        cwe_html = f'<a href="https://cwe.mitre.org/data/definitions/{cweid}.html">{cweid}</a>' if cweid > 0 else ''
        wasc_html = str(wascid) if wascid > 0 else ''
        
        alert_details_section += f'''
	<table class="results">
		<tr height="24">
			<th width="20%" class="risk-{risk}"><a id="{plugin_id}"></a>
				<div>{risk_name}</div></th>
			<th class="risk-{risk}">{name}</th>
		</tr>
		<tr>
			<td width="20%">Description</td>
			<td width="80%">{description}</td>
		</tr>
		<tr vAlign="top">
			<td colspan="2"></td>
		</tr>
		{instances_html}
		<tr>
			<td width="20%">Instances</td>
			<td width="80%">{instance_count}</td>
		</tr>
		<tr>
			<td width="20%">Solution</td>
			<td width="80%">{solution}</td>
		</tr>
		<tr>
			<td width="20%">Reference</td>
			<td width="80%">{references_html}</td>
		</tr>
		<tr>
			<td width="20%">CWE Id</td>
			<td width="80%">{cwe_html}</td>
		</tr>
		<tr>
			<td width="20%">WASC Id</td>
			<td width="80%">{wasc_html}</td>
		</tr>
		<tr>
			<td width="20%">Plugin Id</td>
			<td width="80%"><a href="https://www.zaproxy.org/docs/alerts/{plugin_id}/">{plugin_id}</a></td>
		</tr>
	</table>
	<div class="spacer"></div>'''
    
    # Reemplazar sección de detalles de alertas
    html = re.sub(
        r'<th:block th:if="\$\{reportData\.isIncludeSection\(\'alertdetails\'\)\}">.*?</th:block>',
        alert_details_section,
        html,
        flags=re.DOTALL
    )
    
    return html

def main():
    if len(sys.argv) != 4:
        print("Usage: generate_report.py <template.html> <zap-report.json> <output.html>")
        sys.exit(1)
    
    template_path = sys.argv[1]
    json_path = sys.argv[2]
    output_path = sys.argv[3]
    
    # Cargar datos
    template = load_template(template_path)
    zap_data = load_zap_json(json_path)
    
    # Generar HTML
    html = generate_html(template, zap_data)
    
    # Guardar resultado
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"Report generated successfully: {output_path}")

if __name__ == "__main__":
    main()
