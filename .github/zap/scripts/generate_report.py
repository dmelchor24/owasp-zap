#!/usr/bin/env python3
import json
import sys
import re
import html
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

def generate_html(template, zap_data):
    """Genera el HTML final reemplazando los placeholders de Thymeleaf"""
    
    # Extraer datos del JSON
    site_list = zap_data.get('site', [])
    if isinstance(site_list, list) and len(site_list) > 0:
        site_data = site_list[0]
        site = site_data.get('@name', '') if isinstance(site_data, dict) else ''
        all_alerts = site_data.get('alerts', []) if isinstance(site_data, dict) else []
    else:
        site = ''
        all_alerts = []
    
    # Filtrar alertas para omitir las de nivel Informational (0)
    # El campo 'riskcode' contiene el nivel de riesgo como string
    alerts = [alert for alert in all_alerts if int(alert.get('riskcode', '0')) > 0]
    
    # Contar alertas por riesgo (solo las filtradas)
    alert_counts = {3: 0, 2: 0, 1: 0}
    for alert in alerts:
        risk = int(alert.get('riskcode', '0'))
        if risk in alert_counts:
            alert_counts[risk] += 1
    
    # Generar fecha actual
    current_date = datetime.now().strftime('%a, %d %b %Y %H:%M:%S')
    
    result_html = template
    
    # Reemplazar título
    result_html = re.sub(r'<th:block th:text="\$\{reportTitle\}">.*?</th:block>', 'ZAP Scanning Report', result_html)
    
    # Reemplazar sitio
    site_text = f'Site: {site}' if site else ''
    result_html = re.sub(
        r'<h2 th:switch="\$\{reportData\.sites == null \? 0 : reportData\.sites\.size\}">.*?</h2>',
        f'<h2>{site_text}</h2>' if site else '<h2></h2>',
        result_html,
        flags=re.DOTALL
    )
    
    # Reemplazar fecha - buscar el patrón completo incluyendo el texto por defecto
    result_html = re.sub(
        r'<h3>\s*<th:block\s+th:text="#\{report\.generated\([^)]+\)\}">Date, time</th:block>\s*</h3>',
        f'<h3>Generated on {current_date}</h3>',
        result_html,
        flags=re.DOTALL
    )
    
    # Reemplazar versión de ZAP - buscar el patrón completo incluyendo el texto por defecto
    result_html = re.sub(
        r'<h3>\s*<th:block th:text="#\{report\.zapVersion\([^)]+\)\}">ZAP Version</th:block>\s*</h3>',
        f'<h3>ZAP Version: {zap_data.get("@version", "Unknown")}</h3>',
        result_html,
        flags=re.DOTALL
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
    result_html = re.sub(
        r'<th:block th:if="\$\{reportData\.isIncludeSection\(\'alertcount\'\)\}">.*?</th:block>',
        summary_section,
        result_html,
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
        name = html.escape(alert.get('alert', alert.get('name', 'Unknown Alert')))
        risk = int(alert.get('riskcode', '0'))
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
    result_html = re.sub(
        r'<th:block th:if="\$\{reportData\.isIncludeSection\(\'instancecount\'\)\}">.*?</th:block>',
        alert_list_section,
        result_html,
        flags=re.DOTALL
    )
    
    # Generar detalles de alertas
    alert_details_section = '''
	<h3>Alert Detail</h3>'''
    
    for alert in alerts:
        plugin_id = alert.get('pluginid', '')
        name = html.escape(alert.get('alert', alert.get('name', 'Unknown Alert')))
        risk = int(alert.get('riskcode', '0'))
        risk_name = get_risk_string(risk)
        instances = alert.get('instances', [])
        instance_count = len(instances)
        
        # NO escapar description, solution y reference porque ya contienen HTML válido
        description = alert.get('desc', '').replace('\n', '<br>')
        solution = alert.get('solution', '').replace('\n', '<br>')
        reference = alert.get('reference', '')
        references_html = '<br>'.join([f'<a href="{ref}">{ref}</a>' for ref in reference.split('\n') if ref.strip()])
        
        cweid = alert.get('cweid', '')
        cweid_int = int(cweid) if cweid and str(cweid).isdigit() else 0
        wascid = alert.get('wascid', '')
        wascid_int = int(wascid) if wascid and str(wascid).isdigit() else 0
        
        # Instancias
        instances_html = ""
        for instance in instances:
            uri = html.escape(instance.get('uri', ''))
            method = html.escape(instance.get('method', ''))
            param = html.escape(instance.get('param', ''))
            attack = html.escape(instance.get('attack', ''))
            evidence = html.escape(instance.get('evidence', ''))
            other_info = html.escape(instance.get('otherinfo', ''))
            
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
				<td width="20%" class="indent2">Parameter</td>
				<td width="80%">{param}</td>
			</tr>
			<tr>
				<td width="20%" class="indent2">Attack</td>
				<td width="80%">{attack}</td>
			</tr>
			<tr>
				<td width="20%" class="indent2">Evidence</td>
				<td width="80%">{evidence}</td>
			</tr>
			<tr>
				<td width="20%" class="indent2">Other Info</td>
				<td width="80%">{other_info}</td>
			</tr>'''
        
        cwe_html = f'<a href="https://cwe.mitre.org/data/definitions/{cweid_int}.html">{cweid_int}</a>' if cweid_int > 0 else ''
        wasc_html = str(wascid_int) if wascid_int > 0 else ''
        
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
    result_html = re.sub(
        r'<th:block th:if="\$\{reportData\.isIncludeSection\(\'alertdetails\'\)\}">.*?</th:block>',
        alert_details_section,
        result_html,
        flags=re.DOTALL
    )
    
    return result_html

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
    html_output = generate_html(template, zap_data)
    
    # Guardar resultado
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)
    
    print(f"Report generated successfully: {output_path}")

if __name__ == "__main__":
    main()
