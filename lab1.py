import re
import json
import csv
from pathlib import Path

# Fayl yollarını təyin edirik
log_file_path = Path('server_logs.txt')  # Server loglarının yerləşdiyi faylın yolu
threat_file_path = Path('index.html')   # Təhdid IP-lərinin olduğu HTML faylının yolu

# Log faylını oxuyuruq
if log_file_path.exists():  # Əgər log faylı mövcuddursa
    with log_file_path.open('r') as log_file:
        logs = log_file.readlines()  # Log faylındakı bütün sətirləri oxuyuruq
else:
    raise FileNotFoundError(f"Log faylı tapılmadı: {log_file_path}")  # Əgər fayl tapılmasa, səhv mesajı

# Təhdid IP-lərini oxuyuruq
threat_ips = []  # Təhdid IP-lərini saxlayacaq siyahı
if threat_file_path.exists():  # Əgər HTML faylı mövcuddursa
    with threat_file_path.open('r') as html_file:
        for line in html_file:  # Faylın hər bir sətirini yoxlayırıq
            match = re.search(r'<td>(\d+\.\d+\.\d+\.\d+)</td>', line)  # IP ünvanlarını tapmaq üçün regex istifadə edirik
            if match:
                threat_ips.append(match.group(1))  # Tapılan IP-ni siyahıya əlavə edirik
else:
    raise FileNotFoundError(f"HTML faylı tapılmadı: {threat_file_path}")  # Əgər fayl tapılmasa, səhv mesajı

# Loglardan məlumat çıxarmaq üçün regex
log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"(\w+) .+\" (\d+) .+'  # Log formatını uyğunlaşdıran regex
log_data = []  # Log məlumatlarını saxlayacaq siyahı
failed_attempts = {}  # Uğursuz girişləri sayacaq lüğət

# Hər bir log üçün məlumatları çıxarırıq
for log in logs:
    match = re.match(log_pattern, log)  # Regex ilə logu yoxlayırıq
    if match:
        ip, date, method, status = match.groups()  # IP, tarix, metod və statusu əldə edirik
        log_data.append({"ip": ip, "date": date, "method": method, "status": status})  # Log məlumatını siyahıya əlavə edirik
        if status == '401':  # Əgər status 401-dirsə (uğursuz giriş)
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1  # Uğursuz girişləri sayırıq

# 5-dən çox uğursuz giriş olan IP-lər
failed_logins = {ip: count for ip, count in failed_attempts.items() if count > 5}  # 5 və ya daha çox uğursuz giriş edən IP-ləri tapırıq
with open('failed_logins.json', 'w') as json_file:
    json.dump(failed_logins, json_file, indent=4)  # Uğursuz girişləri JSON formatında fayla yazırıq

# Təhdid IP-lərini JSON faylına yazmaq
matching_threats = [ip for ip in log_data if ip['ip'] in threat_ips]  # Təhdid IP-ləri ilə uyğun gələnləri tapırıq
with open('threat_ips.json', 'w') as json_file:
    json.dump(matching_threats, json_file, indent=4)  # Təhdid IP-lərini JSON formatında fayla yazırıq

# Uğursuz girişləri və təhdid IP-lərini birləşdiririk
combined_data = {"failed_logins": failed_logins, "threat_ips": matching_threats}  # Həm uğursuz girişləri, həm də təhdid IP-lərini birləşdiririk
with open('combined_security_data.json', 'w') as json_file:
    json.dump(combined_data, json_file, indent=4)  # Birlikdə olan məlumatları JSON faylına yazırıq

# Mətn faylı yaratmaq
with open('log_analysis.txt', 'w') as txt_file:
    for ip, count in failed_attempts.items():  # Hər bir uğursuz giriş üçün IP və sayı yazırıq
        txt_file.write(f"IP: {ip}, Failed Attempts: {count}\n")  # Mətn faylında qeyd edirik

# CSV faylı yaratmaq
with open('log_analysis.csv', 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)  # CSV faylı üçün yazıcı yaradılır
    csv_writer.writerow(["IP", "Date", "Method", "Status", "Failed Attempts"])  # Başlıqları yazırıq
    for log in log_data:  # Hər bir log üçün məlumatları yazırıq
        failed_count = failed_attempts.get(log['ip'], 0)  # Hər bir IP üçün uğursuz giriş sayını əldə edirik
        csv_writer.writerow([log['ip'], log['date'], log['method'], log['status'], failed_count])  # CSV faylına məlumat yazırıq

print('process finished')  # Prosesin bitdiyini bildiririk
