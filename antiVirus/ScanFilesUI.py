import os
import requests
from time import sleep
import tkinter as tk
from tkinter import filedialog, messagebox

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key

    def upload_file(self, file_path):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        with open(file_path, 'rb') as file:
            files = {'file': file}
            params = {'apikey': self.api_key}
            response = requests.post(url, data=params, files=files)
            response.raise_for_status()

            if response.headers['Content-Type'] == 'application/json':
                return response.json()['resource']
            else:
                raise Exception('Unable to locate result')

    def retrieve_report(self, resource_id):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': self.api_key, 'resource': resource_id}
        while True:
            response = requests.get(url, params=params)
            response.raise_for_status()

            if response.headers['Content-Type'] == 'application/json':
                result = response.json()
                if result['response_code'] == 1:
                    break
                else:
                    delay = 25
                    sleep(delay)
            else:
                raise Exception('Invalid content type')

        report = result
        positives = [engine for engine, result in report['scans'].items() if result['detected']]
        return positives

class VirusTotalApp:
    def __init__(self, root):
        self.api_key = '7ca5a5e66b464c669f68a8a795a83d1bc59ff75d2d4eb6c1add7418dcbfa1fd3'
        self.api = VirusTotalAPI(self.api_key)

        self.root = root
        self.root.title('VirusTotal Scanner')
        self.root.geometry('400x200')

        self.file_path_var = tk.StringVar()

        tk.Label(root, text='Select a file to scan:').pack(pady=10)
        tk.Entry(root, textvariable=self.file_path_var, width=50).pack(pady=5)
        tk.Button(root, text='Browse', command=self.browse_file).pack(pady=5)
        tk.Button(root, text='Scan File', command=self.scan_file).pack(pady=20)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)

    def scan_file(self):
        file_path = self.file_path_var.get()
        if not os.path.exists(file_path):
            messagebox.showerror('Error', 'The specified file does NOT exist')
            return
        
        try:
            resource_id = self.api.upload_file(file_path)
            positives = self.api.retrieve_report(resource_id)
            result_text = f'Scanned file: {file_path}\nPositives: {len(positives)}\n'

            if positives:
                result_text += f'WARNING: Found {len(positives)} alerts. Please see the full report above.'
            else:
                result_text += 'No positives found. The file appears to be safe.'

            messagebox.showinfo('Scan Result', result_text)
        except Exception as e:
            messagebox.showerror('Error', str(e))

if __name__ == '__main__':
    root = tk.Tk()
    app = VirusTotalApp(root)
    root.mainloop()
