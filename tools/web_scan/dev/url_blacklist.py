import pandas as pd
from datetime import datetime
import os

class URLBlacklist:
    def __init__(self, file_name='url_blacklist.csv'):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.file_path = os.path.join(current_dir, file_name)
        self.last_modified = None
        self.reload()
    
    def check_file_modified(self):
        try:
            current_mtime = os.path.getmtime(self.file_path)
            if self.last_modified is None or current_mtime > self.last_modified:
                self.last_modified = current_mtime
                return True
        except OSError:
            # ถ้าไฟล์ไม่มีอยู่ ถือว่ามีการเปลี่ยนแปลง
            return True
        return False

    def reload_if_modified(self):
        if self.check_file_modified():
            self.reload()
            return True
        return False

    def reload(self):
        try:
            self.df = pd.read_csv(self.file_path)
            self.last_modified = os.path.getmtime(self.file_path)
        except FileNotFoundError:
            self.df = pd.DataFrame(columns=['URL', 'CATEGORY', 'DATE_ADDED', 'REASON', 'STATUS'])
            self.last_modified = None
        return self.df
    
    def save(self):
        self.df.to_csv(self.file_path, index=False)
        self.last_modified = os.path.getmtime(self.file_path)
    
    def check_url(self, url):
        self.reload_if_modified()
        return url in self.df['URL'].values
    
    def add_url(self, url, category, reason):
        self.reload_if_modified()
        if not self.check_url(url):
            new_row = pd.DataFrame({
                'URL': [url],
                'CATEGORY': [category],
                'DATE_ADDED': [datetime.now().strftime('%Y-%m-%d')],
                'REASON': [reason],
                'STATUS': [1]
            })
            self.df = pd.concat([self.df, new_row], ignore_index=True)
            self.save()
            return True
        return False
    
    def set_status(self, url, active=True):
        self.reload_if_modified()
        if self.check_url(url):
            self.df.loc[self.df['URL'] == url, 'STATUS'] = 1 if active else 0
            self.save()
            return True
        return False
    
    def remove_url(self, url):
        self.reload_if_modified()
        if self.check_url(url):
            self.df = self.df[self.df['URL'] != url]
            self.save()
            return True
        return False

