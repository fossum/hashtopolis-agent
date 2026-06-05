import hashlib
import logging
import time
from time import sleep
from pathlib import Path

import os

from htpclient.config import Config
from htpclient.download import Download
from htpclient.initialize import Initialize
from htpclient.jsonRequest import JsonRequest
from htpclient.dicts import *


class Files:
    def __init__(self):
        self.config = Config()
        self.chunk = None
        self.last_check = None
        self.check_interval = 600
        if self.config.get_value('file-deletion-interval'):
            self.check_interval = int(self.config.get_value('file-deletion-interval'))

    def deletion_check(self):
        if self.config.get_value('file-deletion-disable'):
            return
        elif self.last_check is not None and time.time() - self.last_check < self.check_interval:
            return
        query = copy_and_set_token(dict_getFileStatus, self.config.get_value('token'))
        req = JsonRequest(query)
        ans = req.execute()
        self.last_check = time.time()
        if ans is None:
            logging.error("Failed to get file status!")
        elif ans['response'] != 'SUCCESS':
            logging.error("Getting of file status failed: " + str(ans))
        else:
            files = ans['filenames']
            for filename in files:
                file_path = Path(self.config.get_value('files-path'), filename)
                if filename.find("/") != -1 or filename.find("\\") != -1:
                    continue  # ignore invalid file names
                elif os.path.dirname(file_path) != "files":
                    continue  # ignore any case in which we would leave the files folder
                elif os.path.exists(file_path):
                    logging.info("Delete file '" + filename + "' as requested by server...")
                    # When we get the delete requests, this function will check if the <filename>.7z maybe as
                    # an extracted text file. That file will also be deleted.
                    if os.path.splitext(file_path)[1] == '.7z':
                        txt_file = Path(f"{os.path.splitext(file_path)[0]}.txt")
                        if os.path.exists(txt_file):
                            logging.info("Also delete assumed wordlist from archive of same file...")
                            os.unlink(txt_file)
                    os.unlink(file_path)

    def check_files(self, files, task_id):
        for file in files:
            file_localpath = Path(self.config.get_value('files-path'), file)
            txt_file = Path(f"{os.path.splitext(file_localpath)[0]}.txt")
            query = copy_and_set_token(dict_getFile, self.config.get_value('token'))
            query['taskId'] = task_id
            query['file'] = file
            req = JsonRequest(query)
            ans = req.execute()

            # Process request
            if ans is None:
                logging.error("Failed to get file!")
                sleep(5)
                return False
            elif ans['response'] != 'SUCCESS':
                logging.error("Getting of file failed: " + str(ans))
                sleep(5)
                return False
            else:
                # Filesize is OK
                file_size = int(ans['filesize'])
                if os.path.isfile(file_localpath) and os.stat(file_localpath).st_size == file_size:
                    logging.debug("File is present on agent and has matching file size.")
                    continue

                # Multicasting configured
                elif self.config.get_value('multicast'):
                    logging.debug("Multicast is enabled, need to wait until it was delivered!")
                    sleep(5)  # in case the file is not there yet (or not completely), we just wait some time and then try again
                    return False

                # TODO: we might need a better check for this
                if os.path.isfile(txt_file):
                    continue

                # Rsync
                if self.config.get_value('rsync') and Initialize.get_os() != 1:
                    Download.rsync(Path(self.config.get_value('rsync-path'), file), file_localpath)
                else:
                    logging.debug("Starting download of file from server...")
                    Download.download(self.config.get_value('url').replace("api/server.php", "") + ans['url'], file_localpath)

                # Mismatch filesize
                if os.path.isfile(file_localpath) and not Files.is_same_size(file_localpath, file_size):
                    logging.error("file size mismatch on file: %s" % file)
                    sleep(5)
                    return False

                # 7z extraction, check if the <filename>.txt does exist.
                if os.path.splitext(file_localpath)[1] == '.7z' and not os.path.isfile(txt_file):
                    # extract if needed
                    files_path = Path(self.config.get_value('files-path'))
                    if Initialize.get_os() == 1:
                        # Windows
                        cmd = f'7zr{Initialize.get_os_extension()} x -aoa -o"{files_path}" -y "{file_localpath}"'
                    else:
                        # Linux
                        cmd = f"./7zr{Initialize.get_os_extension()} x -aoa -o'{files_path}' -y '{file_localpath}'"
                    os.system(cmd)
        return True

    @staticmethod
    def is_same_size(filepath: Path, expected_size: int) -> bool:
        """Check if file size matches expected size.

        Normalizes line endings to each platform before calculating size.
        """
        if not os.path.isfile(filepath):
            return False
        
        # Try current size first.
        try:
            actual_size = os.stat(filepath).st_size
        except OSError:
            return False
            
        if actual_size == expected_size:
            return True
            
        # Read file memory-efficiently in binary mode to avoid encoding errors and OOMs.
        try:
            crlf_count = 0
            lf_count_no_cr = 0
            last_char = b''
            
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(1024 * 1024)  # 1MB chunk
                    if not chunk:
                        break
                    
                    crlf_count += chunk.count(b'\r\n')
                    if last_char == b'\r' and chunk.startswith(b'\n'):
                        crlf_count += 1
                        
                    lf_chunk = chunk.count(b'\n')
                    lf_no_cr = lf_chunk - chunk.count(b'\r\n')
                    if last_char == b'\r' and chunk.startswith(b'\n'):
                        lf_no_cr -= 1
                    
                    lf_count_no_cr += lf_no_cr
                    last_char = chunk[-1:]
            
            # Case 1: Convert CRLF to LF
            if actual_size - crlf_count == expected_size:
                return True
                
            # Case 2: Convert LF to CRLF
            if actual_size + lf_count_no_cr == expected_size:
                return True
                
        except Exception:
            pass
            
        return False
