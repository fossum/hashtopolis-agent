import logging
from time import sleep

from htpclient.config import Config
from htpclient.jsonRequest import JsonRequest
from htpclient.dicts import *


class Task:
    def __init__(self):
        self.taskId = 0
        self.task = None
        self.config = Config()
        self.preprocessor = None
        self.sleep_inhibitor = None

    def _update_inhibit(self):
        if self.sleep_inhibitor:
            if self.taskId != 0:
                self.sleep_inhibitor.inhibit()
            else:
                self.sleep_inhibitor.release()

    def reset_task(self):
        self.task = None
        self.taskId = 0
        self._update_inhibit()

    def load_task(self):
        if self.taskId != 0:
            return
        self.task = None
        query = copy_and_set_token(dict_getTask, self.config.get_value('token'))
        req = JsonRequest(query)
        ans = req.execute()
        if ans is None:
            logging.error("Failed to get task!")
            sleep(5)
        elif ans['response'] != 'SUCCESS':
            logging.error("Error from server: " + str(ans))
            sleep(5)
        else:
            if ans['taskId'] is None:
                logging.info("No task available!")
                sleep(5)
                return
            elif ans['taskId'] == -1:
                self.taskId = -1
                self._update_inhibit()
                return
            # Automatically detect if PRINCE options are in attackcmd and force usePrince
            if 'attackcmd' in ans and any(opt in ans['attackcmd'] for opt in ['--pw-min', '--pw-max', '--elem-cnt-min', '--elem-cnt-max']):
                ans['usePrince'] = True
                logging.info("Detected PRINCE options in attackcmd, forcing usePrince = True")
            self.task = ans
            self.taskId = ans['taskId']
            self._update_inhibit()
            logging.info("Got task with id: " + str(ans['taskId']))

    def get_task(self):
        return self.task

    def get_task_id(self):
        return self.taskId

    def set_preprocessor(self, settings):
        self.preprocessor = settings
        
    def get_preprocessor(self):
        return self.preprocessor
