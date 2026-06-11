
import logging
import re
from time import sleep

from htpclient.config import Config
from htpclient.jsonRequest import JsonRequest
from htpclient.dicts import copy_and_set_token, dict_getTask
from htpclient.helpers import clean_list


from typing import Any, Dict, List, Optional

class Task:
    """
    Represents a task configuration and handles loading task metadata from the Hashtopolis server.
    Implements a backward-compatibility mapping protocol for dictionary-style access.
    """

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        """
        Initializes a new Task instance.

        Args:
            data: Optional dictionary containing raw task configurations from the server.
        """
        self._data: Dict[str, Any] = data if data is not None else {}
        self.taskId: int = 0
        self.task: Optional['Task'] = None
        self.config: Config = Config()
        self.preprocessor: Optional[Any] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """
        Creates a Task instance populated with the provided dictionary data.

        Args:
            data: Raw task configurations from the server.

        Returns:
            A Task instance.
        """
        return cls(data)

    def reset_task(self) -> None:
        """
        Resets the current task manager state and the loaded task data.
        """
        self.task = None
        self.taskId = 0

    def load_task(self) -> None:
        """
        Queries the Hashtopolis server to fetch and load the active task.
        """
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
                return
            task_instance = Task.from_dict(ans)
            self.task = task_instance.normalize_legacy_prince_task()
            self.taskId = ans['taskId']
            logging.info("Got task with id: " + str(ans['taskId']))

    def get_task(self) -> Optional['Task']:
        """
        Retrieves the currently loaded task instance.

        Returns:
            The loaded Task instance or None if no task is loaded.
        """
        return self.task

    def get_task_id(self) -> int:
        """
        Retrieves the ID of the current task.

        Returns:
            The task ID.
        """
        return self.taskId

    def set_preprocessor(self, settings: Any) -> None:
        """
        Sets the preprocessor settings for this task.

        Args:
            settings: Preprocessor configuration/settings to apply.
        """
        self.preprocessor = settings
        
    def get_preprocessor(self) -> Optional[Any]:
        """
        Retrieves the preprocessor settings for this task.

        Returns:
            The preprocessor settings, or None if not set.
        """
        return self.preprocessor

    # --- Properties representing task data fields ---

    @property
    def task_id(self) -> int:
        """
        The ID of the task.
        """
        return int(self._data.get('taskId', 0))

    @property
    def use_preprocessor(self) -> bool:
        """
        Whether the task is configured to use a preprocessor.
        """
        return bool(self._data.get('usePreprocessor', False))

    @property
    def use_prince(self) -> bool:
        """
        Whether the task is configured to use Prince (deprecated).
        """
        return bool(self._data.get('usePrince', False))

    @property
    def preprocessor_id(self) -> Optional[int]:
        """
        The ID of the preprocessor, if any.
        """
        val = self._data.get('preprocessor')
        return int(val) if val is not None else None

    @property
    def preprocessor_command(self) -> Optional[str]:
        """
        The preprocessor command template.
        """
        return self._data.get('preprocessorCommand')

    @property
    def attack_cmd(self) -> Optional[str]:
        """
        The raw attack command.
        """
        return self._data.get('attackcmd')

    @property
    def cmd_pars(self) -> Optional[str]:
        """
        The command parameters.
        """
        return self._data.get('cmdpars')

    @property
    def hashlist_alias(self) -> Optional[str]:
        """
        The placeholder or alias name of the hashlist file in command strings.
        """
        return self._data.get('hashlistAlias')

    @property
    def files(self) -> List[Any]:
        """
        List of file requirements for this task.
        """
        val = self._data.get('files')
        return val if isinstance(val, list) else []

    @property
    def hashlist_id(self) -> int:
        """
        The ID of the hashlist associated with the task.
        """
        return int(self._data.get('hashlistId', 0))

    @property
    def use_brain(self) -> bool:
        """
        Whether the task uses a hashcat brain server.
        """
        return bool(self._data.get('useBrain', False))

    @property
    def bench_type(self) -> int:
        """
        The benchmark type configuration code.
        """
        return int(self._data.get('benchType', 0))

    @property
    def enforce_pipe(self) -> bool:
        """
        Whether to enforce piping cracker commands.
        """
        return bool(self._data.get('enforcePipe', False))

    @property
    def slow_hash(self) -> bool:
        """
        Whether the task targets a slow hash algorithm.
        """
        return bool(self._data.get('slowHash', False))

    # --- Dictionary Mapping Protocol Methods ---

    def __getitem__(self, key: str) -> Any:
        """
        Implements key lookup for backward compatibility with dictionary access.

        Args:
            key: Dictionary key name to access.

        Returns:
            The associated value from the internal task dictionary.

        Raises:
            KeyError: If the key is not present in the internal dictionary.
        """
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieves a key value or default if the key does not exist.

        Args:
            key: Key name to fetch.
            default: Default value if key is missing.

        Returns:
            The value or default.
        """
        return self._data.get(key, default)

    def __contains__(self, key: str) -> bool:
        """
        Checks if a key exists in the internal dictionary.

        Args:
            key: Key name to verify.

        Returns:
            True if the key exists, False otherwise.
        """
        return key in self._data

    # --- Domain Methods ---

    def uses_prince(self) -> bool:
        """
        Detects if this task command or parameters represent a Prince attack pattern.

        Returns:
            True if Prince rules/arguments are present, False otherwise.
        """
        if self.use_preprocessor:
            return False
        if self.use_prince:
            return True

        prince_args = " ".join([
            str(self.get('attackcmd', '')),
            str(self.get('cmdpars', '')),
        ])
        prince_pattern = re.compile(
            r'(^|\s)--(?:'
            r'pw-(?:min|max)|'
            r'elem-cnt-(?:min|max)|'
            r'case-permute|'
            r'dupe-check-disable|'
            r'save-pos-disable|'
            r'wl-(?:dist-len|max)'
            r')(?:[=\s]|$)'
        )
        return prince_pattern.search(prince_args) is not None

    def normalize_legacy_prince_task(self) -> 'Task':
        """
        Converts legacy Prince task fields to use the generalized preprocessor task structure.

        Returns:
            A new Task instance containing the normalized settings, or self if no conversion is needed.
        """
        if not self.uses_prince():
            return self

        normalized_data = dict(self._data)
        alias = normalized_data['hashlistAlias']
        split = clean_list(str(normalized_data.get('attackcmd', '')).split(" "))

        preprocessor_parts = []
        hashcat_parts = [alias]

        index = 0
        while index < len(split):
            part = split[index]
            if part == alias:
                index += 1
                continue
            if part in ('-r', '--rules-file') and index + 1 < len(split):
                hashcat_parts.extend([part, split[index + 1]])
                index += 2
                continue

            preprocessor_parts.append(part)
            index += 1

        normalized_data['usePrince'] = False
        normalized_data['usePreprocessor'] = True
        normalized_data['preprocessor'] = normalized_data.get('preprocessor') or 1
        normalized_data['preprocessorCommand'] = normalized_data.get('preprocessorCommand') or " ".join(preprocessor_parts)
        normalized_data['attackcmd'] = " ".join(hashcat_parts)

        return Task.from_dict(normalized_data)
