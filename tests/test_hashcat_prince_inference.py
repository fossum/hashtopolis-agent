import unittest
from unittest import mock
from unittest.mock import MagicMock

from htpclient.hashcat_cracker import HashcatCracker
from htpclient.task import Task


class HashcatPrinceInference(unittest.TestCase):
    def test_uses_prince_detects_legacy_prince_arguments(self):
        task = Task.from_dict({
            'attackcmd': '"C:\\development\\hashtopolis\\agent-python\\files\\basic-english2.txt"',
            'cmdpars': '--hash-type=22000 --pw-min=8 --pw-max=14 --elem-cnt-min=1 --elem-cnt-max=4',
            'hashlistAlias': '#HL#',
        })

        assert task.uses_prince() is True

    def test_uses_prince_respects_preprocessor_tasks(self):
        task = Task.from_dict({
            'attackcmd': '"C:\\development\\hashtopolis\\agent-python\\files\\basic-english2.txt"',
            'cmdpars': '--hash-type=22000 --pw-min=8 --pw-max=14',
            'usePreprocessor': True,
        })

        assert task.uses_prince() is False

    def test_normalize_legacy_prince_task_converts_to_preprocessor(self):
        task = Task.from_dict({
            'taskId': 85,
            'attackcmd': '--pw-min=8 --pw-max=14 --elem-cnt-min=1 --elem-cnt-max=4 basic-english2.txt #HL# -r duplicate.rule',
            'cmdpars': '--hash-type=22000',
            'hashlistAlias': '#HL#',
            'usePreprocessor': False,
            'preprocessor': 0,
            'preprocessorCommand': '',
        })

        normalized = task.normalize_legacy_prince_task()

        assert normalized['usePreprocessor'] is True
        assert normalized['usePrince'] is False
        assert normalized['preprocessor'] == 1
        assert normalized['preprocessorCommand'] == '--pw-min=8 --pw-max=14 --elem-cnt-min=1 --elem-cnt-max=4 basic-english2.txt'
        assert normalized['attackcmd'] == '#HL# -r duplicate.rule'

    @mock.patch.object(HashcatCracker, 'preprocessor_keyspace', return_value=True)
    def test_measure_keyspace_routes_normalized_legacy_tasks(self, mock_preprocessor_keyspace):
        cracker = HashcatCracker.__new__(HashcatCracker)
        task_dict = Task.from_dict({
            'taskId': 85,
            'attackcmd': '--pw-min=8 --pw-max=14 --elem-cnt-min=1 --elem-cnt-max=4 basic-english2.txt #HL#',
            'cmdpars': '--hash-type=22000 --pw-min=8 --pw-max=14 --elem-cnt-min=1 --elem-cnt-max=4',
            'hashlistAlias': '#HL#',
            'usePreprocessor': False,
            'preprocessor': 0,
            'preprocessorCommand': '',
        })
        task_data = task_dict.normalize_legacy_prince_task()
        task_mock = MagicMock()
        task_mock.get_task.return_value = task_data
        chunk = MagicMock()

        assert cracker.measure_keyspace(task_mock, chunk) is True

        mock_preprocessor_keyspace.assert_called_once_with(task_mock, chunk)


if __name__ == '__main__':
    unittest.main()
