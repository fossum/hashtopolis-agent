import unittest
from pathlib import Path
from unittest import mock

from htpclient.hashcat_cracker import HashcatCracker


class DummyBinaryDownload:
    @staticmethod
    def get_version():
        return {'executable': 'hashcat.bin'}


class SpeedBenchmarkCommand(unittest.TestCase):
    @mock.patch('htpclient.hashcat_cracker.Initialize.get_os', return_value=0)
    @mock.patch('htpclient.hashcat_cracker.os.path.isfile', return_value=True)
    @mock.patch('htpclient.hashcat_cracker.subprocess.check_output')
    def test_speed_benchmark_keeps_long_options(self, mock_check_output, _mock_isfile, _mock_get_os):
        captured = {}

        def fake_check_output(cmd, shell=False, cwd=None, stderr=None):
            if isinstance(cmd, list):
                return b'v6.2.6'
            captured['cmd'] = cmd
            return b'test:1:2.5\n'

        mock_check_output.side_effect = fake_check_output

        cracker = HashcatCracker(1, DummyBinaryDownload())
        task = {
            'hashlistId': 6,
            'attackcmd': '#HL# -a3 -- ?a?a --optimized-kernel-enable',
            'hashlistAlias': '#HL#',
            'cmdpars': '--hash-type=0',
            'taskId': 1,
            'usePrince': False,
        }

        result = cracker.run_speed_benchmark(task)
        self.assertEqual(result, '1:2.5')

        benchmark_cmd = captured['cmd']
        self.assertIn('--optimized-kernel-enable', benchmark_cmd)

        hashlist_path = Path(cracker.config.get_value('hashlists-path'), str(task['hashlistId']))
        self.assertNotIn(f'"{hashlist_path}"optimized-kernel-enable', benchmark_cmd)

    @mock.patch('htpclient.hashcat_cracker.Initialize.get_os', return_value=0)
    @mock.patch('htpclient.hashcat_cracker.os.path.isfile', return_value=True)
    @mock.patch('htpclient.hashcat_cracker.subprocess.check_output')
    def test_speed_benchmark_strips_pw_min_max(self, mock_check_output, _mock_isfile, _mock_get_os):
        captured = {}

        def fake_check_output(cmd, shell=False, cwd=None, stderr=None):
            if isinstance(cmd, list):
                return b'v6.2.6'
            captured['cmd'] = cmd
            return b'test:1:2.5\n'

        mock_check_output.side_effect = fake_check_output

        cracker = HashcatCracker(1, DummyBinaryDownload())
        task = {
            'hashlistId': 6,
            'attackcmd': '#HL# -a3 ?a?a --pw-max=14 --elem-cnt-min=1',
            'hashlistAlias': '#HL#',
            'cmdpars': '--hash-type=0 "--pw-min=8" --elem-cnt-max=2 --wl-dist-len=12 --dupe-check-disable --save-pos-disable',
            'taskId': 1,
            'usePrince': False,
        }

        result = cracker.run_speed_benchmark(task)
        self.assertEqual(result, '1:2.5')

        benchmark_cmd = captured['cmd']
        self.assertNotIn('--pw-max=14', benchmark_cmd)
        self.assertNotIn('--pw-min=8', benchmark_cmd)
        self.assertNotIn('--elem-cnt-min=1', benchmark_cmd)
        self.assertNotIn('--elem-cnt-max=2', benchmark_cmd)
        self.assertNotIn('--wl-dist-len=12', benchmark_cmd)
        self.assertNotIn('--dupe-check-disable', benchmark_cmd)
        self.assertNotIn('--save-pos-disable', benchmark_cmd)

    @mock.patch('htpclient.hashcat_cracker.Initialize.get_os', return_value=0)
    @mock.patch('htpclient.hashcat_cracker.os.path.isfile', return_value=True)
    @mock.patch('htpclient.hashcat_cracker.subprocess.check_output')
    def test_speed_benchmark_hashlist_is_first_positional_arg(self, mock_check_output, _mock_isfile, _mock_get_os):
        captured = {}

        def fake_check_output(cmd, shell=False, cwd=None, stderr=None):
            if isinstance(cmd, list):
                return b'v6.2.6'
            captured['cmd'] = cmd
            return b'test:1:2.5\n'

        mock_check_output.side_effect = fake_check_output

        cracker = HashcatCracker(1, DummyBinaryDownload())
        task = {
            'hashlistId': 6,
            'attackcmd': '-a0 basic-english2.txt #HL#',
            'hashlistAlias': '#HL#',
            'cmdpars': '--hash-type=0',
            'taskId': 1,
            'usePrince': False,
        }

        result = cracker.run_speed_benchmark(task)
        self.assertEqual(result, '1:2.5')

        benchmark_cmd = captured['cmd']
        hashlist_path = Path(cracker.config.get_value('hashlists-path'), str(task['hashlistId']))
        wordlist_path = Path(cracker.config.get_value('files-path'), 'basic-english2.txt')
        self.assertIn(f'"{hashlist_path}"', benchmark_cmd)
        self.assertIn(f'"{wordlist_path}"', benchmark_cmd)
        self.assertLess(benchmark_cmd.find(f'"{hashlist_path}"'), benchmark_cmd.find(f'"{wordlist_path}"'))

    @mock.patch('htpclient.hashcat_cracker.Initialize.get_os', return_value=0)
    @mock.patch('htpclient.hashcat_cracker.os.path.isfile', return_value=True)
    @mock.patch('htpclient.hashcat_cracker.subprocess.check_output')
    def test_chunk_command_strips_generator_only_options(self, mock_check_output, _mock_isfile, _mock_get_os):
        def fake_check_output(cmd, shell=False, cwd=None, stderr=None):
            if isinstance(cmd, list):
                return b'v6.2.6'
            return b'test:1:2.5\n'

        mock_check_output.side_effect = fake_check_output

        cracker = HashcatCracker(1, DummyBinaryDownload())
        task = {
            'hashlistId': 6,
            'statustimer': 5,
            'attackcmd': '-a0 basic-english2.txt #HL# --elem-cnt-min=1',
            'hashlistAlias': '#HL#',
            'cmdpars': '--hash-type=0 --pw-min=8',
            'useBrain': False,
        }
        chunk = {
            'skip': 0,
            'length': 100,
        }

        full_cmd = cracker.build_command(task, chunk)
        hashlist_path = Path(cracker.config.get_value('hashlists-path'), str(task['hashlistId']))
        wordlist_path = Path(cracker.config.get_value('files-path'), 'basic-english2.txt')

        self.assertNotIn('--pw-min=8', full_cmd)
        self.assertNotIn('--elem-cnt-min=1', full_cmd)
        self.assertIn(f'"{hashlist_path}"', full_cmd)
        self.assertIn(f'"{wordlist_path}"', full_cmd)
        self.assertLess(full_cmd.find(f'"{hashlist_path}"'), full_cmd.find(f'"{wordlist_path}"'))

    @mock.patch('htpclient.hashcat_cracker.Initialize.get_os', return_value=0)
    @mock.patch('htpclient.hashcat_cracker.os.path.isfile', return_value=True)
    @mock.patch('htpclient.hashcat_cracker.subprocess.check_output')
    def test_chunk_command_preserves_increment_options(self, mock_check_output, _mock_isfile, _mock_get_os):
        def fake_check_output(cmd, shell=False, cwd=None, stderr=None):
            if isinstance(cmd, list):
                return b'v6.2.6'
            return b'test:1:2.5\n'

        mock_check_output.side_effect = fake_check_output

        cracker = HashcatCracker(1, DummyBinaryDownload())
        task = {
            'hashlistId': 6,
            'statustimer': 5,
            'attackcmd': '#HL# -a3 --increment --increment-min=1 --increment-max=4 ?a?a?a?a',
            'hashlistAlias': '#HL#',
            'cmdpars': '--hash-type=0',
            'useBrain': False,
        }
        chunk = {
            'skip': 0,
            'length': 100,
        }

        full_cmd = cracker.build_command(task, chunk)
        self.assertIn('--increment', full_cmd)
        self.assertIn('--increment-min=1', full_cmd)
        self.assertIn('--increment-max=4', full_cmd)

    @mock.patch('htpclient.hashcat_cracker.Initialize.get_os', return_value=0)
    @mock.patch('htpclient.hashcat_cracker.os.path.isfile', return_value=True)
    @mock.patch('htpclient.hashcat_cracker.subprocess.check_output')
    def test_chunk_command_moves_hashlist_from_end(self, mock_check_output, _mock_isfile, _mock_get_os):
        def fake_check_output(cmd, shell=False, cwd=None, stderr=None):
            if isinstance(cmd, list):
                return b'v6.2.6'
            return b'test:1:2.5\n'

        mock_check_output.side_effect = fake_check_output

        cracker = HashcatCracker(1, DummyBinaryDownload())
        task = {
            'hashlistId': 6,
            'statustimer': 5,
            'attackcmd': '-a0 basic-english2.txt #HL#',
            'hashlistAlias': '#HL#',
            'cmdpars': '--hash-type=0',
            'useBrain': False,
        }
        chunk = {
            'skip': 0,
            'length': 100,
        }

        full_cmd = cracker.build_command(task, chunk)
        hashlist_path = Path(cracker.config.get_value('hashlists-path'), str(task['hashlistId']))
        wordlist_path = Path(cracker.config.get_value('files-path'), 'basic-english2.txt')
        self.assertIn(f'"{hashlist_path}"', full_cmd)
        self.assertIn(f'"{wordlist_path}"', full_cmd)
        self.assertLess(full_cmd.find(f'"{hashlist_path}"'), full_cmd.find(f'"{wordlist_path}"'))

    def test_is_same_size(self):
        from htpclient.files import Files
        import tempfile
        import os
        
        # Test non-existent file
        self.assertFalse(Files.is_same_size(Path('/nonexistent/file'), 100))
        
        # Test exact match
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello\nworld\n")
            temp_path = Path(f.name)
            
        try:
            self.assertTrue(Files.is_same_size(temp_path, len(b"hello\nworld\n")))
            # Test CRLF to LF normalization match
            # if we expect LF size, but actual is CRLF
            with open(temp_path, 'wb') as f:
                f.write(b"hello\r\nworld\r\n")
            self.assertTrue(Files.is_same_size(temp_path, len(b"hello\nworld\n")))
            
            # Test LF to CRLF normalization match
            # if we expect CRLF size, but actual is LF
            with open(temp_path, 'wb') as f:
                f.write(b"hello\nworld\n")
            self.assertTrue(Files.is_same_size(temp_path, len(b"hello\r\nworld\r\n")))
            
            # Test binary file (no crash on non-UTF-8 bytes)
            with open(temp_path, 'wb') as f:
                f.write(b"\xff\xfe\x00\x00\x01\x02\r\n\x03\x04")
            # Should return False (different size) but not raise UnicodeDecodeError
            self.assertFalse(Files.is_same_size(temp_path, 100))
            # Exact size of binary file
            self.assertTrue(Files.is_same_size(temp_path, 10))
        finally:
            os.unlink(temp_path)

    @mock.patch('htpclient.hashcat_cracker.Initialize.get_os', return_value=0)
    @mock.patch('htpclient.hashcat_cracker.os.path.isfile', return_value=True)
    @mock.patch('htpclient.hashcat_cracker.subprocess.check_output')
    def test_build_prince_command_extracts_options(self, mock_check_output, _mock_isfile, _mock_get_os):
        def fake_check_output(cmd, shell=False, cwd=None, stderr=None):
            if isinstance(cmd, list):
                return b'v6.2.6'
            return b'test:1:2.5\n'

        mock_check_output.side_effect = fake_check_output

        cracker = HashcatCracker(1, DummyBinaryDownload())
        task = {
            'hashlistId': 6,
            'statustimer': 5,
            'attackcmd': '--pw-min=8 --pw-max=14 --elem-cnt-min=1 --elem-cnt-max=4 basic-english2.txt #HL#',
            'hashlistAlias': '#HL#',
            'cmdpars': '--hash-type=22000',
        }
        chunk = {
            'skip': 21625184186,
            'length': 92500,
        }

        full_cmd = cracker.build_prince_command(task, chunk)
        self.assertIn('--pw-min=8', full_cmd)
        self.assertIn('--pw-max=14', full_cmd)
        self.assertIn('--elem-cnt-min=1', full_cmd)
        self.assertIn('--elem-cnt-max=4', full_cmd)
        self.assertIn('basic-english2.txt', full_cmd)
        self.assertIn('pp64', full_cmd)
        self.assertIn('../../hashlists/6 --hash-type=22000', full_cmd)


if __name__ == '__main__':
    unittest.main()