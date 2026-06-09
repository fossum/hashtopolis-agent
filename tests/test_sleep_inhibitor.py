import unittest
from unittest import mock
import sys
import ctypes
import subprocess
import shutil

from htpclient.sleep_inhibitor import (
    create_sleep_inhibitor,
    SleepInhibitor,
    NullSleepInhibitor,
    WindowsSleepInhibitor,
    MacSleepInhibitor,
    LinuxSleepInhibitor
)
from htpclient.config import Config


class TestSleepInhibitor(unittest.TestCase):
    @mock.patch('platform.system')
    def test_windows_inhibit(self, mock_system):
        mock_system.return_value = 'Windows'
        
        # Mock windll since it's not present on non-Windows test environments
        if not hasattr(ctypes, 'windll'):
            ctypes.windll = mock.MagicMock()
            
        mock_set_state = mock.MagicMock()
        ctypes.windll.kernel32 = mock.MagicMock()
        ctypes.windll.kernel32.SetThreadExecutionState = mock_set_state
        
        inhibitor = create_sleep_inhibitor()
        self.assertIsInstance(inhibitor, WindowsSleepInhibitor)
        
        inhibitor.inhibit()
        mock_set_state.assert_called_with(0x80000000 | 0x00000001)
        
        inhibitor.release()
        mock_set_state.assert_called_with(0x80000000)

    @mock.patch('platform.system')
    @mock.patch('shutil.which')
    @mock.patch('subprocess.Popen')
    def test_mac_inhibit(self, mock_popen, mock_which, mock_system):
        mock_system.return_value = 'Darwin'
        mock_which.side_effect = lambda cmd: '/usr/bin/caffeinate' if cmd == 'caffeinate' else None
        
        mock_process = mock.MagicMock()
        mock_popen.return_value = mock_process
        
        inhibitor = create_sleep_inhibitor()
        self.assertIsInstance(inhibitor, MacSleepInhibitor)
        
        inhibitor.inhibit()
        mock_popen.assert_called_once_with(
            ['caffeinate', '-i', 'cat'],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        inhibitor.release()
        mock_process.stdin.close.assert_called_once()
        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called_once_with(timeout=2)

    @mock.patch('platform.system')
    @mock.patch('shutil.which')
    @mock.patch('subprocess.Popen')
    def test_linux_systemd_inhibit(self, mock_popen, mock_which, mock_system):
        mock_system.return_value = 'Linux'
        mock_which.side_effect = lambda cmd: '/usr/bin/systemd-inhibit' if cmd == 'systemd-inhibit' else None
        
        mock_process = mock.MagicMock()
        mock_popen.return_value = mock_process
        
        inhibitor = create_sleep_inhibitor()
        self.assertIsInstance(inhibitor, LinuxSleepInhibitor)
        
        inhibitor.inhibit()
        mock_popen.assert_called_once_with(
            [
                'systemd-inhibit',
                '--what=idle',
                '--who=Hashtopolis Agent',
                '--why=Cracking task in progress',
                '--mode=block',
                'cat'
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        inhibitor.release()
        mock_process.stdin.close.assert_called_once()
        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called_once_with(timeout=2)

    @mock.patch('platform.system')
    @mock.patch('shutil.which')
    @mock.patch('subprocess.Popen')
    def test_linux_gnome_inhibit(self, mock_popen, mock_which, mock_system):
        mock_system.return_value = 'Linux'
        mock_which.side_effect = lambda cmd: '/usr/bin/gnome-session-inhibit' if cmd == 'gnome-session-inhibit' else None
        
        mock_process = mock.MagicMock()
        mock_popen.return_value = mock_process
        
        inhibitor = create_sleep_inhibitor()
        self.assertIsInstance(inhibitor, LinuxSleepInhibitor)
        
        inhibitor.inhibit()
        mock_popen.assert_called_once_with(
            [
                'gnome-session-inhibit',
                '--reason', 'Cracking task in progress',
                '--inhibit', 'idle',
                'cat'
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @mock.patch('platform.system')
    def test_disabled_by_config(self, mock_system):
        mock_system.return_value = 'Linux'
        
        mock_config = mock.MagicMock(spec=Config)
        mock_config.get_value.return_value = False
        
        inhibitor = create_sleep_inhibitor(mock_config)
        self.assertIsInstance(inhibitor, NullSleepInhibitor)
        
        with mock.patch('shutil.which') as mock_which:
            inhibitor.inhibit()
            mock_which.assert_not_called()
            
    @mock.patch('platform.system')
    def test_unsupported_os(self, mock_system):
        mock_system.return_value = 'FreeBSD'
        
        inhibitor = create_sleep_inhibitor()
        self.assertIsInstance(inhibitor, NullSleepInhibitor)
        self.assertEqual(inhibitor.unsupported_os, 'FreeBSD')
