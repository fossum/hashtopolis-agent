import abc
import ctypes
import logging
import platform
import shutil
import subprocess
import atexit


class SleepInhibitor(abc.ABC):
    def __init__(self):
        self.inhibited = False
        # Register atexit handler to ensure we release sleep inhibition on exit
        atexit.register(self.release)

    @abc.abstractmethod
    def inhibit(self):
        pass

    @abc.abstractmethod
    def release(self):
        pass


class NullSleepInhibitor(SleepInhibitor):
    """Used for unsupported OSes or when sleep inhibition is disabled via config."""
    def __init__(self, unsupported_os=None):
        super().__init__()
        self.unsupported_os = unsupported_os

    def inhibit(self):
        if self.unsupported_os:
            logging.warning("Sleep inhibition not supported on OS: %s", self.unsupported_os)

    def release(self):
        pass


class WindowsSleepInhibitor(SleepInhibitor):
    def inhibit(self):
        if self.inhibited:
            return
        logging.info("Preventing system from sleeping/hibernating...")
        try:
            # ES_CONTINUOUS | ES_SYSTEM_REQUIRED
            # ES_CONTINUOUS (0x80000000) - keeps the state in effect until cleared
            # ES_SYSTEM_REQUIRED (0x00000001) - forces the system working state
            ES_CONTINUOUS = 0x80000000
            ES_SYSTEM_REQUIRED = 0x00000001
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
            logging.debug("Windows: Sleep inhibition set successfully.")
            self.inhibited = True
        except Exception as e:
            logging.error("Windows: Failed to inhibit sleep: %s", str(e))

    def release(self):
        if not self.inhibited:
            return
        logging.info("Allowing system to sleep/hibernate...")
        try:
            ES_CONTINUOUS = 0x80000000
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
            logging.debug("Windows: Sleep inhibition released successfully.")
            self.inhibited = False
        except Exception as e:
            logging.error("Windows: Failed to release sleep inhibition: %s", str(e))


class UnixSleepInhibitor(SleepInhibitor):
    """Base class for Unix-like systems which run a process to hold sleep inhibition."""
    def __init__(self):
        super().__init__()
        self.process = None

    def release(self):
        if not self.inhibited:
            return
        logging.info("Allowing system to sleep/hibernate...")
        if self.process:
            try:
                if self.process.stdin:
                    self.process.stdin.close()
            except Exception:
                pass
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
                logging.debug("Unix: Sleep inhibitor process terminated.")
            except Exception as e:
                logging.debug("Unix: Error terminating sleep inhibitor process: %s. Forcing kill...", str(e))
                try:
                    self.process.kill()
                    self.process.wait()
                except Exception:
                    pass
            self.process = None
        self.inhibited = False


class MacSleepInhibitor(UnixSleepInhibitor):
    def inhibit(self):
        if self.inhibited:
            return
        logging.info("Preventing system from sleeping/hibernating...")
        if shutil.which('caffeinate'):
            try:
                self.process = subprocess.Popen(
                    ['caffeinate', '-i', 'cat'],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                logging.debug("macOS: Spawned caffeinate successfully.")
                self.inhibited = True
            except Exception as e:
                logging.error("macOS: Failed to spawn caffeinate: %s", str(e))
        else:
            logging.warning("macOS: caffeinate command not found.")


class LinuxSleepInhibitor(UnixSleepInhibitor):
    def inhibit(self):
        if self.inhibited:
            return
        logging.info("Preventing system from sleeping/hibernating...")

        # Try systemd-inhibit first
        if shutil.which('systemd-inhibit'):
            try:
                self.process = subprocess.Popen([
                    'systemd-inhibit',
                    '--what=idle',
                    '--who=Hashtopolis Agent',
                    '--why=Cracking task in progress',
                    '--mode=block',
                    'cat'
                ], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logging.debug("Linux: Spawned systemd-inhibit successfully.")
                self.inhibited = True
                return
            except Exception as e:
                logging.debug("Linux: Failed to spawn systemd-inhibit: %s", str(e))

        # Try gnome-session-inhibit as fallback
        if shutil.which('gnome-session-inhibit'):
            try:
                self.process = subprocess.Popen([
                    'gnome-session-inhibit',
                    '--reason', 'Cracking task in progress',
                    '--inhibit', 'idle',
                    'cat'
                ], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logging.debug("Linux: Spawned gnome-session-inhibit successfully.")
                self.inhibited = True
                return
            except Exception as e:
                logging.debug("Linux: Failed to spawn gnome-session-inhibit: %s", str(e))

        logging.warning("Linux: Neither systemd-inhibit nor gnome-session-inhibit could be run.")


def create_sleep_inhibitor(config=None):
    """Factory function to create the correct SleepInhibitor subclass based on OS and config."""
    if config:
        # Default to True if not explicitly False
        inhibit_enabled = config.get_value('inhibit-sleep') not in [False, 'false', 'False', 0]
        if not inhibit_enabled:
            return NullSleepInhibitor()

    os_type = platform.system()
    if os_type == 'Windows':
        return WindowsSleepInhibitor()
    elif os_type == 'Darwin':
        return MacSleepInhibitor()
    elif os_type == 'Linux':
        return LinuxSleepInhibitor()
    else:
        return NullSleepInhibitor(unsupported_os=os_type)
