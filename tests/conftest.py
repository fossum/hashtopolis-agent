import pytest
import os
import shutil
from htpclient.config import Config

@pytest.fixture(autouse=True, scope="session")
def setup_test_config():
    test_dir = os.path.abspath('test_workspace')
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)
    
    for folder in ['crackers', 'files', 'hashlists', 'preprocessors']:
        os.makedirs(os.path.join(test_dir, folder))
        
    # Copy files from the real files directory so that update_files() can find them
    real_files_dir = os.path.abspath('files')
    if os.path.exists(real_files_dir):
        for item in os.listdir(real_files_dir):
            s = os.path.join(real_files_dir, item)
            d = os.path.join(test_dir, 'files', item)
            if os.path.isfile(s):
                shutil.copy2(s, d)
                
    original_get_value = Config.get_value
    
    def mock_get_value(self, key):
        if key == 'crackers-path':
            return os.path.join(test_dir, 'crackers')
        elif key == 'files-path':
            return os.path.join(test_dir, 'files')
        elif key == 'hashlists-path':
            return os.path.join(test_dir, 'hashlists')
        elif key == 'preprocessors-path':
            return os.path.join(test_dir, 'preprocessors')
        elif key == 'zaps-path':
            return test_dir
        return original_get_value(self, key)
        
    Config.get_value = mock_get_value
    
    yield
    
    # Cleanup after all tests have completed
    if os.path.exists(test_dir):
        try:
            shutil.rmtree(test_dir)
        except Exception:
            pass
